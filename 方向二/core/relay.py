"""
中继节点（方向二）：三重验证 + 绑定校验 + 会话准入凭证 + 按虚拟地址头路由。

三重验证（《代码汇总版》§4.2）：
    ① 授权验签（KDC 公钥 / 代理验证）
    ② ST 校验（签名 + 时效 + 单次使用缓存）
    ③ DID 一致性（挑战应答：设备用 SM9 私钥签 nonce，中继用 DID 验）

绑定校验：设备入网须关联已认证用户（KDC 绑定表）。
转发：按明文虚拟地址头路由、不解密载荷（B4-4 恶意中继仅见密文）。
"""

import time
from typing import Callable, Dict, Optional, Tuple

from .audit_logger import AuditLogger
from .authorization import (WARRANT_SCOPE_SESSION_CREDENTIAL,
                            issue_session_credential, proxy_verify,
                            verify_auth)
from .common import rand_bytes, sm3
from .did import make_device_did
from .st_ticket import make_st_replay_cache


def _pack(obj: dict) -> bytes:
    import json
    return json.dumps(obj, sort_keys=True).encode("utf-8")


class Relay:
    def __init__(self, sm9_engine, kdc, audit_logger: Optional[AuditLogger] = None,
                 now_fn: Optional[Callable[[], float]] = None,
                 relay_id: str = "relay-1"):
        self.sm9 = sm9_engine
        self.kdc = kdc
        self.relay_did = make_device_did(relay_id, "realm")
        self.sm9.derive_sk(self.relay_did)
        self.audit = audit_logger
        self._now_fn = now_fn or time.time
        self.relay_id = relay_id
        self._warrant = None                       # 代理委托授权书（KDC 签发）
        self.replay_cache = make_st_replay_cache() # ST 单次使用缓存
        self.admitted: Dict[str, dict] = {}        # vaddr -> device session
        self._vaddr_counter = 0
        self.dumped_packets: list = []             # B4-4 恶意中继观察面（仅密文）

    def now(self) -> float:
        return self._now_fn()

    def setup_proxy(self, scope=None, exp=None) -> dict:
        """KDC 代理委托：本中继成为代理签名者（scope 限定）。"""
        self._warrant = self.kdc.delegate_proxy(self.relay_did, scope=scope, exp=exp)
        return self._warrant

    # ------------------------------------------------------------------
    # 三重验证（两轮挑战应答）
    # ------------------------------------------------------------------
    def verify_authorization(self, auth: dict) -> Tuple[bool, float]:
        t0 = self.now()
        ok = verify_auth(self.sm9, auth, now_fn=self.now)
        return ok, (self.now() - t0) * 1000.0

    def verify_st(self, st: dict, service: str,
                  claims_checker: Optional[Callable[[dict], bool]] = None
                  ) -> Tuple[dict, float]:
        t0 = self.now()
        r = self.kdc.st.verify_ticket(st, service, claims_checker=claims_checker,
                                      now=self.now(),
                                      replay_cache=self.replay_cache)
        return r, (self.now() - t0) * 1000.0

    def verify_challenge(self, device_did: str, challenge_nonce: bytes,
                         response_sig: bytes, nonce: bytes, ts: float
                         ) -> Tuple[bool, float]:
        """③ DID 一致性：验设备对 (did || challenge || nonce || ts) 的 SM9 签名。"""
        t0 = self.now()
        message = _pack({"did": device_did, "challenge": challenge_nonce.hex(),
                         "nonce": nonce.hex(), "ts": ts})
        ok = self.sm9.verify(device_did, message, response_sig)
        return ok, (self.now() - t0) * 1000.0

    # ------------------------------------------------------------------
    # 入网
    # ------------------------------------------------------------------
    def begin_admission(self, device_req: dict, service: str,
                        claims_checker: Optional[Callable[[dict], bool]] = None
                        ) -> dict:
        """第一轮：①授权验签 ②ST 校验 ③绑定校验 → 下发挑战 nonce。
        device_req = {did, auth, st, caddr, netperm}"""
        did = device_req["did"]
        ok_auth, ms_auth = self.verify_authorization(device_req["auth"])
        if not ok_auth:
            self._audit("admission", "rejected_auth", did)
            return {"ok": False, "stage": "authorize", "ms": ms_auth,
                    "error": "auth_invalid"}
        r_st, ms_st = self.verify_st(device_req["st"], service,
                                     claims_checker=claims_checker)
        if not r_st["ok"]:
            self._audit("admission", "rejected_st", did,
                        ticket_id=device_req["st"].get("ticket_id"))
            return {"ok": False, "stage": "st", "ms": ms_st, "error": r_st["error"]}
        owner = self.kdc.owner_of(did)
        if owner is None or not self.kdc.users.get(owner, False):
            self._audit("admission", "rejected_binding", did,
                        ticket_id=device_req["st"].get("ticket_id"))
            return {"ok": False, "stage": "binding", "ms": ms_st,
                    "error": "binding_rejected"}
        challenge = rand_bytes(16, f"challenge_{did}")
        return {"ok": True, "challenge": challenge, "ms_authorize": ms_auth,
                "ms_st": ms_st}

    def finish_admission(self, device_req: dict, challenge: bytes,
                         response_sig: bytes, nonce: bytes, ts: float,
                         service: str,
                         claims_checker: Optional[Callable[[dict], bool]] = None
                         ) -> dict:
        """第二轮：③DID 一致性挑战应答 → 分配虚拟地址 → 签发会话准入凭证。
        （ST 已在第一轮校验并标记单次使用，此处不重复验证。）"""
        did = device_req["did"]
        ok_ch, ms_ch = self.verify_challenge(did, challenge, response_sig,
                                             nonce, ts)
        if not ok_ch:
            self._audit("admission", "rejected_challenge", did)
            return {"ok": False, "stage": "challenge", "ms": ms_ch,
                    "error": "challenge_failed"}
        if abs(self.now() - ts) > 1800.0:
            return {"ok": False, "stage": "challenge", "ms": ms_ch,
                    "error": "ts_out_of_window"}
        vaddr = self._allocate_vaddr(did)
        netperm = device_req["st"]["netperm"]
        credential = issue_session_credential(
            self.sm9, self.relay_did, self._warrant, did, netperm, service,
            exp=self.now() + 1800.0, now_fn=self.now)
        self.admitted[vaddr] = {"did": did, "credential": credential,
                                "admitted_at": self.now()}
        self._audit("admission", "success", did,
                    ticket_id=device_req["st"].get("ticket_id"))
        return {"ok": True, "vaddr": vaddr, "credential": credential,
                "ms_challenge": ms_ch, "ms_st": 0.0}

    def _allocate_vaddr(self, did: str) -> str:
        self._vaddr_counter += 1
        return f"10.200.{self._vaddr_counter // 256}.{self._vaddr_counter % 256}"

    # ------------------------------------------------------------------
    # 数据面：按虚拟地址头路由（不解密载荷）
    # ------------------------------------------------------------------
    def forward(self, frame: bytes) -> Optional[str]:
        """读取明文虚拟地址头（前 4 字节）路由；dump 记录仅密文（B4-4）。"""
        if len(frame) < 4:
            return None
        vaddr = f"{frame[0]}.{frame[1]}.{frame[2]}.{frame[3]}"
        self.dumped_packets.append(frame[4:])
        if vaddr not in self.admitted:
            return None
        return vaddr

    def verify_credential(self, credential: dict) -> bool:
        """数据面快速放行校验：验 warrant + 签名 + 时效。"""
        from .authorization import verify_session_credential
        return verify_session_credential(self.sm9, credential, now_fn=self.now)

    def _audit(self, action: str, result: str, principal: str,
               ticket_id: Optional[str] = None):
        if self.audit is not None:
            self.audit.log(action, result, principal, ticket_id=ticket_id)