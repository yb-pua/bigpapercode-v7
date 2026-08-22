"""
中继节点（方向二）：user-device-auth-ST 四元绑定 + 两轮 stateful 挑战 + 会话准入凭证链。

绑定校验（第一轮）：
    request.did == auth.device_did == st.device_did
    binding.owner_of(request.did) == auth.user_did == st.user_did
    auth.auth_id == st.auth_id
    auth.parent_auth_ticket_id == st.parent_auth_ticket_id
    ST.netperm 不能超出 auth.policy
    request.caddr == st.caddr（非空时）
    ST.sname == 目标 service
    UserAuthContext 有效

两轮 stateful 挑战：begin 保存 pending（含 verified claims），finish 只按
challenge_id 读取服务端保存的 claims，不再信任第二份 device_req/ST/netperm，
避免 TOCTOU；challenge 单次使用。

会话凭证：从第一轮 verified claims 生成，含 parent_ticket_id/st_fingerprint。

角色隔离（接口级模拟）：验签用 VerifyOnlySM9，签名用 RestrictedSigner（仅 relay_did）。
"""

import json
import time
from typing import Callable, Dict, Optional, Tuple

from .audit_logger import AuditLogger
from .authorization import (WARRANT_SCOPE_SESSION_CREDENTIAL,
                            issue_session_credential, netperm_subset,
                            verify_auth)
from .common import rand_bytes, sm3
from .crypto_roles import RestrictedSigner, VerifyOnlySM9
from .did import make_device_did
from .st_ticket import make_st_replay_cache, st_fingerprint


def _pack(obj: dict) -> bytes:
    return json.dumps(obj, sort_keys=True).encode("utf-8")


class Relay:
    def __init__(self, sm9_engine, kdc, audit_logger: Optional[AuditLogger] = None,
                 now_fn: Optional[Callable[[], float]] = None,
                 relay_id: str = "relay-1"):
        self.kdc = kdc
        self.relay_did = make_device_did(relay_id, "realm")
        sm9_engine.derive_sk(self.relay_did)
        self.audit = audit_logger
        self._now_fn = now_fn or time.time
        self.relay_id = relay_id
        self._warrant = None
        self.replay_cache = make_st_replay_cache()
        self.admitted: Dict[str, dict] = {}
        self.pending: Dict[str, dict] = {}     # challenge_id -> pending state
        self._consumed_challenges = set()       # 已消费 challenge_id（防重放）
        self._vaddr_counter = 0
        self.dumped_packets: list = []
        # 接口级角色隔离：验签只读，签名仅 relay_did
        self._verifier = VerifyOnlySM9(sm9_engine)
        self._signer = RestrictedSigner(sm9_engine, [self.relay_did])

    def now(self) -> float:
        return self._now_fn()

    def setup_proxy(self, scope=None, exp=None) -> dict:
        self._warrant = self.kdc.delegate_proxy(self.relay_did, scope=scope, exp=exp)
        return self._warrant

    # ------------------------------------------------------------------
    # 入网第一轮：验证 + 绑定 + 下发 stateful challenge
    # ------------------------------------------------------------------
    def begin_admission(self, device_req: dict, service: str,
                        claims_checker: Optional[Callable[[dict], bool]] = None
                        ) -> dict:
        did = device_req["did"]
        auth = device_req["auth"]
        st = device_req["st"]
        caddr = device_req.get("caddr", "")

        # ① 授权验签
        t0 = self.now()
        ok_auth = verify_auth(self._verifier, auth, now_fn=self.now)
        ms_auth = (self.now() - t0) * 1000.0
        if not ok_auth:
            self._audit("admission", "rejected_auth", did)
            return {"ok": False, "stage": "authorize", "ms": ms_auth,
                    "error": "auth_invalid"}

        # ② ST 校验
        t0 = self.now()
        r_st = self.kdc.st.verify_ticket(st, service, claims_checker=claims_checker,
                                         now=self.now(), replay_cache=self.replay_cache)
        ms_st = (self.now() - t0) * 1000.0
        if not r_st["ok"]:
            self._audit("admission", "rejected_st", did,
                        ticket_id=st.get("ticket_id"))
            return {"ok": False, "stage": "st", "ms": ms_st, "error": r_st["error"]}

        # ③ 四元绑定一致性
        err = self._binding_error(did, auth, st, caddr, service)
        if err is not None:
            self._audit("admission", "rejected_binding", did,
                        ticket_id=st.get("ticket_id"))
            return {"ok": False, "stage": "binding", "ms": ms_st, "error": err}

        owner = self.kdc.owner_of(did)
        challenge = rand_bytes(16, f"challenge_{did}")
        challenge_id = rand_bytes(16, "challenge_id").hex()
        request_digest = sm3(_pack(device_req)).hex()
        self.pending[challenge_id] = {
            "device_did": did,
            "user_did": owner,
            "ticket_id": st["ticket_id"],
            "auth_id": auth.get("auth_id"),
            "parent_auth_ticket_id": auth.get("parent_auth_ticket_id", ""),
            "verified_netperm": st["netperm"],
            "st_fingerprint": st_fingerprint(st).hex(),
            "st_end": float(st["times"]["end"]),
            "service": service,
            "caddr": caddr,
            "request_digest": request_digest,
            "challenge": challenge,
            "expires_at": self.now() + 300.0,
            "used": False,
        }
        return {"ok": True, "challenge_id": challenge_id, "challenge": challenge,
                "request_digest": request_digest, "ms_authorize": ms_auth,
                "ms_st": ms_st}

    def _binding_error(self, did, auth, st, caddr, service) -> Optional[str]:
        """四元绑定一致性检查，任一不一致返回明确错误码。"""
        if did != auth.get("device_did", auth.get("did_dev")):
            return "device_mismatch"
        if did != st.get("device_did", st.get("principal")):
            return "device_mismatch"
        owner = self.kdc.owner_of(did)
        if owner is None or not self.kdc.is_user_authenticated(owner):
            return "binding_rejected"
        if auth.get("user_did") != owner:
            return "user_device_mismatch"
        if st.get("user_did") != owner:
            return "user_device_mismatch"
        if auth.get("auth_id") != st.get("auth_id"):
            return "auth_st_mismatch"
        if auth.get("parent_auth_ticket_id") != st.get("parent_auth_ticket_id"):
            return "auth_st_mismatch"
        if not netperm_subset(st.get("netperm", {}), auth.get("policy", {})):
            return "netperm_escalation"
        if st.get("caddr") and caddr and st.get("caddr") != caddr:
            return "caddr_mismatch"
        if st.get("sname") != service:
            return "service_mismatch"
        return None

    # ------------------------------------------------------------------
    # 入网第二轮：按 challenge_id 读 pending，验设备签名，发凭证
    # ------------------------------------------------------------------
    def finish_admission(self, challenge_id: str, challenge: bytes,
                         response_sig: bytes, nonce: bytes, ts: float,
                         service: str) -> dict:
        if challenge_id in self._consumed_challenges:
            return {"ok": False, "stage": "challenge", "error": "challenge_replay"}
        pend = self.pending.get(challenge_id)
        if pend is None:
            return {"ok": False, "stage": "challenge", "error": "challenge_unknown"}
        if pend["used"]:
            return {"ok": False, "stage": "challenge", "error": "challenge_replay"}
        if self.now() > pend["expires_at"]:
            self.pending.pop(challenge_id, None)
            return {"ok": False, "stage": "challenge", "error": "challenge_expired"}
        if pend["challenge"] != challenge:
            return {"ok": False, "stage": "challenge", "error": "challenge_mismatch"}

        did = pend["device_did"]
        # 设备签名载荷绑定 device_did + challenge_id + challenge + request_digest + nonce + ts
        message = _pack({
            "device_did": did,
            "challenge_id": challenge_id,
            "challenge": challenge.hex(),
            "request_digest": pend["request_digest"],
            "nonce": nonce.hex(),
            "ts": ts,
        })
        t0 = self.now()
        if not self._verifier.verify(did, message, response_sig):
            self.pending.pop(challenge_id, None)
            self._consumed_challenges.add(challenge_id)
            self._audit("admission", "rejected_challenge", did)
            return {"ok": False, "stage": "challenge",
                    "ms": (self.now() - t0) * 1000.0, "error": "challenge_failed"}
        if abs(self.now() - ts) > 1800.0:
            self.pending.pop(challenge_id, None)
            self._consumed_challenges.add(challenge_id)
            return {"ok": False, "stage": "challenge",
                    "ms": (self.now() - t0) * 1000.0, "error": "ts_out_of_window"}
        if service != pend["service"]:
            self.pending.pop(challenge_id, None)
            self._consumed_challenges.add(challenge_id)
            return {"ok": False, "stage": "binding",
                    "ms": (self.now() - t0) * 1000.0, "error": "service_mismatch"}

        vaddr = self._allocate_vaddr(did)
        # 会话凭证只使用第一轮保存的 verified_netperm / service（无 TOCTOU）
        credential = issue_session_credential(
            self._signer, self.relay_did, self._warrant,
            pend["device_did"], pend["user_did"], pend["auth_id"],
            pend["parent_auth_ticket_id"], pend["ticket_id"],
            pend["verified_netperm"], pend["service"], vaddr,
            pend["st_fingerprint"],
            exp=min(self.now() + 1800.0, pend["st_end"]), now_fn=self.now)
        self.admitted[vaddr] = {"did": did, "credential": credential,
                                "admitted_at": self.now()}
        self.pending.pop(challenge_id, None)
        self._consumed_challenges.add(challenge_id)
        self._audit("admission", "success", did, ticket_id=pend["ticket_id"])
        return {"ok": True, "vaddr": vaddr, "credential": credential,
                "ms_challenge": (self.now() - t0) * 1000.0}

    def _allocate_vaddr(self, did: str) -> str:
        self._vaddr_counter += 1
        return f"10.200.{self._vaddr_counter // 256}.{self._vaddr_counter % 256}"

    # ------------------------------------------------------------------
    # 数据面：按虚拟地址头路由（不解密载荷）
    # ------------------------------------------------------------------
    def forward(self, frame: bytes) -> Optional[str]:
        if len(frame) < 4:
            return None
        vaddr = f"{frame[0]}.{frame[1]}.{frame[2]}.{frame[3]}"
        self.dumped_packets.append(frame[4:])
        if vaddr not in self.admitted:
            return None
        return vaddr

    def verify_credential(self, credential: dict) -> bool:
        from .authorization import verify_session_credential
        return verify_session_credential(self._verifier, credential, now_fn=self.now,
                                         trusted_kdc_did=self.kdc.kdc_did)

    def _audit(self, action: str, result: str, principal: str,
               ticket_id: Optional[str] = None):
        if self.audit is not None:
            self.audit.log(action, result, principal, ticket_id=ticket_id)
