"""
设备节点（方向二）：enroll / admission（两轮挑战应答）/ negotiate_tunnel / flow_gen。

入网流程：KDC 登记（绑定校验）→ 授权 + ST 获取 → 中继三重验证
（①授权 ②ST ③DID 挑战应答）→ 虚拟地址 + 会话准入凭证 → SM9 密钥协商隧道。
"""

import time
from typing import Callable, Dict, List, Optional, Tuple

from .common import rand_bytes, sm3
from .did import make_device_did


def _pack(obj: dict) -> bytes:
    import json
    return json.dumps(obj, sort_keys=True).encode("utf-8")


class Device:
    def __init__(self, device_id: str, owner_user_did: str, sm9_engine,
                 now_fn: Optional[Callable[[], float]] = None):
        self.device_id = device_id
        self.owner_user_did = owner_user_did
        self.sm9 = sm9_engine
        self.did = make_device_did(device_id, owner_user_did)
        self.sm9.derive_sk(self.did)
        self._now_fn = now_fn or time.time
        self.vaddr: Optional[str] = None
        self.credential: Optional[dict] = None
        self.auth: Optional[dict] = None
        self.st: Optional[dict] = None
        self.caddr = "127.0.0.1"

    def now(self) -> float:
        return self._now_fn()

    def enroll(self, kdc, addr: str = "127.0.0.1") -> bool:
        """KDC 登记（绑定校验：owner 用户须已认证）。"""
        self.caddr = addr
        return kdc.register_device(self.did, self.owner_user_did, addr=addr)

    def obtain_authorization(self, kdc, netperm: dict, ttl: float = 1800.0) -> dict:
        """KDC 原子设备接入：签发绑定 user/device 的授权 + ST。"""
        access = kdc.issue_device_access(self.did, "relay@realm", netperm,
                                         caddr=self.caddr, ttl=ttl)
        if access is None:
            raise RuntimeError("issue_device_access failed: device not enrolled "
                               "or user auth context expired")
        self.auth = access["auth"]
        self.st = access["st"]
        return {"auth": self.auth, "st": self.st}

    # ------------------------------------------------------------------
    def admission_round1(self) -> dict:
        """入网第一轮：提交 {did, auth, st, caddr}。"""
        return {"did": self.did, "auth": self.auth, "st": self.st,
                "caddr": self.caddr}

    def admission_round2(self, challenge_id: str, challenge: bytes,
                         request_digest: str) -> dict:
        """入网第二轮：DID 挑战应答（SM9 私钥签名，绑定 challenge_id/digest）。"""
        nonce = rand_bytes(16, f"dev_nonce_{self.did}")
        ts = self.now()
        message = _pack({"device_did": self.did, "challenge_id": challenge_id,
                         "challenge": challenge.hex(),
                         "request_digest": request_digest,
                         "nonce": nonce.hex(), "ts": ts})
        sig = self.sm9.sign(self.did, message)
        return {"nonce": nonce, "ts": ts, "sig": sig}

    def negotiate_tunnel(self, peer_did: str):
        """SM9 密钥协商（发起方）：返回 (state, r_init)。"""
        return self.sm9.key_exchange_initiator(self.did, peer_did)

    def respond_tunnel(self, peer_did: str, r_init: bytes):
        """SM9 密钥协商（响应方）：返回 (r_resp, key)。"""
        return self.sm9.key_exchange_responder(self.did, peer_did, r_init)

    def finish_tunnel(self, state, r_resp: bytes) -> bytes:
        """SM9 密钥协商（发起方收尾）：返回会话密钥。"""
        return self.sm9.key_exchange_initiator_finish(state, r_resp)

    # ------------------------------------------------------------------
    def flow_gen(self, flow_type: str, rate: float = 1.0,
                 duration: float = 600.0) -> List[Tuple[float, int]]:
        """三型业务流（确定性生成）：
            周期型  period   : 1 pkt/s 定长 512B
            突发型  burst    : 泊松突发（均值 rate 突/s），每突发 20×1448B
            交互型  request  : 请求-应答 1 对/s（req 128B / resp 512B）
        返回 [(ts_offset, payload_len), ...]。
        """
        import numpy as np
        seed = int.from_bytes(sm3(f"flow_{flow_type}_{self.did}".encode())[:4],
                              "big")
        np_rng = np.random.RandomState(seed)
        ts_list = []
        if flow_type == "period":
            n = int(duration * rate)
            for i in range(n):
                ts_list.append((i * (1.0 / max(rate, 1e-9)), 512))
        elif flow_type == "burst":
            # 泊松到达：间隔 = -ln(U)/lambda
            lam = max(rate, 0.05)
            t = 0.0
            while t < duration:
                interval = -np.log(np_rng.uniform(1e-9, 1.0)) / lam
                t += interval
                if t >= duration:
                    break
                for _ in range(20):
                    ts_list.append((t, 1448))
        elif flow_type == "request":
            n = int(duration)
            for i in range(n):
                ts_list.append((i * 1.0, 128))
                ts_list.append((i * 1.0 + 0.05, 512))
        return ts_list