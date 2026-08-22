"""
用户认证上下文（方向二）：接收方向一成功认证结果的模拟交接。

UserAuthContext v1（方向一输出的签名认证上下文，此处只做模拟适配器，
不重新执行人脸/生物认证）：

{
  "schema_version": "user-auth-context-v1",
  "user_did": "...",
  "auth_method": "bio-sm9-simulated",
  "purpose": "p2p_device_binding",
  "source_ticket_id": "...",
  "evidence_id": "...",
  "issued_at": float,
  "expires_at": float,
  "issuer_did": "...",
  "signature": hex
}

verify 检查：schema / issuer 签名 / purpose / auth_method / user_did /
issued_at/expires_at（未过期、未超前、无篡改）。
"""

import json
import time
from typing import Callable, Optional

from .common import rand_bytes

SCHEMA_VERSION = "user-auth-context-v1"
AUTH_METHOD = "bio-sm9-simulated"
PURPOSE_P2P_BINDING = "p2p_device_binding"


def _pack(obj: dict) -> bytes:
    return json.dumps(obj, sort_keys=True).encode("utf-8")


class UserAuthContextService:
    """方向一认证结果 → 方向二消费的模拟交接器（issuer 用 KDC DID 签名）。"""

    def __init__(self, sm9_engine, issuer_did: str,
                 now_fn: Optional[Callable[[], float]] = None):
        self.sm9 = sm9_engine
        self.issuer_did = issuer_did
        self._now_fn = now_fn or time.time

    def now(self) -> float:
        return self._now_fn()

    def issue(self, user_did: str, source_ticket_id: str,
              evidence_id: str, ttl: float = 1800.0,
              purpose: str = PURPOSE_P2P_BINDING) -> dict:
        """签发 UserAuthContext（模拟方向一认证成功后下发的签名上下文）。"""
        now = self.now()
        payload = {
            "schema_version": SCHEMA_VERSION,
            "user_did": user_did,
            "auth_method": AUTH_METHOD,
            "purpose": purpose,
            "source_ticket_id": source_ticket_id,
            "evidence_id": evidence_id,
            "issued_at": now,
            "expires_at": now + ttl,
            "issuer_did": self.issuer_did,
        }
        sig = self.sm9.sign(self.issuer_did, _pack(payload))
        ctx = dict(payload)
        ctx["signature"] = sig.hex()
        return ctx

    def verify(self, ctx: dict, now: Optional[float] = None,
               expected_purpose: str = PURPOSE_P2P_BINDING) -> dict:
        """验 UserAuthContext：返回 {"ok": bool, "error": str}。"""
        now = now if now is not None else self.now()
        if not isinstance(ctx, dict):
            return {"ok": False, "error": "invalid_context"}
        if ctx.get("schema_version") != SCHEMA_VERSION:
            return {"ok": False, "error": "schema_mismatch"}
        if ctx.get("auth_method") != AUTH_METHOD:
            return {"ok": False, "error": "auth_method_mismatch"}
        if ctx.get("purpose") != expected_purpose:
            return {"ok": False, "error": "purpose_mismatch"}
        if not ctx.get("user_did"):
            return {"ok": False, "error": "missing_user_did"}
        try:
            sig = bytes.fromhex(ctx["signature"])
        except (KeyError, ValueError):
            return {"ok": False, "error": "invalid_signature"}
        if ctx.get("issuer_did") != self.issuer_did:
            return {"ok": False, "error": "untrusted_issuer"}
        payload = {k: v for k, v in ctx.items() if k != "signature"}
        if not self.sm9.verify(self.issuer_did, _pack(payload), sig):
            return {"ok": False, "error": "signature_invalid"}
        issued_at = float(ctx["issued_at"])
        expires_at = float(ctx["expires_at"])
        if issued_at > now or now > expires_at:
            return {"ok": False, "error": "context_out_of_window"}
        return {"ok": True, "error": None}


def new_evidence_id() -> str:
    return rand_bytes(16, "evidence_id").hex()
