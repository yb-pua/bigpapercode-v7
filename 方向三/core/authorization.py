"""
授权与代理签名（方向二）：

    授权 A = {DID_dev, policy=NetPerm, exp, Sig_KDC}          （KDC 签发）
    warrant（授权书）= {delegator=KDC, delegatee=relay_did, scope,
                        exp, purpose} + Sig_KDC               （代理委托限定）
    会话准入凭证 = {did, netperm, exp, sname, relay_did} + relay 签名
    （数据面快速放行；验证方先验 warrant 再验签名）

伪造边界：中继无 KDC 主密钥，授权书 scope 外签发凭证 100% 无效
（《代码汇总版》§4.2/§4.3、B4-8 代理伪造测试）。
"""

import json
import time
from typing import Callable, Dict, Optional

from .common import rand_bytes, sm3

WARRANT_SCOPE_SESSION_CREDENTIAL = "session_credential"


def _pack(obj: dict) -> bytes:
    return json.dumps(obj, sort_keys=True).encode("utf-8")


class AuthorizationError(Exception):
    pass


def issue_auth(sm9_engine, kdc_did: str, did_dev: str, policy: dict,
               exp: float, now_fn: Optional[Callable[[], float]] = None) -> dict:
    """KDC 签发授权：A = {DID_dev, policy=NetPerm, exp, Sig_KDC}。"""
    now = now_fn() if now_fn else time.time()
    payload = {"did_dev": did_dev, "policy": policy, "exp": exp, "issued_time": now}
    sig = sm9_engine.sign(kdc_did, _pack(payload))
    auth = dict(payload)
    auth["sig"] = sig.hex()
    auth["kdc_did"] = kdc_did
    return auth


def verify_auth(sm9_engine, auth: dict,
                now_fn: Optional[Callable[[], float]] = None) -> bool:
    """验授权：KDC 验签 + 未过期。"""
    now = now_fn() if now_fn else time.time()
    try:
        sig = bytes.fromhex(auth["sig"])
    except (KeyError, ValueError):
        return False
    payload = {k: v for k, v in auth.items() if k not in ("sig", "kdc_did")}
    if not sm9_engine.verify(auth["kdc_did"], _pack(payload), sig):
        return False
    return now <= float(auth["exp"])


def proxy_delegate(sm9_engine, kdc_did: str, relay_did: str,
                   scope: Optional[list] = None,
                   exp: Optional[float] = None,
                   now_fn: Optional[Callable[[], float]] = None) -> dict:
    """KDC 代理委托：生成授权书 warrant（限定 scope，不能签新授权/新票据）。"""
    now = now_fn() if now_fn else time.time()
    scope = scope or [WARRANT_SCOPE_SESSION_CREDENTIAL]
    payload = {
        "delegator": kdc_did,
        "delegatee": relay_did,
        "purpose": "proxy",
        "scope": scope,
        "exp": exp if exp is not None else now + 3600.0,
        "issued_time": now,
    }
    sig = sm9_engine.sign(kdc_did, _pack(payload))
    warrant = dict(payload)
    warrant["sig"] = sig.hex()
    return warrant


def proxy_verify(sm9_engine, warrant: dict, message: bytes, signature: bytes,
                 required_scope: str,
                 now_fn: Optional[Callable[[], float]] = None,
                 trusted_delegator: Optional[str] = None) -> bool:
    """代理验签：验 warrant（KDC 签名 + scope 覆盖 + 未过期）→ 验 delegatee 签名。

    trusted_delegator 为信任锚（可信 KDC DID）：提供时必须与 warrant.delegator
    一致，防止自签 warrant 伪造代理委托。
    """
    now = now_fn() if now_fn else time.time()
    try:
        sig = bytes.fromhex(warrant["sig"])
    except (KeyError, ValueError):
        return False
    delegator = warrant.get("delegator")
    if trusted_delegator is not None and delegator != trusted_delegator:
        return False
    payload = {k: v for k, v in warrant.items() if k != "sig"}
    if not sm9_engine.verify(delegator, _pack(payload), sig):
        return False
    if now > float(warrant["exp"]):
        return False
    if required_scope not in warrant.get("scope", []):
        return False
    return sm9_engine.verify(warrant["delegatee"], message, signature)


def issue_session_credential(signer, relay_did: str, warrant: dict,
                             device_did: str, user_did: str, auth_id: str,
                             parent_auth_ticket_id: str, parent_ticket_id: str,
                             netperm: dict, sname: str, vaddr: str,
                             st_fingerprint_hex: str, exp: float,
                             now_fn: Optional[Callable[[], float]] = None) -> dict:
    """签发方向二 P2P 会话准入凭证（方向三侧用于构造/交接，非安全签发）。"""
    now = now_fn() if now_fn else time.time()
    payload = {
        "kind": "session_credential",
        "parent_ticket_id": parent_ticket_id,
        "parent_auth_ticket_id": parent_auth_ticket_id,
        "auth_id": auth_id,
        "user_did": user_did,
        "device_did": device_did,
        "netperm": netperm,
        "sname": sname,
        "vaddr": vaddr,
        "relay_did": relay_did,
        "issued_time": now,
        "exp": exp,
        "st_fingerprint": st_fingerprint_hex,
    }
    sig = signer.sign(relay_did, _pack(payload))
    credential = dict(payload)
    credential["sig"] = sig.hex()
    credential["warrant"] = warrant
    return credential


def verify_session_credential(sm9_engine, credential: dict,
                              now_fn: Optional[Callable[[], float]] = None,
                              trusted_kdc_did: Optional[str] = None) -> bool:
    """验方向二 P2P 会话准入凭证：先验 warrant（信任锚 + scope）再验 relay 签名 + 时效。"""
    now = now_fn() if now_fn else time.time()
    warrant = credential["warrant"]
    payload = {k: v for k, v in credential.items() if k not in ("sig", "warrant")}
    try:
        sig = bytes.fromhex(credential["sig"])
    except (KeyError, ValueError):
        return False
    if not proxy_verify(sm9_engine, warrant, _pack(payload), sig,
                        WARRANT_SCOPE_SESSION_CREDENTIAL, now_fn=now_fn,
                        trusted_delegator=trusted_kdc_did):
        return False
    return now <= float(credential["exp"])