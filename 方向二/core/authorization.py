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
from .st_ticket import st_fingerprint

WARRANT_SCOPE_SESSION_CREDENTIAL = "session_credential"


def _pack(obj: dict) -> bytes:
    return json.dumps(obj, sort_keys=True).encode("utf-8")


def netperm_subset(st_netperm: dict, auth_policy: dict) -> bool:
    """检查 netperm 是否被 policy 覆盖（services 子集 + bandwidth 不超）。"""
    if not isinstance(st_netperm, dict) or not isinstance(auth_policy, dict):
        return False
    st_services = set(st_netperm.get("services", []))
    auth_services = set(auth_policy.get("services", []))
    if not st_services.issubset(auth_services):
        return False
    if float(st_netperm.get("bandwidth_mbps", 0.0)) > \
            float(auth_policy.get("bandwidth_mbps", 0.0)):
        return False
    return True


class AuthorizationError(Exception):
    pass


def issue_auth(sm9_engine, kdc_did: str, did_dev: str, policy: dict,
               exp: float, now_fn: Optional[Callable[[], float]] = None,
               auth_id: Optional[str] = None,
               parent_auth_ticket_id: str = "",
               user_did: str = "") -> dict:
    """KDC 签发授权：A = {auth_id, parent_auth_ticket_id, user_did, device_did,
    policy, exp, issued_time, Sig_KDC}。"""
    now = now_fn() if now_fn else time.time()
    payload = {
        "auth_id": auth_id or rand_bytes(16, "auth_id").hex(),
        "parent_auth_ticket_id": parent_auth_ticket_id,
        "user_did": user_did,
        "device_did": did_dev,
        "policy": policy,
        "exp": exp,
        "issued_time": now,
    }
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
    一致，防止中继自签 warrant（delegator 由票据自声明）伪造代理委托。
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
    """中继（代理签名者）签发会话准入凭证：绑定 user/device/auth/ST 链。

    signer 为受限签名器（只允许签 relay_did）；netperm 须来自第一轮 verified claims。
    """
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
                              st: Optional[dict] = None,
                              trusted_kdc_did: Optional[str] = None) -> bool:
    """验会话准入凭证：先验 warrant（scope 限定）再验 relay 签名 + 时效。

    trusted_kdc_did 为信任锚（可信 KDC DID），须传入以拒绝自签 warrant。
    当提供原 KDC 签名 ST（st 参数）时，额外校验凭证与原 ST 的审计链一致、
    且凭证 netperm 未超出 ST 权限、exp 未超过 ST 结束时间。
    """
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
    if now > float(credential["exp"]):
        return False
    if st is not None:
        # 审计链一致性：凭证必须绑定原 ST 的 ticket_id / 指纹 / 四元身份
        if credential.get("parent_ticket_id") != st.get("ticket_id"):
            return False
        if credential.get("st_fingerprint") != st_fingerprint(st).hex():
            return False
        if float(credential.get("exp", 0)) > float(st["times"]["end"]):
            return False
        for f in ("device_did", "user_did", "auth_id", "parent_auth_ticket_id"):
            if credential.get(f) != st.get(f):
                return False
        if not netperm_subset(credential.get("netperm", {}), st.get("netperm", {})):
            return False
    return True