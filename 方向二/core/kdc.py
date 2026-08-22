"""
KDC（方向二）：设备登记（绑定校验）/ 用户认证上下文 / 原子设备接入 / 授权 / ST / 代理委托。

- 用户认证上下文：register_user_context 保存方向一认证结果（UserAuthContext），
  替代 register_user(authenticated=True) 的布尔占位。
- 原子设备接入：issue_device_access 一次性签发绑定 user/device 的 auth + ST。
"""

from typing import Callable, Dict, List, Optional

from .audit_logger import AuditLogger
from .auth_context import UserAuthContextService, new_evidence_id
from .authorization import issue_auth, proxy_delegate
from .binding_table import BindingTable
from .common import rand_bytes
from .did import make_device_did
from .st_ticket import STService, TICKET_TTL


class KDC:
    """KDC 单实例（模拟 TEE 外接 SM9 引擎，主密钥不进日志）。"""

    def __init__(self, sm9_engine, audit_logger: Optional[AuditLogger] = None,
                 now_fn: Optional[Callable[[], float]] = None):
        self.sm9 = sm9_engine
        self.kdc_did = make_device_did("kdc", "realm")
        self.sm9.derive_sk(self.kdc_did)
        self.audit = audit_logger
        self.st = STService(sm9_engine, self.kdc_did, audit_logger=audit_logger,
                            now_fn=now_fn)
        self.binding = BindingTable()
        self.devices: Dict[str, dict] = {}          # device_did -> {owner, addr, enrolled_at}
        self.users: Dict[str, Optional[dict]] = {}  # user_did -> UserAuthContext
        self.auth_context = UserAuthContextService(sm9_engine, self.kdc_did,
                                                   now_fn=now_fn)
        self._warrants: List[dict] = []

    # ------------------------------------------------------------------
    # 用户认证上下文（方向一认证结果模拟交接）
    # ------------------------------------------------------------------
    def register_user(self, user_bio_did: str, authenticated: bool = True) -> None:
        """兼容旧接口：authenticated=True 时模拟签发一个 UserAuthContext。

        新代码应优先使用 register_user_context() 传入方向一的真实签名上下文。
        """
        if authenticated:
            self.users[user_bio_did] = self.auth_context.issue(
                user_bio_did, "simulated-source-ticket", new_evidence_id())
        else:
            self.users[user_bio_did] = None

    def register_user_context(self, context: dict) -> bool:
        """验证并保存完整 UserAuthContext（替代布尔占位）。"""
        r = self.auth_context.verify(context)
        if not r["ok"]:
            if self.audit is not None:
                self.audit.log("user_context", "rejected",
                               context.get("user_did", ""))
            return False
        self.users[context["user_did"]] = context
        if self.audit is not None:
            self.audit.log("user_context", "success", context["user_did"])
        return True

    def is_user_authenticated(self, user_did: str) -> bool:
        ctx = self.users.get(user_did)
        if not isinstance(ctx, dict):
            return False
        return self.auth_context.verify(ctx)["ok"]

    # ------------------------------------------------------------------
    # 设备登记（联动校验：设备须关联已认证用户）
    # ------------------------------------------------------------------
    def register_device(self, device_did: str, owner_user_did: str,
                        addr: str = "") -> bool:
        if not self.is_user_authenticated(owner_user_did):
            if self.audit is not None:
                self.audit.log("device_register", "rejected_unbound_user",
                               device_did)
            return False
        self.binding.bind(owner_user_did, device_did)
        self.devices[device_did] = {"owner": owner_user_did, "addr": addr,
                                    "enrolled_at": self.st.now()}
        if self.audit is not None:
            self.audit.log("device_register", "success", device_did)
        return True

    def is_device_enrolled(self, device_did: str) -> bool:
        return device_did in self.devices

    def owner_of(self, device_did: str) -> Optional[str]:
        return self.binding.owner_of(device_did)

    # ------------------------------------------------------------------
    # 原子设备接入：一次签发绑定 user/device 的 auth + ST
    # ------------------------------------------------------------------
    def issue_device_access(self, device_did: str, service: str, netperm: dict,
                            caddr: str = "",
                            ttl: float = TICKET_TTL) -> Optional[dict]:
        """签发前检查：device 已登记 + user 有效 + owner 一致 → 签发 auth + ST。"""
        if device_did not in self.devices:
            return None
        owner = self.binding.owner_of(device_did)
        if owner is None or not self.is_user_authenticated(owner):
            return None
        ctx = self.users[owner]
        parent = ctx.get("source_ticket_id", "") if isinstance(ctx, dict) else ""
        auth_id = rand_bytes(16, "auth_id").hex()
        auth = issue_auth(self.sm9, self.kdc_did, device_did, netperm,
                          exp=self.st.now() + ttl, now_fn=self.st.now,
                          auth_id=auth_id, parent_auth_ticket_id=parent,
                          user_did=owner)
        st = self.st.issue_ticket(device_did, service, netperm, caddr=caddr,
                                  ttl=ttl, auth_id=auth_id,
                                  parent_auth_ticket_id=parent, user_did=owner)
        return {"auth": auth, "st": st}

    # ------------------------------------------------------------------
    # 授权 / 票据 / 代理委托
    # ------------------------------------------------------------------
    def issue_auth(self, did_dev: str, policy: dict, exp: float,
                   auth_id: Optional[str] = None,
                   parent_auth_ticket_id: str = "",
                   user_did: str = "") -> dict:
        return issue_auth(self.sm9, self.kdc_did, did_dev, policy, exp,
                          now_fn=self.st.now, auth_id=auth_id,
                          parent_auth_ticket_id=parent_auth_ticket_id,
                          user_did=user_did)

    def issue_ticket(self, principal: str, service: str, netperm: dict,
                     caddr: str = "", ttl: float = TICKET_TTL,
                     auth_id: str = "", parent_auth_ticket_id: str = "",
                     user_did: str = "") -> dict:
        return self.st.issue_ticket(principal, service, netperm, caddr=caddr,
                                    ttl=ttl, auth_id=auth_id,
                                    parent_auth_ticket_id=parent_auth_ticket_id,
                                    user_did=user_did)

    def delegate_proxy(self, relay_did: str, scope: Optional[list] = None,
                       exp: Optional[float] = None) -> dict:
        warrant = proxy_delegate(self.sm9, self.kdc_did, relay_did,
                                 scope=scope, exp=exp, now_fn=self.st.now)
        self._warrants.append(warrant)
        return warrant

    def warrants(self) -> List[dict]:
        return list(self._warrants)
