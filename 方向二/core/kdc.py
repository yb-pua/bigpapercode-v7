"""
KDC（方向二）：设备登记（含绑定校验）/ 授权签发 / ST 签发 / 代理委托。

- 设备登记：登记表 {device_did: {owner_user_did, addr}}，绑定校验（无绑定/未认证拒绝）。
- 授权：issue_auth（NetPerm 策略）。
- 票据：STService.issue_ticket（含 ticket_id / NetPerm / Times / CAddr / Sig）。
- 代理委托：proxy_delegate（warrant scope 限定会话准入凭证）。
"""

from typing import Callable, Dict, List, Optional

from .audit_logger import AuditLogger
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
        self.devices: Dict[str, dict] = {}      # device_did -> {owner, addr, enrolled_at}
        self.users: Dict[str, bool] = {}        # user_bio_did -> authenticated
        self._warrants: List[dict] = []

    # ------------------------------------------------------------------
    # 设备登记（联动校验：设备须关联已认证用户）
    # ------------------------------------------------------------------
    def register_device(self, device_did: str, owner_user_did: str,
                        addr: str = "") -> bool:
        """登记设备。绑定用户未登记/未认证 → 拒绝（联动）。"""
        if owner_user_did not in self.users or not self.users[owner_user_did]:
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

    def register_user(self, user_bio_did: str, authenticated: bool = True) -> None:
        """登记用户（模拟生物 DID 已通过方向一认证）。"""
        self.users[user_bio_did] = authenticated

    def is_device_enrolled(self, device_did: str) -> bool:
        return device_did in self.devices

    def owner_of(self, device_did: str) -> Optional[str]:
        return self.binding.owner_of(device_did)

    # ------------------------------------------------------------------
    # 授权 / 票据 / 代理委托
    # ------------------------------------------------------------------
    def issue_auth(self, did_dev: str, policy: dict, exp: float) -> dict:
        return issue_auth(self.sm9, self.kdc_did, did_dev, policy, exp,
                          now_fn=self.st.now)

    def issue_ticket(self, principal: str, service: str, netperm: dict,
                     caddr: str = "", ttl: float = TICKET_TTL) -> dict:
        return self.st.issue_ticket(principal, service, netperm, caddr=caddr,
                                    ttl=ttl)

    def delegate_proxy(self, relay_did: str, scope: Optional[list] = None,
                       exp: Optional[float] = None) -> dict:
        warrant = proxy_delegate(self.sm9, self.kdc_did, relay_did,
                                 scope=scope, exp=exp, now_fn=self.st.now)
        self._warrants.append(warrant)
        return warrant

    def warrants(self) -> List[dict]:
        return list(self._warrants)