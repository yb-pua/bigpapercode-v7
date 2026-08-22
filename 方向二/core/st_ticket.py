"""
ST 票据（方向二）：JSON 载荷 + SM9 签名。

字段：{Realm, Principal=DID_dev, SName, NetPerm, Times={Start,End},
      CAddr, Sig, ticket_id}；时间戳窗口 30min；载荷格式 JSON。

对外接口：
    issue_ticket(principal, service, netperm, caddr, times=None) → ticket
    verify_ticket(ticket, service, claims_checker=None) → dict
"""

import json
import time
from typing import Callable, Dict, Optional

from .common import rand_bytes, sm3

REALM = "REALM"
TICKET_TTL = 1800.0          # 票据有效期 / 时间戳窗口：30 分钟
MAX_SKEW = 1800.0


def _pack(obj: dict) -> bytes:
    return json.dumps(obj, sort_keys=True).encode("utf-8")


def new_ticket_id() -> str:
    return rand_bytes(16, "st_ticket_id").hex()


def netperm_defaults() -> dict:
    """NetPerm 默认结构：{services: [...], bandwidth_mbps: float, time_slots: [...], region: str}。"""
    return {"services": [], "bandwidth_mbps": 0.0, "time_slots": [], "region": "lan"}


class TicketError(Exception):
    pass


class STService:
    """票据服务（KDC 侧）：签发 ST，含 ticket_id、NetPerm、Times、CAddr、Sig。"""

    def __init__(self, sm9_engine, kdc_did: str, audit_logger=None,
                 now_fn: Optional[Callable[[], float]] = None):
        self.sm9 = sm9_engine
        self.kdc_did = kdc_did
        self.audit = audit_logger
        self._now_fn = now_fn or time.time

    def now(self) -> float:
        return self._now_fn()

    def issue_ticket(self, principal: str, service: str, netperm: dict,
                     caddr: str = "", times: Optional[dict] = None,
                     ttl: float = TICKET_TTL, auth_id: str = "",
                     parent_auth_ticket_id: str = "",
                     user_did: str = "") -> dict:
        """签发 ST：payload 字段 + SM9 签名（KDC 私钥）。principal 即 device_did。"""
        import copy
        netperm = copy.deepcopy(netperm)
        now = self.now()
        times = times or {"start": now, "end": now + ttl}
        ticket_id = new_ticket_id()
        payload = {
            "realm": REALM,
            "ticket_id": ticket_id,
            "auth_id": auth_id,
            "parent_auth_ticket_id": parent_auth_ticket_id,
            "user_did": user_did,
            "device_did": principal,
            "principal": principal,
            "sname": service,
            "netperm": netperm,
            "times": {"start": float(times["start"]), "end": float(times["end"])},
            "caddr": caddr,
            "issued_time": now,
        }
        sig = self.sm9.sign(self.kdc_did, _pack(payload))
        ticket = dict(payload)
        ticket["sig"] = sig.hex()
        return ticket

    def verify_ticket(self, ticket: dict, service: str,
                      claims_checker: Optional[Callable[[dict], bool]] = None,
                      now: Optional[float] = None,
                      replay_cache: Optional[Dict[str, float]] = None) -> dict:
        """验 ST：签名 → 时效（30min 窗口）→ SName → 单次使用 → claims_checker。"""
        now = now if now is not None else self.now()
        payload = {k: v for k, v in ticket.items() if k != "sig"}
        try:
            sig = bytes.fromhex(ticket["sig"])
        except (KeyError, ValueError):
            return {"ok": False, "error": "invalid_signature"}
        if not self.sm9.verify(self.kdc_did, _pack(payload), sig):
            return {"ok": False, "error": "signature_invalid"}
        if float(ticket["times"]["start"]) - MAX_SKEW > now or \
                now > float(ticket["times"]["end"]):
            return {"ok": False, "error": "ticket_out_of_window"}
        if ticket["sname"] != service:
            return {"ok": False, "error": "service_mismatch"}
        tid = ticket["ticket_id"]
        if replay_cache is not None:
            if tid in replay_cache and now - replay_cache[tid] < TICKET_TTL:
                return {"ok": False, "error": "replay_detected"}
            replay_cache[tid] = now
        claims = {
            "client_did": ticket["principal"],
            "ticket_id": tid,
            "service_id": ticket["sname"],
            "netperm": ticket["netperm"],
            "issued_time": float(ticket["issued_time"]),
            "validity": float(ticket["times"]["end"]) - float(ticket["times"]["start"]),
        }
        if claims_checker is not None and not claims_checker(claims):
            return {"ok": False, "error": "claims_rejected"}
        if self.audit is not None:
            self.audit.log("st_verify", "success", ticket["principal"], ticket_id=tid)
        return {"ok": True, "ticket": payload, "claims": claims}


def make_st_replay_cache() -> Dict[str, float]:
    """ST 单次使用缓存（重放第二次拒绝；TTL 与票有效期一致）。"""
    return {}


def st_fingerprint(ticket: dict) -> bytes:
    """票据指纹（SM3），用于路由/日志关联（不含签名）。"""
    payload = {k: v for k, v in ticket.items() if k != "sig"}
    return sm3(_pack(payload))