"""
Kerberos 增强认证（与专利技术细节一致）：

    注册：用户以 SM9 签名 (ID || DID || ts) 完成登记（存 σ + key_hash，
          σ 非存储式，无明文特征）。
    AS-REQ：SM9 签名 (DID || ts || nonce) 前置验签替代口令
            + 生物特征 Rep 恢复 bio_key（key_hash=SM3(bio_key) 校验）
            + 时间戳窗口 30min + 重放防护
    TGT/TGS/ST：票据载荷 SM4-CBC 加密；字段含 ticket_id；
            时间戳窗口 30min。
    AP：服务端验 ST + Authenticator + 可选 claims_checker 策略回调。

对外接口：
    issue_ticket(...) → (ticket_id, encrypted_ticket)
    verify_ticket(encrypted_ticket, expected_service, claims_checker=None)
"""

import base64
import json
import time
from dataclasses import dataclass, field
from typing import Callable, Dict, List, Optional, Tuple

from .common import rand_bytes, sm3, sm4_cbc_decrypt, sm4_cbc_encrypt
from .audit_logger import AuditLogger
from .simulated_bio_tee import AUTH_METHOD, SCHEMA_VERSION

TICKET_TTL = 1800.0          # 票据有效期 / 时间戳窗口：30 分钟
MAX_SKEW = 1800.0            # 时间戳窗口：30 分钟
REALM = "REALM"
AS_PURPOSE = "kerberos_as"   # AS 仅接受此 purpose（跨协议隔离）


def _b64e(data: bytes) -> str:
    return base64.b64encode(data).decode("ascii")


def _b64d(s: str) -> bytes:
    return base64.b64decode(s)


def _pack(obj: dict) -> bytes:
    return json.dumps(obj, sort_keys=True).encode("utf-8")


def _unpack(data: bytes) -> dict:
    return json.loads(data.decode("utf-8"))


class TicketError(Exception):
    pass


@dataclass
class Ticket:
    """Kerberos 票据（增强版）：字段含 ticket_id。"""
    ticket_id: str
    client_did: str
    service_id: str
    session_key: bytes
    issued_time: float
    validity_period: float
    ticket_type: str = "tgt"          # "tgt" | "service"
    flags: Dict[str, object] = field(default_factory=dict)

    def to_dict(self) -> dict:
        return {
            "ticket_id": self.ticket_id,
            "client_did": self.client_did,
            "service_id": self.service_id,
            "session_key": _b64e(self.session_key),
            "issued_time": self.issued_time,
            "validity_period": self.validity_period,
            "ticket_type": self.ticket_type,
            "flags": self.flags,
        }

    @classmethod
    def from_dict(cls, d: dict) -> "Ticket":
        return cls(
            ticket_id=d["ticket_id"],
            client_did=d["client_did"],
            service_id=d["service_id"],
            session_key=_b64d(d["session_key"]),
            issued_time=float(d["issued_time"]),
            validity_period=float(d["validity_period"]),
            ticket_type=d.get("ticket_type", "tgt"),
            flags=d.get("flags", {}),
        )

    def is_valid(self, now: float) -> bool:
        return now < self.issued_time + self.validity_period


class _Clock:
    """可注入时钟（实验用：超时场景推进时间）。"""

    def __init__(self, now_fn: Optional[Callable[[], float]] = None):
        self._now_fn = now_fn or time.time

    def now(self) -> float:
        return self._now_fn()


def new_ticket_id() -> str:
    return rand_bytes(16, "ticket_id").hex()


class KerberosRealm:
    """Kerberos 域：持有 AS↔TGS 共享密钥、服务密钥、审计日志与时钟。"""

    def __init__(self, audit_logger: Optional[AuditLogger] = None,
                 now_fn: Optional[Callable[[], float]] = None):
        self.clock = _Clock(now_fn)
        self.audit_logger = audit_logger
        self.tgs_key = rand_bytes(32, "realm_tgs_key")
        self.service_keys: Dict[str, bytes] = {}

    def register_service(self, service_id: str) -> bytes:
        key = rand_bytes(32, f"svc_key_{service_id}")
        self.service_keys[service_id] = key
        return key

    def audit(self, action: str, result: str, principal: str,
              ticket_id: Optional[str] = None, extra: Optional[dict] = None):
        if self.audit_logger is not None:
            self.audit_logger.log(action, result, principal, ticket_id,
                                  ts=self.clock.now(), extra=extra)


class AS:
    """认证服务：登记（SM9 签名 ID+DID+ts）、AS-REQ 验证（证明 + SM9 前置验签）。

    生物门控签名由 SimulatedBioTEE 完成；AS 仅通过 verifier 公开验签，
    不持有、不保存 sigma/mask/key_hash/BioKey/私钥。
    """

    def __init__(self, realm: KerberosRealm, verifier, tgs_id: str = "tgs@REALM"):
        self.realm = realm
        self.verifier = verifier
        self.tgs_id = tgs_id
        self.registrations: Dict[str, dict] = {}       # did → {user_id, reg_ts}
        self.used_nonces: Dict[str, float] = {}        # 重放防护

    # ------------------------------------------------------------------
    # 注册
    # ------------------------------------------------------------------
    def register(self, did: str, user_id: str,
                 reg_signature: bytes, reg_ts: float, now: Optional[float] = None) -> bool:
        """登记：验 SM9 签名 (user_id || did || ts) + 时间戳窗口。

        不保存 key_hash/sigma/bio_key/mask/私钥（生物门控在 TEE 内）。
        """
        now = now if now is not None else self.realm.clock.now()
        if abs(now - reg_ts) > MAX_SKEW:
            self.realm.audit("register", "rejected_ts", did)
            return False
        message = _pack({"user_id": user_id, "did": did, "ts": reg_ts})
        if not self.verifier.verify(did, message, reg_signature):
            self.realm.audit("register", "rejected_sig", did)
            return False
        self.registrations[did] = {
            "user_id": user_id,
            "reg_ts": reg_ts,
        }
        self.realm.audit("register", "success", did)
        return True

    def is_registered(self, did: str) -> bool:
        return did in self.registrations

    # ------------------------------------------------------------------
    # AS-REQ
    # ------------------------------------------------------------------
    def authenticate(self, did: str, nonce: bytes, ts: float,
                     evidence: dict, now: Optional[float] = None) -> dict:
        """AS-REQ 处理：
            1) DID 已登记
            2) 时间戳窗口 30min
            3) nonce 防重放
            4) AuthEvidence v1：schema/user_did/nonce/context_digest 一致性
            5) 模拟证明有效（委托子进程）
            6) SM9 签名有效（verifier 公开验签，绑定 purpose+context_digest）
            7) 签发 TGT（flags 传播 auth_method/evidence_id/measurement）

        不接收、不校验 bio_key（生物门控已在 SimulatedBioTEE 内完成）。
        """
        now = now if now is not None else self.realm.clock.now()
        reg = self.registrations.get(did)
        if reg is None:
            self.realm.audit("as_req", "rejected_unknown", did)
            return {"ok": False, "error": "unknown_did"}
        if abs(now - ts) > MAX_SKEW:
            self.realm.audit("as_req", "rejected_ts", did)
            return {"ok": False, "error": "timestamp_out_of_window"}
        context = _pack({"did": did, "ts": ts, "nonce": _b64e(nonce)})
        context_digest = sm3(context).hex()
        nonce_key = f"{did}:{_b64e(nonce)}"
        if nonce_key in self.used_nonces and now - self.used_nonces[nonce_key] < MAX_SKEW:
            self.realm.audit("as_req", "rejected_replay", did)
            return {"ok": False, "error": "replay_detected"}
        if not isinstance(evidence, dict) or evidence.get("purpose") != AS_PURPOSE:
            self.realm.audit("as_req", "rejected_purpose", did)
            return {"ok": False, "error": "purpose_mismatch"}
        if not self._evidence_valid(evidence, did, nonce, ts, context_digest):
            self.realm.audit("as_req", "rejected_attestation", did)
            return {"ok": False, "error": "attestation_invalid"}
        payload = _pack({"did": did, "ts": ts, "nonce": _b64e(nonce),
                         "purpose": evidence["purpose"],
                         "context_digest": context_digest})
        signature = _b64d(evidence["signature"])
        if not self.verifier.verify(did, payload, signature):
            self.realm.audit("as_req", "rejected_sig", did)
            return {"ok": False, "error": "sm9_signature_invalid"}
        self.used_nonces[nonce_key] = now
        tgt = self._issue_ticket(
            did, self.tgs_id, now,
            flags={"auth_method": evidence.get("auth_method", AUTH_METHOD),
                   "evidence_id": evidence.get("evidence_id"),
                   "measurement": (evidence.get("attestation") or {}).get("measurement")})
        self.realm.audit("as_req", "success", did, ticket_id=tgt["ticket_id"])
        return {"ok": True, "tgt": tgt, "session_key": tgt["session_key"]}

    def _evidence_valid(self, evidence: dict, did: str, nonce: bytes,
                        ts: float, context_digest: str) -> bool:
        """验 AuthEvidence：schema/auth_method/user_did/nonce/issued_at/
        context_digest 一致性 + 模拟证明（委托子进程）。"""
        if not isinstance(evidence, dict):
            return False
        if evidence.get("schema_version") != SCHEMA_VERSION:
            return False
        if evidence.get("auth_method") != AUTH_METHOD:
            return False
        if evidence.get("user_did") != did:
            return False
        if evidence.get("nonce") != _b64e(nonce):
            return False
        if evidence.get("issued_at") != ts:
            return False
        if evidence.get("context_digest") != context_digest:
            return False
        if not self.verifier.verify_attestation(evidence):
            return False
        return True

    def _issue_ticket(self, client_did: str, service_id: str, now: float,
                      flags: Optional[dict] = None) -> dict:
        f = {"realm": REALM, "auth_method": AUTH_METHOD}
        if flags:
            f.update(flags)
        ticket = Ticket(
            ticket_id=new_ticket_id(),
            client_did=client_did,
            service_id=service_id,
            session_key=rand_bytes(32, f"sk_{client_did}_{service_id}"),
            issued_time=now,
            validity_period=TICKET_TTL,
            ticket_type="tgt" if service_id.startswith("tgs") else "service",
            flags=f,
        )
        return self._seal(ticket)

    def _seal(self, ticket: Ticket) -> dict:
        """票据载荷 SM4-CBC 加密（AS↔TGS 共享密钥 / 服务密钥）。"""
        key = self.realm.tgs_key if ticket.ticket_type == "tgt" \
            else self.realm.service_keys[ticket.service_id]
        return {
            "ticket_id": ticket.ticket_id,
            "ticket_type": ticket.ticket_type,
            "service_id": ticket.service_id,
            "encrypted": _b64e(sm4_cbc_encrypt(_pack(ticket.to_dict()), key)),
            "session_key": ticket.session_key,
            "issued_time": ticket.issued_time,
            "validity_period": ticket.validity_period,
        }


class TGS:
    """票据授予服务：验 TGT → 签发 ST。"""

    def __init__(self, realm: KerberosRealm):
        self.realm = realm
        self.used_auths: Dict[str, float] = {}

    def grant_service_ticket(self, encrypted_tgt: str, authenticator: dict,
                             nonce: bytes, now: Optional[float] = None) -> dict:
        now = now if now is not None else self.realm.clock.now()
        try:
            tgt = Ticket.from_dict(_unpack(
                sm4_cbc_decrypt(_b64d(encrypted_tgt), self.realm.tgs_key)))
        except Exception:
            self.realm.audit("tgs_req", "rejected_tgt", "-", extra={"error": "tgt_decrypt"})
            return {"ok": False, "error": "invalid_tgt"}
        if not tgt.is_valid(now):
            self.realm.audit("tgs_req", "rejected_tgt_expired", tgt.client_did,
                             ticket_id=tgt.ticket_id)
            return {"ok": False, "error": "tgt_expired"}
        try:
            auth_inner = _unpack(sm4_cbc_decrypt(
                _b64d(authenticator["encrypted"]), tgt.session_key))
        except Exception:
            self.realm.audit("tgs_req", "rejected_auth", tgt.client_did,
                             ticket_id=tgt.ticket_id, extra={"error": "auth_decrypt"})
            return {"ok": False, "error": "invalid_authenticator"}
        if auth_inner.get("client_did") != tgt.client_did:
            self.realm.audit("tgs_req", "rejected_auth_did", tgt.client_did,
                             ticket_id=tgt.ticket_id)
            return {"ok": False, "error": "authenticator_did_mismatch"}
        if abs(now - float(auth_inner.get("ts", authenticator["ts"]))) > MAX_SKEW:
            self.realm.audit("tgs_req", "rejected_ts", tgt.client_did,
                             ticket_id=tgt.ticket_id)
            return {"ok": False, "error": "authenticator_ts_out_of_window"}
        auth_key = f"{tgt.client_did}:{tgt.ticket_id}:{authenticator['nonce']}"
        if auth_key in self.used_auths and now - self.used_auths[auth_key] < MAX_SKEW:
            self.realm.audit("tgs_req", "rejected_replay", tgt.client_did,
                             ticket_id=tgt.ticket_id)
            return {"ok": False, "error": "replay_detected"}
        self.used_auths[auth_key] = now
        service_id = authenticator.get("service_id")
        if service_id not in self.realm.service_keys:
            self.realm.audit("tgs_req", "rejected_unknown_service", tgt.client_did,
                             ticket_id=tgt.ticket_id)
            return {"ok": False, "error": "unknown_service"}
        st = self._issue_st(tgt, service_id, now)
        self.realm.audit("tgs_req", "success", tgt.client_did, ticket_id=st["ticket_id"])
        return {"ok": True, "st": st, "session_key": st["session_key"]}

    def _issue_st(self, tgt: Ticket, service_id: str, now: float) -> dict:
        ticket = Ticket(
            ticket_id=new_ticket_id(),
            client_did=tgt.client_did,
            service_id=service_id,
            session_key=rand_bytes(32, f"sk_{tgt.client_did}_{service_id}_st"),
            issued_time=now,
            validity_period=TICKET_TTL,
            ticket_type="service",
            flags={"realm": REALM, "auth_method": tgt.flags.get("auth_method", "sm9_bio")},
        )
        key = self.realm.service_keys[service_id]
        return {
            "ticket_id": ticket.ticket_id,
            "ticket_type": ticket.ticket_type,
            "service_id": ticket.service_id,
            "encrypted": _b64e(sm4_cbc_encrypt(_pack(ticket.to_dict()), key)),
            "session_key": ticket.session_key,
            "issued_time": ticket.issued_time,
            "validity_period": ticket.validity_period,
        }


class Service:
    """应用服务：验 ST + Authenticator + claims_checker 策略。"""

    def __init__(self, realm: KerberosRealm, service_id: str):
        self.realm = realm
        self.service_id = service_id
        self.used_auths: Dict[str, float] = {}

    def verify_ticket(self, encrypted_st: str, expected_service: str,
                      claims_checker: Optional[Callable[[dict], bool]] = None,
                      now: Optional[float] = None) -> dict:
        """验 ST：SM4 解密 → 有效性 → claims_checker 策略回调。"""
        now = now if now is not None else self.realm.clock.now()
        try:
            st = Ticket.from_dict(_unpack(
                sm4_cbc_decrypt(_b64d(encrypted_st), self.realm.service_keys[expected_service])))
        except Exception:
            self.realm.audit("ap_req", "rejected_st", "-", extra={"error": "st_decrypt"})
            return {"ok": False, "error": "invalid_st"}
        if st.ticket_type != "service":
            return {"ok": False, "error": "not_service_ticket"}
        if st.service_id != expected_service:
            self.realm.audit("ap_req", "rejected_service_mismatch", st.client_did,
                             ticket_id=st.ticket_id)
            return {"ok": False, "error": "service_mismatch"}
        if not st.is_valid(now):
            self.realm.audit("ap_req", "rejected_st_expired", st.client_did,
                             ticket_id=st.ticket_id)
            return {"ok": False, "error": "st_expired"}
        if claims_checker is not None:
            claims = {"client_did": st.client_did, "ticket_id": st.ticket_id,
                      "service_id": st.service_id, "issued_time": st.issued_time}
            if not claims_checker(claims):
                self.realm.audit("ap_req", "rejected_claims", st.client_did,
                                 ticket_id=st.ticket_id)
                return {"ok": False, "error": "claims_rejected"}
        self.realm.audit("ap_req", "success", st.client_did, ticket_id=st.ticket_id)
        return {"ok": True, "ticket": st, "claims": {
            "client_did": st.client_did, "ticket_id": st.ticket_id,
            "service_id": st.service_id, "session_key": st.session_key,
            "issued_time": st.issued_time, "validity": st.validity_period,
        }}

    def verify_authenticator(self, encrypted_authenticator: str, session_key: bytes,
                             now: Optional[float] = None) -> dict:
        """验 Authenticator（会话密钥加密）：时间戳窗口 + 重放。"""
        now = now if now is not None else self.realm.clock.now()
        try:
            auth = _unpack(sm4_cbc_decrypt(_b64d(encrypted_authenticator), session_key))
        except Exception:
            return {"ok": False, "error": "invalid_authenticator"}
        if abs(now - float(auth["ts"])) > MAX_SKEW:
            return {"ok": False, "error": "authenticator_ts_out_of_window"}
        key = f"{auth['client_did']}:{auth['nonce']}"
        if key in self.used_auths and now - self.used_auths[key] < MAX_SKEW:
            return {"ok": False, "error": "replay_detected"}
        self.used_auths[key] = now
        return {"ok": True, "auth": auth}

    def verify_ap_req(self, ap_req: dict,
                      claims_checker: Optional[Callable[[dict], bool]] = None,
                      now: Optional[float] = None) -> dict:
        """完整 AP-REQ 处理：验 ST（SM4+有效期+claims）→ 验 Authenticator。"""
        now = now if now is not None else self.realm.clock.now()
        r = self.verify_ticket(ap_req["encrypted_st"], ap_req["service_id"],
                               claims_checker=claims_checker, now=now)
        if not r["ok"]:
            return r
        st = r["ticket"]
        ra = self.verify_authenticator(ap_req["authenticator"],
                                       st.session_key, now=now)
        if not ra["ok"]:
            self.realm.audit("ap_req", "rejected_authenticator", st.client_did,
                             ticket_id=st.ticket_id, extra={"error": ra["error"]})
            return {"ok": False, "error": ra["error"]}
        return {"ok": True, "ticket": st, "claims": r["claims"], "auth": ra["auth"]}


class KerberosClient:
    """客户端：构造 AS-REQ（经生物门控 TEE 签名）、TGS-REQ、AP-REQ。"""

    def __init__(self, did: str, tee):
        self.did = did
        self.tee = tee
        self.tgt: Optional[dict] = None
        self.tgt_session_key: Optional[bytes] = None
        self.service_tickets: Dict[str, dict] = {}

    # ------------------------------------------------------------------
    def build_as_req(self, now: float, probe_embedding,
                     purpose: str = "kerberos_as") -> dict:
        nonce = rand_bytes(16, f"as_nonce_{self.did}")
        ts = now
        context = _pack({"did": self.did, "ts": ts, "nonce": _b64e(nonce)})
        auth = self.tee.authenticate_and_sign(self.did, probe_embedding,
                                              context, nonce, ts, purpose=purpose)
        return {"did": self.did, "ts": ts, "nonce": nonce,
                "evidence": auth["evidence"]}

    def build_tgs_req(self, service_id: str, now: float) -> dict:
        if self.tgt is None:
            raise TicketError("no_tgt")
        nonce = rand_bytes(16, f"tgs_nonce_{self.did}")
        auth = _pack({"client_did": self.did, "ts": now, "nonce": _b64e(nonce),
                      "service_id": service_id})
        encrypted_auth = _b64e(sm4_cbc_encrypt(auth, self.tgt_session_key))
        return {"encrypted_tgt": self.tgt["encrypted"],
                "authenticator": {"ts": now, "nonce": _b64e(nonce), "service_id": service_id,
                                  "encrypted": encrypted_auth},
                "nonce": nonce}

    def build_ap_req(self, service_id: str, now: float) -> dict:
        st = self.service_tickets.get(service_id)
        if st is None:
            raise TicketError("no_service_ticket")
        nonce = rand_bytes(16, f"ap_nonce_{self.did}")
        auth = _pack({"client_did": self.did, "ts": now, "nonce": _b64e(nonce)})
        encrypted_auth = _b64e(sm4_cbc_encrypt(auth, st["session_key"]))
        return {"encrypted_st": st["encrypted"], "authenticator": encrypted_auth,
                "service_id": service_id, "nonce": nonce}

    # ------------------------------------------------------------------
    def store_tgt(self, tgt: dict) -> None:
        self.tgt = tgt
        self.tgt_session_key = tgt["session_key"]

    def store_st(self, st: dict) -> None:
        self.service_tickets[st["service_id"]] = st

    def clear_tickets(self) -> None:
        self.tgt = None
        self.tgt_session_key = None
        self.service_tickets.clear()

    def ticket_ids(self) -> List[str]:
        ids = []
        if self.tgt is not None:
            ids.append(self.tgt["ticket_id"])
        ids.extend(st["ticket_id"] for st in self.service_tickets.values())
        return ids