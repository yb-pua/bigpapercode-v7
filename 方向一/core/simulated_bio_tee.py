"""模拟生物 TEE：生物门控 SM9 签名（AuthEvidence v1）。

设计目标（小论文模拟实验原型，非真实 TEE/TPM）：
    - 敏感状态（sigma、mask、key_hash、BioKey、SM9 私钥）仅存在于子进程内存。
    - 模拟证明密钥也在子进程内生成，主进程无法直接获得；验证明走子进程。
    - 生物 Rep 失败（异人/纠错失败/key_hash 不匹配）一律不签名，并计入限次。

安全语义：
    - DID 与人脸/生物密钥无派生关系；SM9 私钥仍由 KGC 依据 DID 派生（子进程内）。
    - BioKey 仅作为「SM9 私钥使用权限」的生物门控条件。
    - 签名与模拟证明同时绑定 purpose + context_digest。

对外接口：
    enroll / authenticate_and_sign / verify / verify_attestation / stop
"""

import base64
import hmac as _hmac
import json
import multiprocessing
import secrets
import time
from typing import Dict, Optional

import numpy as np

from .common import hmac_sm3, rand_bytes, sm3
from .fuzzy_extractor import FuzzyExtractor
from .preprocessing import quantize_to_bits
from .sm9_engine import SM9Engine
from .stable_bits import majority_vote, select_stable

# 公开度量值（非敏感，标注 simulated）
MEASUREMENT = "simulated-bio-tee-v1"
ATTESTATION_TYPE = "simulated-hmac"
AUTH_METHOD = "bio-sm9-simulated"
SCHEMA_VERSION = "v1"

# 算法口径（与实验一致，禁止切换为 Min-Max 归一化）
BIT_THRESHOLD = 0.0
STABLE_THRESHOLD = 0.8
NUM_BITS = 256
DIM = 512
DEFAULT_MAX_ATTEMPTS = 3


def _b64(data: bytes) -> str:
    return base64.b64encode(data).decode("ascii")


def _b64d(s: str) -> bytes:
    return base64.b64decode(s)


def _pack(obj: dict) -> bytes:
    return json.dumps(obj, sort_keys=True).encode("utf-8")


def _quantize(embedding) -> np.ndarray:
    """512 维嵌入 → 512 比特（threshold=0.0 符号量化）。"""
    return quantize_to_bits(np.asarray(embedding, dtype=np.float64),
                            BIT_THRESHOLD)


def _enroll_internal(fe: FuzzyExtractor, embeddings):
    """登记：量化 → 多数投票 → 稳定位 → Gen。返回 (W, mask, bio_key, sigma)。"""
    bit_matrix = np.stack([_quantize(e) for e in embeddings])
    voted, stability = majority_vote(bit_matrix)
    W, mask = select_stable(voted, stability, threshold=STABLE_THRESHOLD,
                            num_bits=NUM_BITS)
    bio_key, sigma = fe.gen(W, mask)
    return W, mask, bio_key, sigma


def _signing_payload(did: str, ts: float, nonce: bytes, purpose: str,
                     context_digest: str) -> bytes:
    """签名/验签共用的绑定载荷（绑定 purpose + context_digest）。"""
    return _pack({"did": did, "ts": ts, "nonce": _b64(nonce),
                  "purpose": purpose, "context_digest": context_digest})


def _attestation_bound(did: str, nonce_b64: str, ts: float, purpose: str,
                       context_digest: str, evidence_id: str) -> bytes:
    """证明 MAC 绑定的字段（含 schema_version/auth_method/purpose）。"""
    return _pack({
        "schema_version": SCHEMA_VERSION,
        "user_did": did,
        "auth_method": AUTH_METHOD,
        "purpose": purpose,
        "context_digest": context_digest,
        "nonce": nonce_b64,
        "issued_at": ts,
        "evidence_id": evidence_id,
        "measurement": MEASUREMENT,
    })


def _make_attestation(evidence_key: bytes, did: str, nonce: bytes, ts: float,
                      purpose: str, context_digest: str, evidence_id: str) -> dict:
    """子进程内用内部证明密钥生成模拟证明（HMAC-SM3）。"""
    bound = _attestation_bound(did, _b64(nonce), ts, purpose, context_digest,
                               evidence_id)
    return {
        "measurement": MEASUREMENT,
        "attestation_type": ATTESTATION_TYPE,
        "hardware_tee": False,
        "hardware_tpm": False,
        "mac": hmac_sm3(evidence_key, bound).hex(),
    }


def _verify_attestation_internal(evidence_key: bytes, evidence: dict) -> bool:
    """子进程内验证模拟证明（内部证明密钥重算，compare_digest 比对）。"""
    if not isinstance(evidence, dict):
        return False
    if evidence.get("schema_version") != SCHEMA_VERSION:
        return False
    if evidence.get("auth_method") != AUTH_METHOD:
        return False
    att = evidence.get("attestation")
    if not isinstance(att, dict):
        return False
    if att.get("measurement") != MEASUREMENT:
        return False
    if att.get("attestation_type") != ATTESTATION_TYPE:
        return False
    mac = att.get("mac")
    if not mac:
        return False
    bound = _attestation_bound(
        evidence.get("user_did"), evidence.get("nonce"),
        evidence.get("issued_at"), evidence.get("purpose"),
        evidence.get("context_digest"), evidence.get("evidence_id"))
    return _hmac.compare_digest(hmac_sm3(evidence_key, bound).hex(), mac)


def _tee_process(conn, max_attempts):
    """TEE 子进程：持有敏感状态 + SM9 KGC 主密钥/私钥 + 证明密钥。"""
    fe = FuzzyExtractor()
    engine = SM9Engine()
    # 模拟证明密钥：仅在子进程内随机生成（非源码可计算），不返回主进程
    evidence_key = secrets.token_bytes(32)
    # did -> {sigma, mask, key_hash, bio_key, attempts, blocked, max_attempts}
    states: Dict[str, dict] = {}

    while True:
        try:
            req = conn.recv()
        except (EOFError, OSError):
            return
        if req == "STOP":
            conn.send("OK")
            return
        op = req.get("op")
        did = req.get("did")

        if op == "enroll":
            try:
                W, mask, bio_key, sigma = _enroll_internal(fe, req["embeddings"])
                key_hash = fe.key_hash(bio_key)
                reg_sig = engine.sign(did, req["registration_message"])
                states[did] = {
                    "sigma": sigma, "mask": mask, "key_hash": key_hash,
                    "bio_key": bio_key, "attempts": 0, "blocked": False,
                    "max_attempts": max_attempts,
                }
                conn.send({"ok": True, "registration_signature": reg_sig,
                           "simulated": True})
            except Exception:
                conn.send({"ok": False, "error": "enroll_failed",
                           "registration_signature": None})
            continue

        if op == "auth_sign":
            st = states.get(did)
            if st is None:
                conn.send({"ok": False, "error": "unknown_did",
                           "evidence": None})
                continue
            if st["blocked"]:
                conn.send({"ok": False, "error": "blocked", "evidence": None})
                continue
            try:
                pb = _quantize(req["probe_embedding"])[st["mask"] == 1]
                recovered = fe.rep(pb, st["sigma"], key_hash=st["key_hash"])
            except Exception:
                recovered = None
            if recovered is None:
                st["attempts"] += 1
                # max_attempts=None 表示不限次（G2 消融），永不 blocked
                if st["max_attempts"] is not None and st["attempts"] >= st["max_attempts"]:
                    st["blocked"] = True
                conn.send({"ok": False, "error": "bio_auth_failed",
                           "evidence": None})
                continue
            st["attempts"] = 0
            context = req["context"]
            context_digest = sm3(context).hex()
            ts = req["ts"]
            purpose = req.get("purpose", "kerberos_as")
            nonce = req["nonce"]
            payload = _signing_payload(did, ts, nonce, purpose, context_digest)
            try:
                signature = engine.sign(did, payload)
            except Exception:
                conn.send({"ok": False, "error": "sign_failed", "evidence": None})
                continue
            evidence_id = rand_bytes(16, "evidence_id").hex()
            evidence = {
                "schema_version": SCHEMA_VERSION,
                "user_did": did,
                "auth_method": AUTH_METHOD,
                "purpose": purpose,
                "context_digest": context_digest,
                "nonce": _b64(nonce),
                "issued_at": ts,
                "evidence_id": evidence_id,
                "signature": _b64(signature),
                "attestation": _make_attestation(
                    evidence_key, did, nonce, ts, purpose, context_digest,
                    evidence_id),
            }
            conn.send({"ok": True, "evidence": evidence, "error": None})
            continue

        if op == "verify":
            try:
                ok = bool(engine.verify(did, req["message"], req["signature"]))
            except Exception:
                ok = False
            conn.send({"ok": ok})
            continue

        if op == "verify_attestation":
            ok = _verify_attestation_internal(evidence_key, req["evidence"])
            conn.send({"ok": ok})
            continue

        conn.send({"ok": False, "error": "unknown_op"})


class SimulatedBioTEE:
    """模拟生物 TEE：独立进程持有敏感状态 + 证明密钥，对外仅门控接口。"""

    def __init__(self, max_attempts: Optional[int] = DEFAULT_MAX_ATTEMPTS):
        # max_attempts=None 表示不限次（G2 限次消融）
        self.max_attempts = max_attempts
        self._parent_conn, self._child_conn = multiprocessing.Pipe()
        self._proc = multiprocessing.Process(
            target=_tee_process, args=(self._child_conn, max_attempts),
            daemon=True)
        self._proc.start()

    def enroll(self, did: str, enrollment_embeddings,
               registration_message: bytes) -> dict:
        self._parent_conn.send({
            "op": "enroll", "did": did,
            "embeddings": [np.asarray(e, dtype=np.float64)
                           for e in enrollment_embeddings],
            "registration_message": registration_message,
        })
        resp = self._parent_conn.recv()
        return {
            "ok": resp.get("ok", False),
            "tee_handle": did,
            "registration_signature": resp.get("registration_signature"),
            "simulated": True,
        }

    def authenticate_and_sign(self, did: str, probe_embedding, context: bytes,
                              nonce: bytes, ts: float, purpose: str = "kerberos_as",
                              device_id: str = "sim-device") -> dict:
        """生物门控签名 + AuthEvidence v1 生成。

        返回 {"ok", "evidence", "error"}；evidence 为 AuthEvidence v1。
        签名与证明同时绑定 purpose + context_digest。
        """
        self._parent_conn.send({
            "op": "auth_sign", "did": did,
            "probe_embedding": np.asarray(probe_embedding, dtype=np.float64),
            "context": context, "nonce": nonce, "ts": ts,
            "purpose": purpose, "device_id": device_id,
        })
        resp = self._parent_conn.recv()
        return {
            "ok": resp.get("ok", False),
            "evidence": resp.get("evidence"),
            "error": resp.get("error"),
        }

    def verify(self, did: str, message: bytes, signature: bytes) -> bool:
        """模拟公开验签（子进程用公开参数验签，不返回私钥信息）。"""
        self._parent_conn.send({"op": "verify", "did": did,
                                "message": message, "signature": signature})
        return bool(self._parent_conn.recv().get("ok", False))

    def verify_attestation(self, evidence: dict) -> bool:
        """验证 AuthEvidence 的模拟证明（委托子进程，主进程无法获得证明密钥）。"""
        self._parent_conn.send({"op": "verify_attestation", "evidence": evidence})
        return bool(self._parent_conn.recv().get("ok", False))

    def stop(self):
        try:
            self._parent_conn.send("STOP")
            self._parent_conn.recv()
        except (EOFError, OSError):
            pass
        if self._proc.is_alive():
            self._proc.terminate()
            self._proc.join(timeout=5)

    def __enter__(self):
        return self

    def __exit__(self, *args):
        self.stop()
