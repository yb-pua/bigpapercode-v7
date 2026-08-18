"""core 单元测试（验收项：RS 自测 / 熔断 / 30min / 预留接口）。"""

import os
import sys
import tempfile
from pathlib import Path

import numpy as np
import pytest

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from core.common import (compute_auc_mann_whitney, compute_eer, hmac_sm3,
                         pbkdf2_sm3, rand_bytes, sm3, sm4_cbc_decrypt,
                         sm4_cbc_encrypt)
from core.circuit_breaker import CircuitBreaker
from core.did import DIDRegistry, make_device_did, make_user_did
from core.fuzzy_extractor import FuzzyExtractor, RS_K, RS_N, rs_encode
from core.kerberos_enhanced import (AS, KerberosClient, KerberosRealm,
                                    Service, TGS, MAX_SKEW, TICKET_TTL)
from core.kdc_tee import SimulatedTeeKgc
from core.noise_injector import apply_noise
from core.sm9_engine import SM9Engine
from core.stable_bits import (bits_to_bytes, byte_error_count,
                              bytes_to_bits, majority_vote, select_stable)

SEED = 20260817


# ---------------------------------------------------------------------------
# 1. SM3 / SM4
# ---------------------------------------------------------------------------
class TestCrypto:
    def test_sm3_standard_vector(self):
        assert sm3(b"abc").hex() == \
            "66c7f0f462eeedd9d1f2d46bdc10e4e24167c4875cf2f7a2297da02b8f4ba8e0"

    def test_hmac_sm3(self):
        assert len(hmac_sm3(b"key", b"msg")) == 32

    def test_pbkdf2_sm3(self):
        assert len(pbkdf2_sm3(b"pw", b"salt")) == 32

    def test_sm4_roundtrip(self):
        key = rand_bytes(16, "k")
        pt = b"ticket payload " * 3
        ct = sm4_cbc_encrypt(pt, key)
        assert sm4_cbc_decrypt(ct, key) == pt

    def test_rand_bytes_deterministic(self):
        import core.common as cc
        cc._rand_counter = 0
        first = [rand_bytes(8, "a") for _ in range(3)]
        cc._rand_counter = 0
        second = [rand_bytes(8, "a") for _ in range(3)]
        assert first == second
        assert first[0] != first[1]


# ---------------------------------------------------------------------------
# 2. RS 自测（验收 3）：≤32 字节错 100% 恢复；>32 失败或被 key_hash 拦截
# ---------------------------------------------------------------------------
class TestFuzzyExtractorRS:
    def _setup(self):
        fe = FuzzyExtractor()
        stable = np.random.RandomState(1).randint(0, 2, 256).astype(np.uint8)
        mask = np.zeros(512, dtype=np.uint8)
        mask[:256] = 1
        key, sigma = fe.gen(stable, mask)
        return fe, stable, key, sigma

    def test_leq32_byte_errors_recovered(self):
        fe, stable, key, sigma = self._setup()
        kh = fe.key_hash(key)
        for k in range(0, 33):
            pos = np.random.RandomState(100 + k).choice(RS_N, k, replace=False)
            payload = key + bytes(RS_K - 32)
            c = bytearray(rs_encode(payload))
            for p in pos:
                c[p] ^= 0xFF
            from core.stable_bits import bits_to_bytes
            w_ext = bits_to_bytes(stable) + bytes(RS_N - 32)
            sig = dict(sigma)
            sig["offset"] = bytes(a ^ b for a, b in zip(c, w_ext))
            assert fe.rep(stable, sig, kh) == key, f"failed at {k} errors"

    def test_gt32_byte_errors_rejected(self):
        fe, stable, key, sigma = self._setup()
        kh = fe.key_hash(key)
        rejected = 0
        for trial in range(30):
            k = np.random.RandomState(5000 + trial).randint(33, 65)
            pos = np.random.RandomState(6000 + trial).choice(RS_N, k, replace=False)
            payload = key + bytes(RS_K - 32)
            c = bytearray(rs_encode(payload))
            for p in pos:
                c[p] ^= 0xFF
            w_ext = bits_to_bytes(stable) + bytes(RS_N - 32)
            sig = dict(sigma)
            sig["offset"] = bytes(a ^ b for a, b in zip(c, w_ext))
            if fe.rep(stable, sig, kh) is None:
                rejected += 1
        assert rejected == 30

    def test_sigma_no_plaintext(self):
        fe, stable, key, sigma = self._setup()
        assert stable.tobytes() not in sigma["offset"]
        assert key not in sigma["offset"]

    def test_key_hash_intercepts_miscorrection(self):
        fe, stable, key, sigma = self._setup()
        bits2 = stable.copy()
        for j in range(32):
            bits2[j * 8:(j + 1) * 8] ^= 1
        wrong_hash = sm3(b"x" * 32)
        assert fe.rep(bits2, sigma, wrong_hash) is None


# ---------------------------------------------------------------------------
# 3. 稳定比特
# ---------------------------------------------------------------------------
class TestStableBits:
    def test_majority_vote_and_stability(self):
        mat = np.array([
            [1, 1, 0, 0],
            [1, 1, 0, 1],
            [1, 0, 0, 0],
        ], dtype=np.uint8)
        voted, stability = majority_vote(mat)
        assert voted.tolist() == [1, 1, 0, 0]
        assert np.allclose(stability, [1.0, 2 / 3, 1.0, 2 / 3])

    def test_select_stable_threshold(self):
        voted = np.random.RandomState(2).randint(0, 2, 512).astype(np.uint8)
        stability = np.random.RandomState(3).rand(512)
        stability[:300] = 1.0
        seq, mask = select_stable(voted, stability, threshold=0.8, num_bits=256)
        assert seq.size == 256
        assert mask.sum() == 256
        assert np.array_equal(seq, voted[mask.astype(bool)])

    def test_bits_bytes_roundtrip(self):
        bits = np.random.RandomState(4).randint(0, 2, 256).astype(np.uint8)
        assert np.array_equal(bytes_to_bits(bits_to_bytes(bits), 256), bits)

    def test_byte_error_count(self):
        a = np.zeros(256, dtype=np.uint8)
        b = a.copy()
        b[0:8] = 1
        assert byte_error_count(a, b) == 1


# ---------------------------------------------------------------------------
# 4. SM9 引擎 + 预留接口（验收 6）
# ---------------------------------------------------------------------------
class TestSM9Engine:
    def setup_method(self):
        self.engine = SM9Engine()
        self.alice = make_user_did("alice")
        self.bob = make_user_did("bob")

    def test_sign_verify(self):
        msg = b"as_req_body"
        sig = self.engine.sign(self.alice, msg)
        assert self.engine.verify(self.alice, msg, sig)
        assert not self.engine.verify(self.alice, msg + b"x", sig)

    def test_verify_chain_order(self):
        m1 = b"step1"
        m2 = b"step2_" + sm3(m1)
        m3 = b"step3_" + sm3(m2)
        entries = [
            (self.alice, m1, self.engine.sign(self.alice, m1)),
            (self.bob, m2, self.engine.sign(self.bob, m2)),
            (self.alice, m3, self.engine.sign(self.alice, m3)),
        ]
        assert self.engine.verify_chain(entries)
        tampered = b"tampered_" + sm3(b"unrelated")
        bad = entries[:2] + [(self.bob, tampered,
                              self.engine.sign(self.bob, tampered))]
        assert not self.engine.verify_chain(bad)

    def test_key_exchange_equal_keys(self):
        state, r_init = self.engine.key_exchange_initiator(self.alice, self.bob)
        r_resp, key_b = self.engine.key_exchange_responder(self.bob, self.alice, r_init)
        key_a = self.engine.key_exchange_initiator_finish(state, r_resp)
        assert key_a == key_b
        assert len(key_a) == 32

    def test_proxy_sign_verify(self):
        msg = b"proxy_message"
        p_sig = self.engine.proxy_sign(self.bob, self.alice, msg)
        assert self.engine.proxy_verify(self.bob, msg, p_sig)
        assert not self.engine.proxy_verify(self.bob, b"tampered", p_sig)

    def test_did_format_and_collision_retry(self):
        reg = DIDRegistry()
        did_a = reg.register("user_a")
        assert did_a.startswith("didsm9:user_a:")
        assert reg.register("user_a") == did_a
        assert reg.lookup(did_a) == "user_a"
        d = make_user_did("dup", 3)
        assert d.startswith("didsm9:dup:")


# ---------------------------------------------------------------------------
# 5. KGC 模拟 TEE（验收：独立进程 + 主密钥不进日志 + 派生审计）
# ---------------------------------------------------------------------------
class TestKgcTee:
    def test_derive_and_audit(self):
        with tempfile.TemporaryDirectory() as td:
            audit = str(Path(td) / "audit.jsonl")
            tee = SimulatedTeeKgc(audit)
            try:
                did = make_user_did("tee_user")
                sk_s, sk_e, mpk = tee.derive_sk(did)
                assert len(sk_s) > 0 and len(sk_e) > 0
                assert tee.master_key_in_log()
                entries = tee.audit_entries()
                assert len(entries) == 1
                assert entries[0]["action"] == "derive_sk"
                assert entries[0]["did"] == did
                assert entries[0]["msk_in_log"] is False
                text = Path(audit).read_text(encoding="utf-8")
                assert "master_key" not in text
            finally:
                tee.stop()


# ---------------------------------------------------------------------------
# 6. Kerberos 增强：30min 窗口（验收 5）、claims_checker（验收 6）
# ---------------------------------------------------------------------------
class TestKerberosEnhanced:
    def _realm_and_flow(self, now_fn=None):
        import tempfile
        td = tempfile.mkdtemp()
        realm = KerberosRealm(audit_logger=None, now_fn=now_fn)
        engine = SM9Engine()
        as_server = AS(realm, engine)
        tgs_server = TGS(realm)
        service_id = "svc_a@REALM"
        realm.register_service(service_id)
        service = Service(realm, service_id)
        return realm, engine, as_server, tgs_server, service, service_id

    def _register_and_authenticate(self, realm, engine, as_server, tgs_server,
                                   service, service_id, now):
        did = make_user_did("carol")
        fe = FuzzyExtractor()
        stable = np.random.RandomState(7).randint(0, 2, 256).astype(np.uint8)
        mask = np.zeros(512, dtype=np.uint8)
        mask[:256] = 1
        bio_key, sigma = fe.gen(stable, mask)
        reg_ts = now
        import json as _json
        reg_msg = _json.dumps({"user_id": "carol", "did": did, "ts": reg_ts},
                              sort_keys=True).encode("utf-8")
        reg_sig = engine.sign(did, reg_msg)
        assert as_server.register(did, "carol", fe.key_hash(bio_key), reg_sig, reg_ts, now=now)

        client = KerberosClient(did, bio_key, engine)
        as_req = client.build_as_req(now)
        resp = as_server.authenticate(
            did, bio_key, as_req["nonce"], as_req["ts"],
            as_req["signature"], now=now)
        assert resp["ok"], resp
        client.store_tgt(resp["tgt"])
        tgs_req = client.build_tgs_req(service_id, now)
        tgs_resp = tgs_server.grant_service_ticket(
            tgs_req["encrypted_tgt"], tgs_req["authenticator"],
            tgs_req["nonce"], now=now)
        assert tgs_resp["ok"], tgs_resp
        st = tgs_resp["st"]
        assert "ticket_id" in st
        client.store_st(st)
        ap_req = client.build_ap_req(service_id, now)
        ver = service.verify_ticket(ap_req["encrypted_st"], service_id, now=now)
        assert ver["ok"], ver
        return client, fe, stable, bio_key, sigma

    def test_happy_flow_and_ticket_id(self):
        now_fn = lambda: 1000.0
        realm, engine, as_server, tgs_server, service, service_id = \
            self._realm_and_flow(now_fn)
        client, fe, stable, bio_key, sigma = self._register_and_authenticate(
            realm, engine, as_server, tgs_server, service, service_id, now_fn())
        assert client.tgt is not None and client.tgt["ticket_id"]
        assert len(client.ticket_ids()) == 2

    def test_30min_window_rejection(self):
        now_fn = lambda: 1000.0
        realm, engine, as_server, tgs_server, service, service_id = \
            self._realm_and_flow(now_fn)
        did = make_user_did("dave")
        fe = FuzzyExtractor()
        stable = np.random.RandomState(8).randint(0, 2, 256).astype(np.uint8)
        mask = np.zeros(512, dtype=np.uint8)
        mask[:256] = 1
        bio_key, sigma = fe.gen(stable, mask)
        reg_ts = 1000.0
        import json as _json
        reg_msg = _json.dumps({"user_id": "dave", "did": did, "ts": reg_ts},
                              sort_keys=True).encode("utf-8")
        reg_sig = engine.sign(did, reg_msg)
        assert as_server.register(did, "dave", fe.key_hash(bio_key), reg_sig, reg_ts, now=1000.0)
        client = KerberosClient(did, bio_key, engine)
        as_req = client.build_as_req(1000.0)
        resp = as_server.authenticate(
            did, bio_key, as_req["nonce"], as_req["ts"],
            as_req["signature"], now=1000.0)
        assert resp["ok"]
        client.store_tgt(resp["tgt"])
        # 超 30min：TGT 过期拒绝
        tgs_req = client.build_tgs_req(service_id, 1000.0 + TICKET_TTL + 1)
        tgs_resp = tgs_server.grant_service_ticket(
            tgs_req["encrypted_tgt"], tgs_req["authenticator"],
            tgs_req["nonce"], now=1000.0 + TICKET_TTL + 1)
        assert not tgs_resp["ok"]
        assert tgs_resp["error"] == "tgt_expired"
        # AS-REQ 时间戳超窗拒绝
        as_req2 = client.build_as_req(1000.0)
        resp2 = as_server.authenticate(
            did, bio_key, as_req2["nonce"], 1000.0 - MAX_SKEW - 1,
            as_req2["signature"], now=1000.0)
        assert not resp2["ok"]
        assert resp2["error"] == "timestamp_out_of_window"

    def test_verify_ticket_claims_checker_called(self):
        now_fn = lambda: 2000.0
        realm, engine, as_server, tgs_server, service, service_id = \
            self._realm_and_flow(now_fn)
        client, fe, stable, bio_key, sigma = self._register_and_authenticate(
            realm, engine, as_server, tgs_server, service, service_id, now_fn())
        ap_req = client.build_ap_req(service_id, now_fn())
        calls = []
        def checker(claims):
            calls.append(claims)
            return True
        ver = service.verify_ticket(ap_req["encrypted_st"], service_id,
                                    claims_checker=checker, now=now_fn())
        assert ver["ok"] and len(calls) == 1
        assert calls[0]["ticket_id"] == client.service_tickets[list(client.service_tickets)[0]]["ticket_id"]
        def reject(claims):
            return False
        ver2 = service.verify_ticket(ap_req["encrypted_st"], service_id,
                                     claims_checker=reject, now=now_fn())
        assert not ver2["ok"] and ver2["error"] == "claims_rejected"

    def test_tampered_ticket_rejected(self):
        now_fn = lambda: 3000.0
        realm, engine, as_server, tgs_server, service, service_id = \
            self._realm_and_flow(now_fn)
        client, fe, stable, bio_key, sigma = self._register_and_authenticate(
            realm, engine, as_server, tgs_server, service, service_id, now_fn())
        ap_req = client.build_ap_req(service_id, now_fn())
        import base64
        raw = bytearray(base64.b64decode(ap_req["encrypted_st"]))
        raw[10] ^= 0xFF
        ver = service.verify_ticket(base64.b64encode(bytes(raw)).decode(),
                                    service_id, now=now_fn())
        assert not ver["ok"]


# ---------------------------------------------------------------------------
# 7. 熔断（验收 4）：3 次失败 → is_blocked → 删票据 → L1 → L2
# ---------------------------------------------------------------------------
class TestCircuitBreaker:
    def test_breaker_l1_l2(self):
        deleted = []
        l1_ok, l2_ok = [True], [False]
        cb = CircuitBreaker(
            principal="alice",
            ticket_cleanup=lambda p: deleted.append(p),
            l1_attempt=lambda: l1_ok[0],
            l2_attempt=lambda: l2_ok[0],
        )
        assert not cb.record_failure()
        assert not cb.record_failure()
        assert cb.record_failure()          # 第 3 次触发熔断
        assert cb.is_blocked()
        assert deleted == ["alice"]
        # L1 恢复成功 → 解除，bio_key/DID 不变由上层断言（本单测验证状态机）
        assert cb.recover_l1()
        assert not cb.is_blocked()
        assert cb.failure_count() == 0
        # 再次熔断后 L1 失败 → L2
        cb.record_failure()
        cb.record_failure()
        cb.record_failure()
        assert cb.is_blocked()
        l1_ok[0] = False
        assert not cb.recover_l1()
        assert cb.is_blocked()
        l2_ok[0] = True
        assert cb.recover_l2()
        assert not cb.is_blocked()


# ---------------------------------------------------------------------------
# 8. 噪声扰动 / 指标
# ---------------------------------------------------------------------------
class TestNoiseAndMetrics:
    def test_noise_types(self):
        img = np.random.RandomState(9).randint(0, 255, (64, 64, 3)).astype(np.uint8)
        for nt in ["gaussian", "brightness", "rotation", "blur", "occlusion"]:
            out = apply_noise(img, nt, 0.3, seed=5)
            assert out.shape == img.shape

    def test_metrics(self):
        g = np.array([1, 2, 3])
        i = np.array([10, 11, 12])
        assert compute_auc_mann_whitney(g, i) == 1.0
        assert compute_eer([0.1, 0.5, 0.9], [0.9, 0.5, 0.1]) == pytest.approx(0.5, abs=1e-6)