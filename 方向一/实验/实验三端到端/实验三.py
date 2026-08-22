"""A3 端到端 Kerberos 认证实验（生物门控 TEE 签名 + 限次验证）。

流程：登记（TEE 内 Gen+派生私钥+签名）→ AS-REQ（TEE 生物门控签名+模拟证明
+AS 验签）→ TGT → TGS → ST → AP-REQ → 服务会话。
限次：连续 3 次异人失败 → TEE 内 blocked。
输出：
    结果/formal_v2_<run_id>/attempts.csv / circuit.csv / summary.csv / manifest.json
    敏感值（sigma/key_hash/BioKey/mask/私钥）不得进入 CSV/审计日志。
"""

import json
import sys
import time
from pathlib import Path

import numpy as np

sys.path.insert(0, str(Path(__file__).resolve().parent.parent.parent))
sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from core.audit_logger import AuditLogger
from core.common import rand_bytes, write_csv
from core.did import make_user_did
from core.fuzzy_extractor import FuzzyExtractor
from core.kerberos_enhanced import (AS, KerberosClient, KerberosRealm, MAX_SKEW,
                                    Service, TGS, _b64e, _pack)
from core.simulated_bio_tee import SimulatedBioTEE
from core.sm9_engine import SM9Engine
from exp_common import (cohort_persons, enroll_from_images, load_cache, log,
                        make_run_dir, quantize, split_enroll_probe,
                        write_manifest)
from data_config import (FORMAL_V2_CACHE_DIR, VOTE_PROBE_MIN_IMAGES,
                         VOTE_ENROLL_IMAGES)

RESULTS_DIR = Path(__file__).resolve().parent / "结果"
FIGURES_DIR = RESULTS_DIR / "figures"
AUDIT_PATH = RESULTS_DIR / "auth_audit.jsonl"

N_PERSONS = 30
SERVICE_ID = "svc_a@REALM"


class G1LocalAuthenticator:
    """G1 普通环境的本地认证器：登记检查 + 时间检查 + nonce 检查 + SM9 验签 → 签发 TGT。

    与 AS 的区别：认证走本地 SM9 签名（无 AuthEvidence / TEE 证明），
    复现「普通环境无 TEE 隔离」的诚实认证流程，避免绕过 AS 接口直接发 TGT。
    """

    def __init__(self, as_server, engine):
        self.as_server = as_server
        self.engine = engine
        self.used_nonces = {}

    def register(self, did, user_id, reg_signature, reg_ts, now=None):
        return self.as_server.register(did, user_id, reg_signature, reg_ts, now=now)

    def authenticate(self, did, nonce, ts, signature, now=None):
        now = now if now is not None else self.as_server.realm.clock.now()
        if did not in self.as_server.registrations:
            return {"ok": False, "error": "unknown_did"}
        if abs(now - ts) > MAX_SKEW:
            return {"ok": False, "error": "timestamp_out_of_window"}
        message = _pack({"did": did, "ts": ts, "nonce": _b64e(nonce)})
        nonce_key = f"{did}:{_b64e(nonce)}"
        if nonce_key in self.used_nonces and now - self.used_nonces[nonce_key] < MAX_SKEW:
            return {"ok": False, "error": "replay_detected"}
        if not self.engine.verify(did, message, signature):
            return {"ok": False, "error": "sm9_signature_invalid"}
        self.used_nonces[nonce_key] = now
        tgt = self.as_server._issue_ticket(did, "tgs@REALM", now,
                                           flags={"auth_method": "local"})
        return {"ok": True, "tgt": tgt}

# 敏感值标记（用于审计/CSV 泄漏扫描）
SECRET_MARKERS = ("key_hash", "bio_key", "sigma", "master_key",
                  "private_key", "sk_s", "sk_e")


def _count_lines(path: Path) -> int:
    try:
        return sum(1 for _ in path.open(encoding="utf-8"))
    except Exception:
        return 0


def _scan_secret(path: Path) -> bool:
    """返回 True 表示文件中检测到敏感标记（异常）。"""
    try:
        text = path.read_text(encoding="utf-8")
    except Exception:
        return False
    return any(m in text for m in SECRET_MARKERS)


def _as_clean(as_server) -> bool:
    """检查 AS registrations 不含敏感字段。"""
    for rec in as_server.registrations.values():
        if any(k in ("key_hash", "sigma", "bio_key", "mask", "sk",
                     "private_key") for k in rec):
            return False
    return True


def main():
    debug = "--debug" in sys.argv
    quick = "--quick" in sys.argv
    n_persons = 10 if quick else N_PERSONS
    RESULTS_DIR.mkdir(parents=True, exist_ok=True)
    FIGURES_DIR.mkdir(parents=True, exist_ok=True)
    out_dir = make_run_dir(RESULTS_DIR)
    audit_path = out_dir / "auth_audit.jsonl"
    fe = FuzzyExtractor()
    embs = load_cache(cache_dir=FORMAL_V2_CACHE_DIR)
    cohort = cohort_persons(embs, VOTE_PROBE_MIN_IMAGES)[:n_persons]
    log(f"persons: {len(cohort)}")

    bio_tee = SimulatedBioTEE()
    realm = KerberosRealm(audit_logger=AuditLogger(str(audit_path)))
    as_server = AS(realm, bio_tee)
    tgs_server = TGS(realm)
    realm.register_service(SERVICE_ID)
    svc = Service(realm, SERVICE_ID)

    rows_flow = []
    ok_count = 0
    for i, person in enumerate(cohort):
        user_id = f"user_{i:03d}"
        did = make_user_did(user_id)
        sp = split_enroll_probe(embs, person, enroll_n=VOTE_ENROLL_IMAGES)
        if sp is None:
            continue
        enroll_embs = sp["enroll_embs"]
        probe_emb = sp["probe_embs"][0]
        now = [1000.0 + i * 100]

        # 1) 登记：TEE 内 Gen + 派生私钥 + 对登记消息签名
        reg_ts = now[0]
        reg_msg = _pack({"user_id": user_id, "did": did, "ts": reg_ts})
        t0 = time.time()
        enroll_resp = bio_tee.enroll(did, enroll_embs, reg_msg)
        ok_reg = bool(enroll_resp["ok"]) and as_server.register(
            did, user_id, enroll_resp["registration_signature"], reg_ts,
            now=reg_ts)
        rows_flow.append({"person": person, "step": "enroll",
                          "ok": int(ok_reg), "seconds": time.time() - t0})

        # 2) AS-REQ：TEE 生物门控签名 + 模拟证明
        nonce = rand_bytes(16, f"as_nonce_{did}")
        as_message = _pack({"did": did, "ts": now[0], "nonce": _b64e(nonce)})
        t0 = time.time()
        auth_resp = bio_tee.authenticate_and_sign(did, probe_emb, as_message,
                                                  nonce, now[0])
        if bool(auth_resp["ok"]):
            as_resp = as_server.authenticate(
                did, nonce, now[0], auth_resp["evidence"], now=now[0])
            ok_as = bool(as_resp["ok"])
        else:
            ok_as = False
            as_resp = {}
        rows_flow.append({"person": person, "step": "as_req",
                          "ok": int(ok_as), "seconds": time.time() - t0})

        # 3) TGS → ST
        client = KerberosClient(did, bio_tee)
        ok_tgs = False
        if ok_as:
            client.store_tgt(as_resp["tgt"])
            t0 = time.time()
            tgs_req = client.build_tgs_req(SERVICE_ID, now[0])
            tgs_resp = tgs_server.grant_service_ticket(
                tgs_req["encrypted_tgt"], tgs_req["authenticator"],
                tgs_req["nonce"], now=now[0])
            ok_tgs = bool(tgs_resp["ok"])
            rows_flow.append({"person": person, "step": "tgs",
                              "ok": int(ok_tgs), "seconds": time.time() - t0})
        else:
            rows_flow.append({"person": person, "step": "tgs",
                              "ok": 0, "seconds": 0.0})

        # 4) AP-REQ → 服务会话
        ok_ap = False
        if ok_tgs:
            client.store_st(tgs_resp["st"])
            ap_req = client.build_ap_req(SERVICE_ID, now[0])
            t0 = time.time()
            ok_ap = bool(svc.verify_ap_req(ap_req, now=now[0]))
            rows_flow.append({"person": person, "step": "ap_req",
                              "ok": int(ok_ap), "seconds": time.time() - t0})
        else:
            rows_flow.append({"person": person, "step": "ap_req",
                              "ok": 0, "seconds": 0.0})

        ok_all = ok_reg and ok_as and ok_tgs and ok_ap
        ok_count += int(ok_all)
        log(f"A3: {person} ok_all={ok_all}")

    # ---------- 限次验证：连续 3 次异人失败 → blocked ----------
    rows_circuit = []
    lock_did = make_user_did("lockout_user")
    lock_sp = split_enroll_probe(embs, cohort[0], enroll_n=VOTE_ENROLL_IMAGES)
    lock_enroll = lock_sp["enroll_embs"]
    lock_probe = lock_sp["probe_embs"][0]
    other_person = cohort[1] if len(cohort) > 1 else cohort[0]
    other_sp = split_enroll_probe(embs, other_person, enroll_n=VOTE_ENROLL_IMAGES)
    other_probe = other_sp["probe_embs"][0]
    now = [5000.0]
    reg_msg = _pack({"user_id": "lockout_user", "did": lock_did, "ts": now[0]})
    lock_enroll_resp = bio_tee.enroll(lock_did, lock_enroll, reg_msg)
    as_server.register(lock_did, "lockout_user",
                       lock_enroll_resp["registration_signature"], now[0],
                       now=now[0])

    def auth_once(probe):
        nonce = rand_bytes(16, f"as_nonce_{lock_did}_{time.time_ns()}")
        msg = _pack({"did": lock_did, "ts": now[0], "nonce": _b64e(nonce)})
        return bio_tee.authenticate_and_sign(lock_did, probe, msg, nonce, now[0])

    for k in range(1, 4):
        r = auth_once(other_probe)
        rows_circuit.append({"scenario": "lockout", "seq": k,
                             "event": "impostor_failure",
                             "ok": int(r["ok"]), "error": r["error"]})
    r_blocked = auth_once(lock_probe)
    rows_circuit.append({"scenario": "lockout", "seq": 4,
                         "event": "blocked_after_3_failures",
                         "ok": int(r_blocked["ok"]), "error": r_blocked["error"]})
    blocked_ok = (not r_blocked["ok"]) and r_blocked["error"] == "blocked"

    # ---------- 架构对比：G1/G2/G3（诚实认证流程，同数据端到端） ----------
    arch_rows = []
    for arch in ("G1", "G2", "G3"):
        engine = SM9Engine()
        tee = SimulatedBioTEE(max_attempts=None if arch == "G2" else 3) \
            if arch != "G1" else None
        verifier = tee if tee else engine
        realm2 = KerberosRealm()
        as2 = AS(realm2, verifier)
        g1_auth = G1LocalAuthenticator(as2, engine) if arch == "G1" else None
        tgs2 = TGS(realm2)
        realm2.register_service(SERVICE_ID)
        svc2 = Service(realm2, SERVICE_ID)
        n_users = len(cohort)
        n_rep = n_sign = n_imp = n_tgt = n_e2e = 0
        setup_lat = []
        genuine_lat = []
        impostor_lat = []
        auth_req_bytes_list = []
        for i in range(n_users):
            person = cohort[i]
            other = cohort[(i + 1) % n_users]
            sp = split_enroll_probe(embs, person, enroll_n=VOTE_ENROLL_IMAGES)
            osp = split_enroll_probe(embs, other, enroll_n=VOTE_ENROLL_IMAGES)
            enroll_embs = sp["enroll_embs"]
            probe_emb = sp["probe_embs"][0]
            other_emb = osp["probe_embs"][0]
            did = make_user_did(f"{arch.lower()}_{i}")
            now = 1000.0 + i * 100

            # 登记（Gen + AS/TEE 登记）
            setup_t0 = time.time()
            if arch == "G1":
                W, mask, bio_key, sigma = enroll_from_images(enroll_embs, fe)
                reg_msg = _pack({"user_id": did, "did": did, "ts": now})
                g1_auth.register(did, did, engine.sign(did, reg_msg), now, now=now)
            else:
                reg_msg = _pack({"user_id": did, "did": did, "ts": now})
                enroll_resp = tee.enroll(did, enroll_embs, reg_msg)
                as2.register(did, did, enroll_resp["registration_signature"],
                             now, now=now)
            setup_time = (time.time() - setup_t0) * 1000

            # 同人诚实认证（Rep → 签名 → TGT → TGS → ST → AP）
            rep_ok = sign_ok = tgt_ok = st_ok = ap_ok = False
            tgt = None
            genuine_t0 = time.time()
            if arch == "G1":
                pb = quantize(probe_emb)[mask == 1]
                bio_key2 = fe.rep(pb, sigma, key_hash=fe.key_hash(bio_key))
                rep_ok = bio_key2 == bio_key
                if rep_ok:
                    nonce = rand_bytes(16, f"g1_{i}")
                    payload = _pack({"did": did, "ts": now, "nonce": _b64e(nonce)})
                    sig = engine.sign(did, payload)
                    auth_req_bytes_list.append(len(_pack({
                        "did": did, "ts": now, "nonce": _b64e(nonce),
                        "signature": _b64e(sig)})))
                    as_resp = g1_auth.authenticate(did, nonce, now, sig, now=now)
                    sign_ok = bool(as_resp["ok"])
                    tgt_ok = sign_ok
                    tgt = as_resp.get("tgt") if tgt_ok else None
            else:
                nonce = rand_bytes(16, f"{arch}_{i}")
                ctx = _pack({"did": did, "ts": now, "nonce": _b64e(nonce)})
                auth = tee.authenticate_and_sign(did, probe_emb, ctx, nonce, now)
                rep_ok = sign_ok = bool(auth["ok"])
                if auth["ok"]:
                    as_resp = as2.authenticate(did, nonce, now,
                                               auth["evidence"], now=now)
                    tgt_ok = bool(as_resp["ok"])
                    tgt = as_resp.get("tgt") if tgt_ok else None
                    auth_req_bytes_list.append(len(json.dumps(auth["evidence"])))
            # TGS → ST → AP
            if tgt_ok:
                client = KerberosClient(did, verifier)
                client.store_tgt(tgt)
                tgs_req = client.build_tgs_req(SERVICE_ID, now)
                tgs_resp = tgs2.grant_service_ticket(
                    tgs_req["encrypted_tgt"], tgs_req["authenticator"],
                    tgs_req["nonce"], now=now)
                st_ok = bool(tgs_resp["ok"])
                if st_ok:
                    client.store_st(tgs_resp["st"])
                    ap_req = client.build_ap_req(SERVICE_ID, now)
                    ap_ok = bool(svc2.verify_ap_req(ap_req, now=now)["ok"])
            genuine_time = (time.time() - genuine_t0) * 1000

            # 异人尝试
            imp_t0 = time.time()
            if arch == "G1":
                pb_imp = quantize(other_emb)[mask == 1]
                imp_ok = fe.rep(pb_imp, sigma,
                                key_hash=fe.key_hash(bio_key)) == bio_key
            else:
                imp_nonce = rand_bytes(16, f"{arch}_imp_{i}")
                imp_ctx = _pack({"did": did, "ts": now, "nonce": _b64e(imp_nonce)})
                imp_ok = bool(tee.authenticate_and_sign(
                    did, other_emb, imp_ctx, imp_nonce, now)["ok"])
            impostor_time = (time.time() - imp_t0) * 1000

            e2e_ok = rep_ok and sign_ok and tgt_ok and st_ok and ap_ok
            n_rep += int(rep_ok); n_sign += int(sign_ok); n_imp += int(imp_ok)
            n_tgt += int(tgt_ok); n_e2e += int(e2e_ok)
            setup_lat.append(setup_time)
            genuine_lat.append(genuine_time)
            impostor_lat.append(impostor_time)

        arch_rows.append({
            "group": arch, "n_users": n_users,
            "genuine_rep_success_rate": round(n_rep / n_users, 4),
            "genuine_signature_rate": round(n_sign / n_users, 4),
            "impostor_signature_rate": round(n_imp / n_users, 4),
            "tgt_success_rate": round(n_tgt / n_users, 4),
            "end_to_end_success_rate": round(n_e2e / n_users, 4),
            "setup_time_p50_ms": round(float(np.percentile(setup_lat, 50)), 2),
            "genuine_e2e_time_p50_ms": round(float(np.percentile(genuine_lat, 50)), 2),
            "genuine_e2e_time_p95_ms": round(float(np.percentile(genuine_lat, 95)), 2),
            "impostor_attempt_time_p50_ms": round(float(np.percentile(impostor_lat, 50)), 2),
            "auth_request_bytes_p50": round(float(np.percentile(auth_req_bytes_list, 50)), 0) if auth_req_bytes_list else 0,
        })
        if tee:
            tee.stop()
    write_csv(out_dir / "architecture.csv", arch_rows)

    write_csv(out_dir / "attempts.csv", rows_flow)
    write_csv(out_dir / "circuit.csv", rows_circuit)
    summary = [
        {"metric": "persons", "value": len(cohort)},
        {"metric": "flow_ok_ratio", "value": ok_count / len(cohort)},
        {"metric": "lockout_after_3_failures", "value": int(blocked_ok)},
        {"metric": "attestation_type", "value": "simulated-hmac"},
        {"metric": "auth_audit_entries", "value": _count_lines(audit_path)},
        {"metric": "secret_in_audit", "value": int(_scan_secret(audit_path))},
        {"metric": "as_registrations_clean", "value": int(_as_clean(as_server))},
    ]
    write_csv(out_dir / "summary.csv", summary)
    write_manifest(out_dir, FORMAL_V2_CACHE_DIR,
                   "reedsolo" if fe.helper_uses_reedsolo() else "simulated",
                   "enroll=5, probe=第6张独立, bio_tee=simulated-hmac")
    bio_tee.stop()
    log(f"A3 done -> {out_dir.relative_to(RESULTS_DIR)}")


if __name__ == "__main__":
    main()
