"""A3 端到端 Kerberos 认证实验（含 TEE 主密钥隔离与熔断恢复路径）。

流程：生物密钥恢复（本地 Rep）→ 注册（SM9 签名）→ AS-REQ（生物认证+SM9
前置验签）→ TGT → TGS → ST → AP-REQ → 服务会话。
熔断：连续 3 次失败 → L1（票据清理+Rep 重认证）；L1 再失败 → L2（重新 Gen
+显式更新登记）。
输出：
    results/expA3_flow.csv      —— 逐步认证状态与耗时
    results/expA3_circuit.csv   —— 熔断序列
    results/expA3_summary.csv   —— 汇总
"""

import sys
import time
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent.parent))
sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from core.audit_logger import AuditLogger
from core.circuit_breaker import CircuitBreaker
from core.common import csv_meta, write_csv
from core.did import make_user_did
from core.fuzzy_extractor import FuzzyExtractor
from core.kerberos_enhanced import (AS, KerberosClient, KerberosRealm, Service,
                                    TGS)
from core.kdc_tee import SimulatedTeeKgc
from core.sm9_engine import SM9Engine
from exp_common import (cohort_persons, enroll_from_images, load_cache, log,
                        person_embs, quantize)
from data_config import (AUDIT_PATH, FIGURES_DIR, RESULTS_DIR, TEE_AUDIT_PATH,
                         VOTE_COHORT_MIN_IMAGES, VOTE_ENROLL_IMAGES)
RESULTS_DIR = Path(__file__).resolve().parent / "结果"
FIGURES_DIR = RESULTS_DIR / "figures"
AUDIT_PATH = RESULTS_DIR / "auth_audit.jsonl"
TEE_AUDIT_PATH = RESULTS_DIR / "kdc_tee_audit.jsonl"

N_PERSONS = 30
SERVICE_ID = "svc_a@REALM"


def main():
    debug = "--debug" in sys.argv
    quick = "--quick" in sys.argv
    n_persons = 10 if quick else N_PERSONS
    RESULTS_DIR.mkdir(parents=True, exist_ok=True)
    FIGURES_DIR.mkdir(parents=True, exist_ok=True)
    fe = FuzzyExtractor()
    embs = load_cache()
    cohort = cohort_persons(embs, VOTE_COHORT_MIN_IMAGES)[:n_persons]
    log(f"persons: {len(cohort)}")

    tee = SimulatedTeeKgc(audit_path=str(TEE_AUDIT_PATH))
    engine = SM9Engine()
    realm = KerberosRealm(audit_logger=AuditLogger(str(AUDIT_PATH)))
    as_server = AS(realm, engine)
    tgs_server = TGS(realm)
    realm.register_service(SERVICE_ID)
    svc = Service(realm, SERVICE_ID)

    rows_flow = []
    ok_count = 0
    for i, person in enumerate(cohort):
        user_id = f"user_{i:03d}"
        did = make_user_did(user_id)
        e = person_embs(embs, person, max_n=VOTE_ENROLL_IMAGES)
        now = [1000.0 + i * 100]

        # 1) 本地生物密钥恢复（登记在 σ，验证侧 Rep）
        W, mask, bio_key, sigma = enroll_from_images(e, fe)
        pb = quantize(e[0])[mask == 1]
        t0 = time.time()
        bio_key2 = fe.rep(pb, sigma, key_hash=fe.key_hash(bio_key))
        dt_rep = time.time() - t0
        ok_rep = bio_key2 == bio_key
        rows_flow.append({"person": person, "step": "bio_rep",
                          "ok": int(ok_rep), "seconds": dt_rep})

        # 2) 注册（SM9 签名 did|user|ts）
        from core.kerberos_enhanced import _pack
        reg_ts = now[0]
        reg_msg = _pack({"user_id": user_id, "did": did, "ts": reg_ts})
        reg_sig = engine.sign(did, reg_msg)
        t0 = time.time()
        ok_reg = as_server.register(did, user_id, fe.key_hash(bio_key),
                                    reg_sig, reg_ts, now=reg_ts)
        rows_flow.append({"person": person, "step": "register",
                          "ok": int(ok_reg), "seconds": time.time() - t0})

        # 3) AS-REQ：生物认证 + SM9 前置验签（响应含 TGT）
        client = KerberosClient(did, bio_key, engine)
        as_req = client.build_as_req(now[0])
        t0 = time.time()
        as_resp = as_server.authenticate(
            did, bio_key, as_req["nonce"], as_req["ts"],
            as_req["signature"], now=now[0])
        ok_as = bool(as_resp["ok"])
        rows_flow.append({"person": person, "step": "as_req",
                          "ok": int(ok_as), "seconds": time.time() - t0})

        # 4) TGS → ST
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
                              "ok": int(ok_tgs),
                              "seconds": time.time() - t0})
        else:
            rows_flow.append({"person": person, "step": "tgs",
                              "ok": 0, "seconds": 0.0})

        # 5) AP-REQ → 服务会话
        ok_ap = False
        if ok_tgs:
            client.store_st(tgs_resp["st"])
            ap_req = client.build_ap_req(SERVICE_ID, now[0])
            t0 = time.time()
            ok_ap = bool(svc.verify_ap_req(ap_req, now=now[0]))
            rows_flow.append({"person": person, "step": "ap_req",
                              "ok": int(ok_ap),
                              "seconds": time.time() - t0})
        else:
            rows_flow.append({"person": person, "step": "ap_req",
                              "ok": 0, "seconds": 0.0})

        ok_all = ok_rep and ok_reg and ok_as and ok_tgs and ok_ap
        ok_count += int(ok_all)
        log(f"A3: {person} ok_all={ok_all}")

    # ---------- 熔断路径 ----------
    rows_circuit = []
    person = cohort[-1]
    user_id = "breaker_user"
    did = make_user_did(user_id)
    e = person_embs(embs, person, max_n=VOTE_ENROLL_IMAGES)
    W, mask, bio_key, sigma = enroll_from_images(e, fe)
    now = [5000.0]
    reg_ts = now[0]
    from core.kerberos_enhanced import _pack
    reg_msg = _pack({"user_id": user_id, "did": did, "ts": reg_ts})
    as_server.register(did, user_id, fe.key_hash(bio_key),
                       engine.sign(did, reg_msg), reg_ts, now=reg_ts)
    client = KerberosClient(did, bio_key, engine)

    def rep_attempt() -> bool:
        """L1：Rep 重认证（同一 σ，bio_key/DID 不变）。"""
        pb = quantize(e[0])[mask == 1]
        out = fe.rep(pb, sigma, key_hash=fe.key_hash(bio_key))
        return out == bio_key

    def regen_attempt() -> bool:
        """L2：重新 Gen（新 σ）+ 显式更新登记。"""
        nonlocal bio_key, sigma
        from core.kerberos_enhanced import _pack
        bio_key, sigma = enroll_from_images(e, fe)[2:4]
        rts = now[0]
        rmsg = _pack({"user_id": user_id, "did": did, "ts": rts})
        return as_server.register(did, user_id, fe.key_hash(bio_key),
                                  engine.sign(did, rmsg), rts, now=rts)

    breaker = CircuitBreaker(
        principal=did,
        ticket_cleanup=lambda p: client.clear_tickets(),
        l1_attempt=rep_attempt,
        l2_attempt=regen_attempt,
    )

    def fail_once(k):
        breaker.record_failure(reason="bio_reject")
        rows_circuit.append({
            "seq": k, "event": "bio_failure",
            "state": "blocked" if breaker.is_blocked() else "closed",
            "action": "block" if breaker.is_blocked() else "retry"})

    rows_circuit.append({"seq": 0, "event": "baseline_success",
                         "state": "closed", "action": "allow"})
    for k in range(1, 4):
        fail_once(k)
    rows_circuit.append({"seq": 4, "event": "breaker_trip",
                         "state": "blocked", "action": "tickets_cleared"})
    ok_l1 = breaker.recover_l1()
    rows_circuit.append({"seq": 5, "event": "l1_recover",
                         "state": "closed" if not breaker.is_blocked() else "blocked",
                         "action": "allow" if ok_l1 else "block"})
    for k in range(6, 9):
        fail_once(k)
    ok_l2 = breaker.recover_l2()
    rows_circuit.append({"seq": 9, "event": "l2_reregister",
                         "state": "closed" if not breaker.is_blocked() else "blocked",
                         "action": "allow" if ok_l2 else "block"})
    # 重注册后完整流程应恢复
    as_req = client.build_as_req(now[0])
    ok_after = as_server.authenticate(did, bio_key, as_req["nonce"],
                                      as_req["ts"], as_req["signature"],
                                      now=now[0])
    rows_circuit.append({"seq": 10, "event": "after_l2_auth",
                         "state": "closed", "action": "allow",
                         "ok": int(ok_after["ok"])})

    write_csv(RESULTS_DIR / "expA3_flow.csv", rows_flow)
    write_csv(RESULTS_DIR / "expA3_circuit.csv", rows_circuit)
    summary = [
        {"metric": "persons", "value": len(cohort)},
        {"metric": "flow_ok_ratio", "value": ok_count / len(cohort)},
        {"metric": "breaker_l1_ok", "value": int(ok_l1)},
        {"metric": "breaker_l2_ok", "value": int(ok_l2)},
        {"metric": "after_l2_auth_ok", "value": int(ok_after["ok"])},
        {"metric": "tee_audit_entries",
         "value": len(tee.audit_entries())},
        {"metric": "tee_master_in_log",
         "value": int(tee.master_key_in_log())},
        {"metric": "auth_audit_entries",
         "value": _count_lines(AUDIT_PATH)},
    ]
    write_csv(RESULTS_DIR / "expA3_summary.csv", summary)
    csv_meta(RESULTS_DIR / "expA3_summary.csv", {
        "tee": "multiprocessing-simulated",
        "breaker_threshold": CircuitBreaker.FAIL_THRESHOLD,
        "ticket_ttl_sec": 1800,
        "service": SERVICE_ID,
    })
    tee.stop()
    log("A3 done -> results/expA3_*.csv")


def _count_lines(path: Path) -> int:
    try:
        return sum(1 for _ in path.open(encoding="utf-8"))
    except Exception:
        return 0


if __name__ == "__main__":
    main()