"""A5 攻击面与隐私度量实验（生物门控 TEE 版）。

攻击面（围绕「生物认证成功后才允许签名」与「敏感值不出 TEE」）：
    bio01 genuine_bio_sign          同人认证与签名成功
    bio02 impostor_bio_sign         异人人脸不能触发签名
    bio03 repeated_failure_lockout  连续 3 次失败后阻断
    bio04 sign_without_bio_denied   不存在绕过生物认证的签名接口
    bio05 private_key_export_denied 不存在私钥导出接口
    bio06 helper_export_denied      不存在 sigma/key_hash 导出接口
    bio07 normal_db_leak            AS 注册库不含 sigma/key_hash/BioKey/mask/私钥
    bio08 replay_nonce_rejected     相同 nonce 重放被拒绝
    bio09 audit_secret_scan         审计日志/CSV 不含敏感材料

隐私度量（度量 σ 性质，不输出 σ 明文）：
    p01 σ 熵 / p02 重登记不可链接 / p03 W 熵 / p04 σ 不含明文特征

输出：结果/formal_v2_<run_id>/attempts.csv / summary.csv / manifest.json
"""

import sys
import time
from pathlib import Path

import numpy as np

sys.path.insert(0, str(Path(__file__).resolve().parent.parent.parent))
sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from core.audit_logger import AuditLogger
from core.common import rand_bytes, write_csv
from core.did import make_user_did
from core.fuzzy_extractor import FuzzyExtractor, RS_N
from core.kerberos_enhanced import (AS, KerberosClient, KerberosRealm, Service,
                                    TGS, _b64e, _pack)
from core.simulated_bio_tee import SimulatedBioTEE
from core.sm9_engine import SM9Engine
from exp_common import (cohort_persons, enroll_from_images, load_cache, log,
                        make_run_dir, person_embs, quantize, similarity,
                        write_manifest)
from data_config import FORMAL_V2_CACHE_DIR, VOTE_PROBE_MIN_IMAGES

RESULTS_DIR = Path(__file__).resolve().parent / "结果"
SERVICE_ID = "svc_a@REALM"
N_ATTACKS = 20

SECRET_MARKERS = ("key_hash", "bio_key", "sigma", "master_key",
                  "private_key", "sk_s", "sk_e")


def _scan_text(text: str) -> bool:
    return any(m in text for m in SECRET_MARKERS)


def main():
    debug = "--debug" in sys.argv
    quick = "--quick" in sys.argv
    main_start = time.time()
    n_persons = 5 if quick else N_ATTACKS
    RESULTS_DIR.mkdir(parents=True, exist_ok=True)
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

    # ---------- 登记 victim ----------
    person = cohort[0]
    e = person_embs(embs, person, max_n=5)
    did = make_user_did("victim")
    now = [20000.0]
    reg_msg = _pack({"user_id": "victim", "did": did, "ts": now[0]})
    enroll_resp = bio_tee.enroll(did, e, reg_msg)
    assert enroll_resp["ok"]
    as_server.register(did, "victim", enroll_resp["registration_signature"],
                       now[0], now=now[0])

    probe_emb = person_embs(embs, person, max_n=6)[5]  # 第 6 张独立 probe
    other_emb = person_embs(embs, cohort[1], max_n=1)[0]

    rows = []

    def rec(name, attack_succeeded, detail):
        rows.append({"attack": name, "attack_succeeded": int(attack_succeeded),
                     "detail": detail,
                     "status": "vulnerable" if attack_succeeded else "blocked"})

    # bio01 同人认证与签名成功（正常用例，非攻击）
    nonce = rand_bytes(16, "bio01")
    msg = _pack({"did": did, "ts": now[0], "nonce": _b64e(nonce)})
    r = bio_tee.authenticate_and_sign(did, probe_emb, msg, nonce, now[0])
    genuine_ok = bool(r["ok"]) and r["evidence"] is not None
    rows.append({"attack": "bio01_genuine_bio_sign",
                 "attack_succeeded": 0,
                 "detail": "signature_ok" if genuine_ok else "failed",
                 "status": "success" if genuine_ok else "failed"})

    # bio02 异人人脸不能触发签名
    nonce = rand_bytes(16, "bio02")
    msg = _pack({"did": did, "ts": now[0], "nonce": _b64e(nonce)})
    r = bio_tee.authenticate_and_sign(did, other_emb, msg, nonce, now[0])
    rec("bio02_impostor_bio_sign", bool(r["ok"]), r["error"])

    # bio03 连续 3 次失败后阻断（用独立 DID 避免污染 bio02 的限次）
    lock_did = make_user_did("lockout")
    lock_msg = _pack({"user_id": "lockout", "did": lock_did, "ts": now[0]})
    lock_enroll_resp = bio_tee.enroll(lock_did, e, lock_msg)
    as_server.register(lock_did, "lockout",
                       lock_enroll_resp["registration_signature"],
                       now[0], now=now[0])

    def lock_auth(probe):
        n = rand_bytes(16, f"lock_{time.time_ns()}")
        m = _pack({"did": lock_did, "ts": now[0], "nonce": _b64e(n)})
        return bio_tee.authenticate_and_sign(lock_did, probe, m, n, now[0])

    for _ in range(3):
        lock_auth(other_emb)
    r_blocked = lock_auth(probe_emb)
    lockout_ok = (not r_blocked["ok"]) and r_blocked["error"] == "blocked"
    rec("bio03_repeated_failure_lockout", not lockout_ok, r_blocked["error"])

    # bio04 不存在绕过生物认证的签名接口
    has_bypass = (hasattr(bio_tee, "sign_without_biometric")
                  or hasattr(bio_tee, "sign_without_bio"))
    rec("bio04_sign_without_bio_denied", has_bypass, "absent" if not has_bypass else "present")

    # bio05 不存在私钥导出接口
    has_export = (hasattr(bio_tee, "export_private_key")
                  or hasattr(bio_tee, "derive_sk")
                  or hasattr(bio_tee, "get_private_key"))
    rec("bio05_private_key_export_denied", has_export, "absent" if not has_export else "present")

    # bio06 不存在 sigma/key_hash 导出接口
    has_helper = (hasattr(bio_tee, "get_sigma") or hasattr(bio_tee, "get_key_hash")
                  or hasattr(bio_tee, "get_mask") or hasattr(bio_tee, "get_bio_key"))
    rec("bio06_helper_export_denied", has_helper, "absent" if not has_helper else "present")

    # bio07 AS 注册库不含敏感值
    db_leak = any(k in ("key_hash", "sigma", "bio_key", "mask", "sk", "private_key")
                  for rec_dict in as_server.registrations.values() for k in rec_dict)
    rec("bio07_normal_db_leak", db_leak, "clean" if not db_leak else "leaked")

    # bio08 相同 nonce 重放被拒绝
    nonce = rand_bytes(16, "bio08")
    msg = _pack({"did": did, "ts": now[0], "nonce": _b64e(nonce)})
    auth = bio_tee.authenticate_and_sign(did, probe_emb, msg, nonce, now[0])
    r1 = as_server.authenticate(did, nonce, now[0], auth["evidence"], now=now[0])
    r2 = as_server.authenticate(did, nonce, now[0], auth["evidence"], now=now[0])
    replay_rejected = bool(r1["ok"]) and (not r2["ok"]) and r2["error"] == "replay_detected"
    rec("bio08_replay_nonce_rejected", not replay_rejected, r2.get("error", ""))

    # bio09 审计日志/CSV 不含敏感材料
    try:
        audit_text = audit_path.read_text(encoding="utf-8")
    except Exception:
        audit_text = ""
    audit_leak = _scan_text(audit_text)
    rec("bio09_audit_secret_scan", audit_leak, "clean" if not audit_leak else "leaked")

    # ---------- 候选集合攻击：G0/G1/G2/G3（多 victim × 多排列） ----------
    attack_rows = []
    all_persons = cohort_persons(embs, min_images=1)
    n_victims = 1 if quick else 20
    n_perm = 1 if quick else 5
    victim_persons = cohort[:n_victims]

    for vi, victim_person in enumerate(victim_persons):
        victim_enroll = person_embs(embs, victim_person, max_n=5)
        victim_images = person_embs(embs, victim_person, max_n=6)
        assert len(victim_images) >= 6, f"{victim_person} 不足 6 张图"
        victim_probe = victim_images[5]
        other_persons = [p for p in all_persons if p != victim_person]
        for candidate_count in (10, 50, 100):
            for perm in range(n_perm):
                rng_p = np.random.RandomState(20260817 + vi * 1000 + candidate_count + perm)
                selected = rng_p.choice(other_persons, size=candidate_count - 1,
                                        replace=False)
                cands = [victim_probe] + [person_embs(embs, p, max_n=1)[0] for p in selected]
                order = list(range(candidate_count))
                rng_p.shuffle(order)
                shuffled = [cands[o] for o in order]
                target_pos = order.index(0)

                for arch in ("G0", "G1", "G2", "G3"):
                    setup_t0 = time.time()
                    if arch == "G0":
                        ref = np.mean(victim_enroll, axis=0)
                    elif arch == "G1":
                        W, mask, bio_key, sigma = enroll_from_images(victim_enroll, fe)
                        kh = fe.key_hash(bio_key)
                    else:
                        tee_c = SimulatedBioTEE(max_attempts=None if arch == "G2" else 3)
                        gid = make_user_did(f"{arch.lower()}_{vi}_{candidate_count}_{perm}")
                        tee_c.enroll(gid, victim_enroll,
                                     _pack({"user_id": gid, "did": gid, "ts": now[0]}))
                    setup_time = (time.time() - setup_t0) * 1000

                    atk_t0 = time.time()
                    identified = False
                    false_accept = False
                    requests_sent = 0
                    biometric_evaluations = 0
                    blocked_requests = 0
                    signature_issued = False
                    if arch == "G0":
                        best, best_sim = -1, -1.0
                        for k, cand in enumerate(shuffled):
                            requests_sent += 1
                            biometric_evaluations += 1
                            s = similarity(ref, cand)
                            if s > best_sim:
                                best_sim, best = s, k
                        identified = (best == target_pos)
                        false_accept = (best != target_pos)
                    elif arch == "G1":
                        matched = False
                        for k, cand in enumerate(shuffled):
                            requests_sent += 1
                            biometric_evaluations += 1
                            pb = quantize(cand)[mask == 1]
                            out = fe.rep(pb, sigma, key_hash=kh)
                            if out == bio_key:
                                matched = True
                                identified = (k == target_pos)
                                false_accept = (k != target_pos)
                                break
                        signature_issued = matched
                    else:
                        for k, cand in enumerate(shuffled):
                            requests_sent += 1
                            n = rand_bytes(16, f"{arch}_{vi}_{candidate_count}_{perm}_{k}_{time.time_ns()}")
                            ctx = _pack({"did": gid, "ts": now[0], "nonce": _b64e(n)})
                            r = tee_c.authenticate_and_sign(gid, cand, ctx, n, now[0])
                            if r["error"] == "blocked":
                                blocked_requests += 1
                                break
                            biometric_evaluations += 1
                            if r["ok"]:
                                identified = (k == target_pos)
                                false_accept = (k != target_pos)
                                signature_issued = True
                                break
                        tee_c.stop()
                    attack_time = (time.time() - atk_t0) * 1000
                    attack_rows.append({
                        "group": arch, "attack": "candidate_scan",
                        "victim": victim_person,
                        "candidate_count": candidate_count,
                        "permutation": perm,
                        "target_position": target_pos,
                        "setup_time_ms": round(setup_time, 2),
                        "attack_time_ms": round(attack_time, 2),
                        "requests_sent": requests_sent,
                        "biometric_evaluations": biometric_evaluations,
                        "blocked_requests": blocked_requests,
                        "target_identified": int(identified),
                        "false_accept": int(false_accept),
                        "signature_issued": int(signature_issued),
                        "attempts_per_second": round(requests_sent / (attack_time / 1000), 2) if attack_time > 0 else 0.0,
                    })

    # G1 直接绕过 Rep 调用 SM9 签名（单独攻击）
    g1_engine = SM9Engine()
    d_sig = g1_engine.sign(did, b"direct_sign_bypass")
    direct_bypass_ok = g1_engine.verify(did, b"direct_sign_bypass", d_sig)
    attack_rows.append({
        "group": "G1", "attack": "direct_sign_bypass", "victim": "",
        "candidate_count": 0, "permutation": 0, "target_position": -1,
        "setup_time_ms": 0.0, "attack_time_ms": 0.0,
        "requests_sent": 0, "biometric_evaluations": 0, "blocked_requests": 0,
        "target_identified": 0, "false_accept": 0,
        "signature_issued": int(direct_bypass_ok),
        "attempts_per_second": 0.0,
    })

    scan_rows = [r for r in attack_rows if r["attack"] == "candidate_scan"]
    summary_arch = []
    for arch in ("G0", "G1", "G2", "G3"):
        for candidate_count in (10, 50, 100):
            grp = [r for r in scan_rows if r["group"] == arch
                   and r["candidate_count"] == candidate_count]
            if not grp:
                continue
            blocked_runs = sum(1 for r in grp if r["blocked_requests"] > 0)
            total_requests = sum(r["requests_sent"] for r in grp)
            total_blocked = sum(r["blocked_requests"] for r in grp)
            summary_arch.append({
                "group": arch,
                "candidate_count": candidate_count,
                "n_runs": len(grp),
                "target_identification_rate": round(sum(r["target_identified"] for r in grp) / len(grp), 4),
                "false_accept_rate": round(sum(r["false_accept"] for r in grp) / len(grp), 4),
                "blocked_run_rate": round(blocked_runs / len(grp), 4),
                "blocked_request_rate": round(total_blocked / total_requests, 4) if total_requests else 0.0,
                "signature_issuance_rate": round(sum(r["signature_issued"] for r in grp) / len(grp), 4),
                "mean_biometric_evaluations": round(sum(r["biometric_evaluations"] for r in grp) / len(grp), 2),
            })

    storage_rows = [
        {"group": "G0", "embedding_exposed": 1, "sigma_exposed": 0,
         "key_hash_exposed": 0, "offline_verifier_available": 1,
         "sensitive_bytes_exposed": 512 * 4},
        {"group": "G1", "embedding_exposed": 0, "sigma_exposed": 1,
         "key_hash_exposed": 1, "offline_verifier_available": 1,
         "sensitive_bytes_exposed": 255 + 64 + 32},
        {"group": "G2", "embedding_exposed": 0, "sigma_exposed": 0,
         "key_hash_exposed": 0, "offline_verifier_available": 0,
         "sensitive_bytes_exposed": 0},
        {"group": "G3", "embedding_exposed": 0, "sigma_exposed": 0,
         "key_hash_exposed": 0, "offline_verifier_available": 0,
         "sensitive_bytes_exposed": 0},
    ]
    write_csv(out_dir / "architecture.csv", attack_rows)
    write_csv(out_dir / "architecture_summary.csv", summary_arch)
    write_csv(out_dir / "storage_exposure.csv", storage_rows)

    write_csv(out_dir / "attempts.csv", rows)
    for r in rows:
        log(f"A5: {r['attack']:<28} -> {r['status']}")

    # ---------- 隐私度量（度量 σ 性质，不输出 σ 明文） ----------
    W, mask, bio_key, sigma = enroll_from_images(e, fe)
    W2, mask2, bio_key2, sigma2 = enroll_from_images(e, fe)
    priv = []

    counts = np.bincount(np.frombuffer(sigma["offset"], dtype=np.uint8),
                         minlength=256).astype(np.float64)
    p = counts / counts.sum()
    h = float(-(p[p > 0] * np.log2(p[p > 0])).sum())
    priv.append({"metric": "p01_sigma_entropy_bits_per_byte", "value": h})

    d = sum(a != b for a, b in zip(sigma["offset"], sigma2["offset"]))
    priv.append({"metric": "p02_rereg_sigma_diff_ratio", "value": d / RS_N})
    priv.append({"metric": "p02_rereg_key_stable", "value": int(bio_key == bio_key2)})

    from core.stable_bits import majority_vote
    bit_matrix = np.stack([quantize(x) for x in e])
    _, stab = majority_vote(bit_matrix)

    def _bit_entropy(pv):
        pv = np.clip(np.asarray(pv, dtype=np.float64), 1e-9, 1 - 1e-9)
        return -(pv * np.log2(pv) + (1 - pv) * np.log2(1 - pv))

    per_bit = np.where((stab > 0.0) & (stab < 1.0), _bit_entropy(stab), 0.0)
    w_entropy = float(per_bit[mask == 1].sum())
    priv.append({"metric": "p03_w_entropy_bits", "value": w_entropy})
    priv.append({"metric": "p04_w_plaintext_in_offset",
                 "value": int(W.tobytes() in sigma["offset"])})
    priv.append({"metric": "p04_bio_key_in_offset",
                 "value": int(bio_key in sigma["offset"])})

    attack_only = [r for r in rows if r["attack"] != "bio01_genuine_bio_sign"]
    summary = [
        {"metric": "attacks_total", "value": len(attack_only)},
        {"metric": "attacks_blocked", "value": sum(1 for r in attack_only if r["status"] == "blocked")},
        {"metric": "attacks_vulnerable", "value": sum(1 for r in attack_only if r["status"] == "vulnerable")},
        {"metric": "genuine_bio_sign_ok", "value": int(genuine_ok)},
        {"metric": "direct_sign_bypass", "value": int(direct_bypass_ok)},
        {"metric": "attestation_type", "value": "simulated-hmac"},
        {"metric": "audit_secret_scan", "value": int(audit_leak)},
    ]
    write_csv(out_dir / "summary.csv", summary)
    write_manifest(out_dir, FORMAL_V2_CACHE_DIR,
                   "reedsolo" if fe.helper_uses_reedsolo() else "simulated",
                   f"bio_tee=simulated-hmac, attacks={len(attack_only)}")
    # 追加实验运行参数（mode/样本量等）
    import json as _json
    _mf = _json.loads((out_dir / "manifest.json").read_text(encoding="utf-8"))
    _mf.update({
        "mode": "quick" if quick else "full",
        "n_victims": n_victims,
        "n_permutations": n_perm,
        "candidate_counts": [10, 50, 100],
        "sample_size": len(cohort),
        "start_time": time.strftime("%Y-%m-%d %H:%M:%S",
                                    time.localtime(main_start)),
    })
    (out_dir / "manifest.json").write_text(
        _json.dumps(_mf, ensure_ascii=False, indent=2), encoding="utf-8")
    bio_tee.stop()
    log(f"A5 done -> {out_dir.relative_to(RESULTS_DIR)}")


if __name__ == "__main__":
    main()
