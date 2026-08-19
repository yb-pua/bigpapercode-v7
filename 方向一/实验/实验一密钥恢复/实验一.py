"""A1 生物特征密钥可恢复性实验（对应专利"密钥撤销/可恢复"方向）。

内容：
    A1-1 单图登记基线：423 人（≥5 张）登记第 1 张，探测第 2~5 张（1692 次）。
    A1-2 五图投票登记：423 人登记 5 张（多数投票），探测 5 张（2115 次）。
    A1-3 跨条件双样本：1680 人（≥2 张）登记第 1 张，探测第 2 张（1257 次）。
    A1-4 异人冒用：5000 对异人，FAR。
    A1-5 阈值扫描：θ∈{0..40} 字节错强制注入（登记侧），纠正/拒绝/误纠统计。

输出：
    results/expA1_vote_gain.csv     —— 单图 vs 五图投票（KRR/BER）
    results/expA1_cross_condition.csv —— 跨条件双样本
    results/expA1_impostor.csv      —— 异人 FAR
    results/expA1_threshold_scan.csv —— θ 扫描
    results/expA1_summary.csv       —— 汇总（含余弦相似度 EER/AUC 上下文）
"""

import sys
from pathlib import Path

import numpy as np

sys.path.insert(0, str(Path(__file__).resolve().parent.parent.parent))
sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from core.common import (compute_auc_mann_whitney, compute_eer, csv_meta,
                         write_csv)
from core.fuzzy_extractor import FuzzyExtractor, RS_T
from exp_common import (build_impostor_pairs, cohort_persons,
                        enroll_from_images, genuine_attempt, impostor_attempt,
                        load_cache, log, person_embs, quantize, similarity,
                        summarize_attempts)
from data_config import (FIGURES_DIR, IMPOSTOR_PAIRS, RESULTS_DIR,
                         VOTE_COHORT_MIN_IMAGES, VOTE_ENROLL_IMAGES)
RESULTS_DIR = Path(__file__).resolve().parent / "结果"
FIGURES_DIR = RESULTS_DIR / "figures"
AUDIT_PATH = RESULTS_DIR / "auth_audit.jsonl"
TEE_AUDIT_PATH = RESULTS_DIR / "kdc_tee_audit.jsonl"

THETA_MAX = 40
THETA_STEP = 2


def main():
    debug = "--debug" in sys.argv
    quick = "--quick" in sys.argv
    scan_step = 5 if quick else THETA_STEP
    scan_n = 50 if quick else 200
    RESULTS_DIR.mkdir(parents=True, exist_ok=True)
    FIGURES_DIR.mkdir(parents=True, exist_ok=True)
    fe = FuzzyExtractor()
    embs = load_cache()
    log(f"cache loaded: {len(embs)} images")

    # ---------- 队列 ----------
    cohort = cohort_persons(embs, VOTE_COHORT_MIN_IMAGES)
    log(f"cohort (>=5): {len(cohort)} persons")
    cross = cohort_persons(embs, 2)
    cross = [p for p in cross if len(person_embs(embs, p)) < VOTE_ENROLL_IMAGES]
    log(f"cross-condition (2-4): {len(cross)} persons")

    # ---------- A1-1/A1-2 投票增益 ----------
    rows_vote = []
    for person in cohort:
        e = person_embs(embs, person, max_n=VOTE_ENROLL_IMAGES)
        for probe in e[1:]:  # 单图基线：登记第 1 张
            r = genuine_attempt(e[:1], probe, fe)
            rows_vote.append({"config": "single", "person": person,
                              "ok": int(r["ok"]),
                              "byte_errors": r["byte_errors"]})
        for probe in e:      # 五图投票：登记 5 张
            r = genuine_attempt(e, probe, fe)
            rows_vote.append({"config": "vote5", "person": person,
                              "ok": int(r["ok"]),
                              "byte_errors": r["byte_errors"]})
    s_single = summarize_attempts(
        [r for r in rows_vote if r["config"] == "single"])
    s_vote = summarize_attempts(
        [r for r in rows_vote if r["config"] == "vote5"])
    write_csv(RESULTS_DIR / "expA1_vote_gain.csv", rows_vote)
    log(f"A1-1/2: single KRR={s_single['krr']:.4f} BER={s_single['ber_mean']:.2f} | "
        f"vote5 KRR={s_vote['krr']:.4f} BER={s_vote['ber_mean']:.2f}")

    # ---------- A1-3 跨条件双样本 ----------
    rows_cross = []
    for person in cross:
        e = person_embs(embs, person, max_n=2)
        if len(e) < 2:
            continue
        r = genuine_attempt(e[:1], e[1], fe)
        rows_cross.append({"person": person, "ok": int(r["ok"]),
                           "byte_errors": r["byte_errors"]})
    s_cross = summarize_attempts(rows_cross)
    write_csv(RESULTS_DIR / "expA1_cross_condition.csv", rows_cross)
    log(f"A1-3: cross KRR={s_cross['krr']:.4f} BER={s_cross['ber_mean']:.2f}")

    # ---------- A1-4 异人冒用 ----------
    pairs = build_impostor_pairs(embs, cohort, IMPOSTOR_PAIRS)
    rows_imp = []
    for pa, pb in pairs:
        ea = person_embs(embs, pa, max_n=VOTE_ENROLL_IMAGES)
        eb = person_embs(embs, pb, max_n=1)
        r = impostor_attempt(ea, eb[0], fe)
        rows_imp.append({"person_a": pa, "person_b": pb,
                         "ok": int(r["ok"]), "byte_errors": r["byte_errors"]})
    n_ok = sum(r["ok"] for r in rows_imp)
    far = n_ok / len(rows_imp)
    write_csv(RESULTS_DIR / "expA1_impostor.csv", rows_imp)
    log(f"A1-4: impostor n={len(rows_imp)} FAR={far:.6f}")

    # ---------- A1-5 阈值扫描（单图登记，θ 字节强制翻转） ----------
    scan_persons = cohort[:scan_n]  # 200 人抽样（全量 423 人耗时相同，抽样以提速）
    rows_scan = []
    for person in scan_persons:
        e = person_embs(embs, person, max_n=2)
        W, mask, bio_key, sigma = enroll_from_images(e[:1], fe)
        for theta in range(0, THETA_MAX + 1, scan_step):
            pb = quantize(e[1])[mask == 1]
            if theta > 0:
                flip = np.random.RandomState(0).randint(
                    0, 2, min(theta * 8, pb.size))
                pb = pb.copy()
                pb[: flip.size] ^= flip.astype(np.uint8)
            out = fe.rep(pb, sigma, key_hash=fe.key_hash(bio_key))
            rows_scan.append({
                "theta": theta,
                "person": person,
                "ok": int(out == bio_key),
            })
    write_csv(RESULTS_DIR / "expA1_threshold_scan.csv", rows_scan)
    for theta in range(0, THETA_MAX + 1, scan_step):
        sub = [r for r in rows_scan if r["theta"] == theta]
        krr = sum(r["ok"] for r in sub) / len(sub)
        log(f"A1-5: theta={theta:2d} KRR={krr:.3f}")

    # ---------- 余弦相似度上下文（EER/AUC） ----------
    gen_sims, imp_sims = [], []
    for person in cohort[:scan_n]:
        e = person_embs(embs, person, max_n=VOTE_ENROLL_IMAGES)
        for i in range(len(e)):
            for j in range(i + 1, len(e)):
                gen_sims.append(similarity(e[i], e[j]))
    for pa, pb in pairs[:2000]:
        ea = person_embs(embs, pa, max_n=1)[0]
        eb = person_embs(embs, pb, max_n=1)[0]
        imp_sims.append(similarity(ea, eb))
    gen_sims = np.array(gen_sims)
    imp_sims = np.array(imp_sims)
    auc = compute_auc_mann_whitney(gen_sims, imp_sims)
    thresholds = np.linspace(gen_sims.min(), imp_sims.max(), 2001)
    far_arr = np.array([np.mean(imp_sims >= t) for t in thresholds])
    frr_arr = np.array([np.mean(gen_sims < t) for t in thresholds])
    eer = compute_eer(far_arr, frr_arr)
    log(f"context: EER={eer:.4f} AUC={auc:.4f}")

    # ---------- 汇总 ----------
    summary = [
        {"metric": "cohort_persons", "value": len(cohort)},
        {"metric": "cross_persons", "value": len(cross)},
        {"metric": "single_krr", "value": s_single["krr"]},
        {"metric": "single_ber_mean", "value": s_single["ber_mean"]},
        {"metric": "single_ber_p95", "value": s_single["ber_p95"]},
        {"metric": "vote5_krr", "value": s_vote["krr"]},
        {"metric": "vote5_ber_mean", "value": s_vote["ber_mean"]},
        {"metric": "vote5_ber_p95", "value": s_vote["ber_p95"]},
        {"metric": "cross_krr", "value": s_cross["krr"]},
        {"metric": "cross_ber_mean", "value": s_cross["ber_mean"]},
        {"metric": "impostor_pairs", "value": len(rows_imp)},
        {"metric": "impostor_far", "value": far},
        {"metric": "context_eer", "value": eer},
        {"metric": "context_auc", "value": auc},
        {"metric": "rs_t", "value": RS_T},
    ]
    write_csv(RESULTS_DIR / "expA1_summary.csv", summary)
    csv_meta(RESULTS_DIR / "expA1_summary.csv", {
        "seed": 20260817,
        "binarization": "sign-threshold-0",
        "stable_threshold": 0.8,
        "rs": f"RS({255},{191},t={RS_T})",
        "cohort_n": len(cohort),
        "cross_n": len(cross),
        "impostor_n": len(rows_imp),
        "theta_max": THETA_MAX,
    })
    log("A1 done -> results/expA1_*.csv")


if __name__ == "__main__":
    main()