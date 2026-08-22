"""A1 生物特征密钥可恢复性实验（正式 V2：独立 probe 划分 + RS 符号错误注入）。

内容：
    A1-1 单图登记基线：登记第 1 张，探测第 6 张及以后（独立 probe）。
    A1-2 五图投票登记：登记前 5 张，探测第 6 张及以后（独立 probe）。
    A1-3 跨条件双样本：≥2 张人群登记第 1 张，探测第 2 张。
    A1-4 异人冒用：异人对，FAR。
    A1-5 阈值扫描：θ∈{0..t=32} 个 RS 符号（字节）错误强制注入，检验恢复能力。

输出（隔离，不覆盖旧 CSV）：
    结果/formal_v2_<run_id>/attempts.csv   —— 全部 attempt 行（统一 schema）
    结果/formal_v2_<run_id>/summary.csv    —— 汇总（micro/macro KRR、balanced/extended）
    结果/formal_v2_<run_id>/manifest.json  —— 元数据
"""

import hashlib
import json
import subprocess
import sys
import time
from pathlib import Path

import numpy as np

sys.path.insert(0, str(Path(__file__).resolve().parent.parent.parent))
sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from core.common import (compute_auc_mann_whitney, compute_eer, write_csv)
from core.fuzzy_extractor import FuzzyExtractor, RS_T
from core.stable_bits import byte_error_count
from exp_common import (build_impostor_pairs, cohort_persons,
                        enroll_from_images, genuine_attempt, impostor_attempt,
                        inject_rs_symbol_errors, load_cache, log, make_run_dir,
                        person_embs, quantize, similarity, split_enroll_probe)
from data_config import (FORMAL_V2_CACHE_DIR, IMPOSTOR_PAIRS,
                         VOTE_PROBE_MIN_IMAGES, VOTE_ENROLL_IMAGES)

RESULTS_DIR = Path(__file__).resolve().parent / "结果"
THETA_MAX = RS_T          # θ 符号距离上限 = t=32
SEED = 20260817
SCAN_N = 200              # 阈值扫描抽样人数


def _rel(p: str) -> str:
    return f"{Path(p).parent.name}/{Path(p).name}"


def _git_commit() -> str:
    try:
        cwd = str(Path(__file__).resolve().parent.parent.parent)
        return subprocess.run(
            ["git", "rev-parse", "HEAD"], capture_output=True, text=True,
            cwd=cwd).stdout.strip()
    except Exception:
        return "unknown"


def _cache_sha256() -> str:
    p = FORMAL_V2_CACHE_DIR / "embs_insightface.npy"
    if not p.exists():
        return ""
    h = hashlib.sha256()
    with open(p, "rb") as f:
        for chunk in iter(lambda: f.read(1 << 20), b""):
            h.update(chunk)
    return h.hexdigest()


def _krr_micro(rows) -> float:
    return sum(r["ok"] for r in rows) / len(rows) if rows else 0.0


def _krr_macro(rows) -> float:
    from collections import defaultdict
    per = defaultdict(list)
    for r in rows:
        per[r["person"]].append(r["ok"])
    return float(np.mean([sum(v) / len(v) for v in per.values()])) if per else 0.0


def main():
    quick = "--quick" in sys.argv
    scan_n = 50 if quick else SCAN_N

    out_dir = make_run_dir(RESULTS_DIR)
    fe = FuzzyExtractor()
    embs = load_cache(cache_dir=FORMAL_V2_CACHE_DIR)
    log(f"cache loaded: {len(embs)} images")

    # ---------- 队列 ----------
    cohort = cohort_persons(embs, VOTE_PROBE_MIN_IMAGES)   # ≥6 张
    log(f"cohort (>=6): {len(cohort)} persons")
    cross = [p for p in cohort_persons(embs, 2)
             if len(person_embs(embs, p)) < VOTE_PROBE_MIN_IMAGES]
    log(f"cross-condition (2-5): {len(cross)} persons")

    # ---------- A1-1/A1-2 投票增益（独立 probe） ----------
    rows_vote = []
    for person in cohort:
        sp = split_enroll_probe(embs, person, enroll_n=VOTE_ENROLL_IMAGES)
        if sp is None:
            continue
        enroll_embs = sp["enroll_embs"]
        probe_paths = sp["probe_paths"]
        probe_embs = sp["probe_embs"]
        for idx, (pp, pe) in enumerate(zip(probe_paths, probe_embs)):
            bucket = "first_probe" if idx == 0 else "additional_probe"
            r1 = genuine_attempt(enroll_embs[:1], pe, fe)   # single：第 1 张登记
            rows_vote.append({
                "experiment": "vote_gain", "person": person, "person_b": "",
                "config": "single", "enroll_count": 1,
                "probe_path": _rel(pp), "probe_index": idx,
                "probe_bucket": bucket, "in_balanced": int(idx == 0),
                "in_extended": 1, "ok": int(r1["ok"]),
                "byte_errors": r1["byte_errors"],
                "theta_requested": "", "theta_observed": "", "seed": ""})
            r5 = genuine_attempt(enroll_embs, pe, fe)        # vote5：前 5 张登记
            rows_vote.append({
                "experiment": "vote_gain", "person": person, "person_b": "",
                "config": "vote5", "enroll_count": len(enroll_embs),
                "probe_path": _rel(pp), "probe_index": idx,
                "probe_bucket": bucket, "in_balanced": int(idx == 0),
                "in_extended": 1, "ok": int(r5["ok"]),
                "byte_errors": r5["byte_errors"],
                "theta_requested": "", "theta_observed": "", "seed": ""})

    # ---------- A1-3 跨条件双样本 ----------
    rows_cross = []
    for person in cross:
        e = person_embs(embs, person, max_n=2)
        if len(e) < 2:
            continue
        r = genuine_attempt(e[:1], e[1], fe)
        rows_cross.append({
            "experiment": "cross_condition", "person": person, "person_b": "",
            "config": "", "enroll_count": 1, "probe_path": "",
            "probe_index": "", "probe_bucket": "", "in_balanced": "",
            "in_extended": "", "ok": int(r["ok"]),
            "byte_errors": r["byte_errors"],
            "theta_requested": "", "theta_observed": "", "seed": ""})

    # ---------- A1-4 异人冒用 ----------
    pairs = build_impostor_pairs(embs, cohort, IMPOSTOR_PAIRS)
    rows_imp = []
    for pa, pb in pairs:
        ea = person_embs(embs, pa, max_n=VOTE_ENROLL_IMAGES)
        eb = person_embs(embs, pb, max_n=1)
        r = impostor_attempt(ea, eb[0], fe)
        rows_imp.append({
            "experiment": "impostor", "person": pa, "person_b": pb,
            "config": "", "enroll_count": len(ea), "probe_path": "",
            "probe_index": "", "probe_bucket": "", "in_balanced": "",
            "in_extended": "", "ok": int(r["ok"]),
            "byte_errors": r["byte_errors"],
            "theta_requested": "", "theta_observed": "", "seed": ""})

    # ---------- A1-5 阈值扫描（独立 probe + RS 符号错误注入） ----------
    rows_scan = []
    for person in cohort[:scan_n]:
        sp = split_enroll_probe(embs, person, enroll_n=VOTE_ENROLL_IMAGES)
        if sp is None:
            continue
        W, mask, bio_key, sigma = enroll_from_images(sp["enroll_embs"], fe)
        # 从登记序列 W 注入精确 θ 个 RS 符号错误（byte_error_count(W,·)==θ）
        for theta in range(0, THETA_MAX + 1):
            seed = SEED + theta
            perturbed = inject_rs_symbol_errors(W, theta, seed) if theta > 0 else W
            theta_obs = byte_error_count(W, perturbed)
            out = fe.rep(perturbed, sigma, key_hash=fe.key_hash(bio_key))
            rows_scan.append({
                "experiment": "synthetic_rs_threshold_scan",
                "person": person, "person_b": "",
                "config": "", "enroll_count": VOTE_ENROLL_IMAGES,
                "probe_path": "", "probe_index": "",
                "probe_bucket": "", "in_balanced": "",
                "in_extended": "", "ok": int(out == bio_key),
                "byte_errors": theta_obs,
                "theta_requested": theta, "theta_observed": theta_obs,
                "seed": seed})

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

    # ---------- 汇总（micro/macro × balanced/extended） ----------
    def _rows(cfg, policy):
        rr = [r for r in rows_vote if r["config"] == cfg]
        if policy == "balanced":
            return [r for r in rr if r["in_balanced"]]
        return [r for r in rr if r["in_extended"]]

    summary = [
        {"metric": "cohort_persons", "value": len(cohort)},
        {"metric": "cross_persons", "value": len(cross)},
        {"metric": "cross_krr", "value": _krr_micro(rows_cross)},
        {"metric": "cross_ber_mean",
         "value": float(np.mean([r["byte_errors"] for r in rows_cross]))
         if rows_cross else 0.0},
        {"metric": "impostor_pairs", "value": len(rows_imp)},
        {"metric": "impostor_far",
         "value": sum(r["ok"] for r in rows_imp) / max(1, len(rows_imp))},
        {"metric": "context_eer", "value": eer},
        {"metric": "context_auc", "value": auc},
        {"metric": "rs_t", "value": RS_T},
        {"metric": "policy_max_correct", "value": 28},
    ]
    for cfg in ("single", "vote5"):
        for policy in ("balanced", "extended"):
            rr = _rows(cfg, policy)
            errs = [r["byte_errors"] for r in rr]
            summary += [
                {"metric": f"{cfg}_{policy}_krr_micro", "value": _krr_micro(rr)},
                {"metric": f"{cfg}_{policy}_krr_macro", "value": _krr_macro(rr)},
                {"metric": f"{cfg}_{policy}_ber_mean",
                 "value": float(np.mean(errs)) if errs else 0.0},
                {"metric": f"{cfg}_{policy}_ber_p95",
                 "value": float(np.percentile(errs, 95)) if errs else 0.0},
                {"metric": f"{cfg}_{policy}_n_attempts", "value": len(rr)},
            ]
    # 阈值扫描：每个 θ 的 KRR
    for theta in range(0, THETA_MAX + 1):
        sub = [r for r in rows_scan if r["theta_requested"] == theta]
        summary.append({"metric": f"theta{theta}_krr",
                        "value": _krr_micro(sub) if sub else 0.0})

    # ---------- 落盘 ----------
    attempts = rows_vote + rows_cross + rows_imp + rows_scan
    write_csv(out_dir / "attempts.csv", attempts)
    write_csv(out_dir / "summary.csv", summary)
    manifest = {
        "git_commit": _git_commit(),
        "seed": SEED,
        "cache_path": str(FORMAL_V2_CACHE_DIR),
        "cache_sha256": _cache_sha256(),
        "split_policy": "enroll=5, probe=6+ (balanced=仅第6张, extended=第6张及以后)",
        "model": "insightface/buffalo_l",
        "implementation": "reedsolo" if fe.helper_uses_reedsolo() else "simulated",
        "start_time": time.strftime("%Y-%m-%d %H:%M:%S"),
        "environment": "LFW funneled",
        "rs_t": RS_T,
        "policy_max_correct": 28,
        "theta_max": THETA_MAX,
    }
    (out_dir / "manifest.json").write_text(
        json.dumps(manifest, ensure_ascii=False, indent=2), encoding="utf-8")
    log(f"A1 done -> {out_dir.relative_to(RESULTS_DIR)}")


if __name__ == "__main__":
    main()
