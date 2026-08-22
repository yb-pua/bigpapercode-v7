"""A2 噪声鲁棒性实验：五类扰动 × 6 档强度 × 423 人投票登记。

对照：同一扰动下，生物密钥恢复率（KRR）与余弦相似度（相似度基线）双指标。
扰动图像分批池化提取（5 进程），避免串行 3 小时。
输出：
    results/expA2_noise_krr.csv —— 每 (noise_type, intensity) 的 KRR 与相似度
    results/expA2_summary.csv  —— 汇总（各类型最差档）
"""

import sys
import time
from pathlib import Path

import numpy as np

sys.path.insert(0, str(Path(__file__).resolve().parent.parent.parent))
sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from core.common import get_rng, csv_meta, write_csv
from core.face_embedder import FaceEmbedder
from core.fuzzy_extractor import FuzzyExtractor
from core.noise_injector import INTENSITY_GRID, NOISE_TYPES, noise_is_available
from exp_common import (cohort_persons, enroll_from_images, load_cache, log,
                        make_run_dir, quantize, similarity, split_enroll_probe,
                        write_manifest)
from data_config import (FIGURES_DIR, FORMAL_V2_CACHE_DIR, INSIGHTFACE_ROOT,
                         RESULTS_DIR, VOTE_PROBE_MIN_IMAGES,
                         VOTE_ENROLL_IMAGES)
RESULTS_DIR = Path(__file__).resolve().parent / "结果"
FIGURES_DIR = RESULTS_DIR / "figures"
AUDIT_PATH = RESULTS_DIR / "auth_audit.jsonl"
TEE_AUDIT_PATH = RESULTS_DIR / "kdc_tee_audit.jsonl"

PERTURB_SEED = 20260817
CHUNK_PERSONS = 5


def main():
    debug = "--debug" in sys.argv
    quick = "--quick" in sys.argv
    max_persons = None
    for _a in sys.argv[1:]:
        if _a.startswith("--max-persons="):
            max_persons = int(_a.split("=", 1)[1])
    chunk_step = 100 if quick else CHUNK_PERSONS
    if not noise_is_available():
        raise SystemExit("OpenCV 不可用，A2 无法执行")
    RESULTS_DIR.mkdir(parents=True, exist_ok=True)
    FIGURES_DIR.mkdir(parents=True, exist_ok=True)
    from core.data_loader import LFWLoader
    from core.noise_injector import apply_noise
    from data_config import LFW_DIR
    loader = LFWLoader(LFW_DIR)
    fe = FuzzyExtractor()
    embs = load_cache(cache_dir=FORMAL_V2_CACHE_DIR)
    cohort = cohort_persons(embs, VOTE_PROBE_MIN_IMAGES)
    if max_persons:
        cohort = cohort[:max_persons]
    log(f"cohort: {len(cohort)} persons")
    embedder = FaceEmbedder(backend="insightface", model_root=INSIGHTFACE_ROOT)

    rng = get_rng(PERTURB_SEED)
    rows = []
    t0_all = time.time()
    for c0 in range(0, len(cohort), chunk_step):
        chunk = cohort[c0:c0 + chunk_step]
        jobs = []   # (person, noise_type, intensity, seed, img)
        meta = []
        for person in chunk:
            sp = split_enroll_probe(embs, person, enroll_n=VOTE_ENROLL_IMAGES)
            if sp is None:
                continue
            enroll_embs = sp["enroll_embs"]
            probe_path = f"{person}/{Path(sp['probe_paths'][0]).name}"
            orig_emb = sp["probe_embs"][0]   # 第 6 张独立 probe 原始特征
            W, mask, bio_key, sigma = enroll_from_images(enroll_embs, fe)
            kh = fe.key_hash(bio_key)
            img = loader.load_image(probe_path)
            if img is None:
                raise SystemExit(f"image load failed: {probe_path}")
            for noise_type in NOISE_TYPES:
                for intensity in INTENSITY_GRID[noise_type]:
                    seed = int(rng.randint(0, 2 ** 31))
                    jobs.append(apply_noise(img, noise_type, intensity,
                                            seed=seed))
                    meta.append((person, noise_type, intensity, orig_emb,
                                 probe_path, mask, bio_key, sigma, kh))
        emb_list = embedder.extract_batch_from_arrays(jobs, workers=5)
        for (person, noise_type, intensity, orig_emb, probe_path, mask,
             bio_key, sigma, kh), emb in zip(meta, emb_list):
            if emb is None:
                rows.append({
                    "person": person, "noise_type": noise_type,
                    "intensity": intensity, "ok": 0,
                    "similarity": float("nan"), "extract_failed": 1,
                    "probe_path": probe_path})
                continue
            pb = quantize(emb)[mask == 1]
            out = fe.rep(pb, sigma, key_hash=kh)
            rows.append({
                "person": person, "noise_type": noise_type,
                "intensity": intensity, "ok": int(out == bio_key),
                "similarity": similarity(orig_emb, emb),
                "extract_failed": 0,
                "probe_path": probe_path})
        log(f"A2: chunk {c0}-{c0 + len(chunk)} done "
            f"({len(rows)} rows, {time.time() - t0_all:.0f}s)")
    out_dir = make_run_dir(RESULTS_DIR)
    write_csv(out_dir / "attempts.csv", rows)

    summary = []
    for noise_type in NOISE_TYPES:
        sub = [r for r in rows if r["noise_type"] == noise_type]
        krr = sum(r["ok"] for r in sub) / max(1, len(sub))
        sims = [r["similarity"] for r in sub
                if r["similarity"] == r["similarity"]]
        worst = 1.0
        for i in INTENSITY_GRID[noise_type]:
            s = [r for r in sub if r["intensity"] == i]
            if s:
                worst = min(worst, sum(r["ok"] for r in s) / len(s))
        summary.append({
            "noise_type": noise_type,
            "n_attempts": len(sub),
            "krr_overall": krr,
            "sim_mean": float(np.mean(sims)) if sims else float("nan"),
            "krr_worst": worst,
        })
    write_csv(out_dir / "summary.csv", summary)
    write_manifest(out_dir, FORMAL_V2_CACHE_DIR,
                   "reedsolo" if fe.helper_uses_reedsolo() else "simulated",
                   "enroll=5, probe=第6张独立")
    log(f"A2 done -> {out_dir.relative_to(RESULTS_DIR)}")


if __name__ == "__main__":
    main()