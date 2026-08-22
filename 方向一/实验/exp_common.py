"""A1–A5 共享实验底座：缓存加载、队列构造、指标、CSV 落盘。"""

import sys
from pathlib import Path
from typing import Dict, List, Optional, Tuple

import numpy as np

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from core.common import get_rng, write_csv
from core.data_loader import LFWLoader
from core.face_embedder import EmbeddingCache, FaceEmbedder
from core.fuzzy_extractor import FuzzyExtractor
from core.preprocessing import quantize_to_bits
from core.stable_bits import byte_error_count, majority_vote, select_stable
from data_config import (CACHE_DIR, IMPOSTOR_PAIRS, INSIGHTFACE_ROOT, LFW_DIR,
                         PRIMARY_BACKEND)

BIT_THRESHOLD = 0.0


def load_cache(backend: str = PRIMARY_BACKEND,
               cache_dir=CACHE_DIR) -> Dict[str, np.ndarray]:
    """加载特征缓存（相对路径 → 512 维向量）。不存在则报错。"""
    embedder = FaceEmbedder(backend=backend, model_root=INSIGHTFACE_ROOT)
    cache = EmbeddingCache(str(cache_dir), embedder)
    if not cache.has_cache():
        raise SystemExit(
            f"特征缓存缺失：{cache._data_path}。"
            "请先运行 experiments/build_cache.py 构建缓存。")
    return cache.load()


def cohort_persons(embs: Dict[str, np.ndarray],
                   min_images: int) -> List[str]:
    """按缓存中人数筛选队列（缓存 key 为绝对路径，取父目录名作人名）。"""
    from collections import Counter
    counts = Counter(Path(p).parent.name for p in embs)
    return sorted(p for p, c in counts.items() if c >= min_images)


def person_embs(embs: Dict[str, np.ndarray], person: str,
                max_n: Optional[int] = None) -> List[np.ndarray]:
    """某人按文件名序的特征列表（key 为绝对路径，按父目录名匹配）。"""
    ps = sorted(p for p in embs if Path(p).parent.name == person)
    if max_n:
        ps = ps[:max_n]
    return [embs[p] for p in ps]


def quantize(emb: np.ndarray) -> np.ndarray:
    """单嵌入 → 512 比特（符号量化，阈值 0.0）。"""
    return quantize_to_bits(np.asarray(emb, dtype=np.float64), BIT_THRESHOLD)


def enroll_from_images(imgs: List[np.ndarray], fe: FuzzyExtractor
                       ) -> Tuple[np.ndarray, np.ndarray, bytes, Dict]:
    """n 张图登记：投票 → 稳定位 → Gen。返回 (W, mask, bio_key, σ)。"""
    bit_matrix = np.stack([quantize(e) for e in imgs])
    voted, stability = majority_vote(bit_matrix)
    W, mask = select_stable(voted, stability, threshold=0.8,
                            num_bits=fe.num_bits)
    bio_key, sigma = fe.gen(W, mask)
    return W, mask, bio_key, sigma


def genuine_attempt(enroll_imgs: List[np.ndarray], probe_emb: np.ndarray,
                    fe: FuzzyExtractor) -> Dict:
    """一次同人登记-探测：返回结果字典。"""
    W, mask, bio_key, sigma = enroll_from_images(enroll_imgs, fe)
    pb = quantize(probe_emb)[mask == 1]
    byte_errors = byte_error_count(W, pb)
    out = fe.rep(pb, sigma, key_hash=fe.key_hash(bio_key))
    return {
        "ok": out == bio_key,
        "byte_errors": byte_errors,
        "bio_key": bio_key,
        "sigma": sigma,
        "mask": mask,
    }


def impostor_attempt(enroll_imgs: List[np.ndarray], probe_emb: np.ndarray,
                     fe: FuzzyExtractor) -> Dict:
    """一次异人登记-探测：σ 来自登记人，探测为他人。"""
    W, mask, bio_key, sigma = enroll_from_images(enroll_imgs, fe)
    pb = quantize(probe_emb)[mask == 1]
    out = fe.rep(pb, sigma, key_hash=fe.key_hash(bio_key))
    return {
        "ok": out == bio_key,
        "byte_errors": byte_error_count(W, pb),
        "sigma": sigma,
    }


def similarity(a: np.ndarray, b: np.ndarray) -> float:
    a = a / (np.linalg.norm(a) + 1e-12)
    b = b / (np.linalg.norm(b) + 1e-12)
    return float(np.dot(a, b))


def build_impostor_pairs(embs: Dict[str, np.ndarray], persons: List[str],
                         n_pairs: int = IMPOSTOR_PAIRS,
                         seed: int = 20260817) -> List[Tuple[str, str]]:
    """异人配对（人名索引）。"""
    rng = get_rng(seed)
    pairs = []
    seen = set()
    guard = 0
    while len(pairs) < n_pairs and guard < n_pairs * 20:
        guard += 1
        i = int(rng.randint(0, len(persons)))
        j = int(rng.randint(0, len(persons)))
        if i == j:
            continue
        key = (min(i, j), max(i, j))
        if key in seen:
            continue
        seen.add(key)
        pairs.append((persons[i], persons[j]))
    return pairs


def summarize_attempts(rows: List[Dict]) -> Dict:
    """attempts 行汇总 → KRR/BER。rows: [{'ok':bool,'byte_errors':int}]"""
    n = len(rows)
    ok = sum(1 for r in rows if r["ok"])
    errs = [r["byte_errors"] for r in rows]
    return {
        "n_attempts": n,
        "krr": ok / n if n else 0.0,
        "ber_mean": float(np.mean(errs)) if errs else 0.0,
        "ber_p95": float(np.percentile(errs, 95)) if errs else 0.0,
        "ber_max": float(np.max(errs)) if errs else 0.0,
    }


def log(msg: str) -> None:
    print(f"[exp] {msg}", flush=True)


def split_enroll_probe(embs: Dict[str, np.ndarray], person: str,
                       enroll_n: int = 5) -> Optional[Dict]:
    """正式划分：前 enroll_n 张登记，第 enroll_n+1 张及以后为独立 probe。

    不足 enroll_n+1 张的人返回 None（调用方跳过），不允许回退到登记图像。
    返回的 paths 为缓存 key（绝对路径）；enroll/probe 集合强制互斥。
    """
    ps = sorted(p for p in embs if Path(p).parent.name == person)
    if len(ps) < enroll_n + 1:
        return None
    enroll_paths = ps[:enroll_n]
    probe_paths = ps[enroll_n:]
    assert set(enroll_paths).isdisjoint(probe_paths), \
        "enroll/probe 图像集合重叠（数据泄漏）"
    return {
        "enroll_paths": enroll_paths,
        "enroll_embs": [embs[p] for p in enroll_paths],
        "probe_paths": probe_paths,
        "probe_embs": [embs[p] for p in probe_paths],
    }


def inject_rs_symbol_errors(bits, theta: int, seed: int) -> np.ndarray:
    """在比特序列中注入 theta 个 RS 符号（字节）错误。

    将比特序列按 8 位分组为符号，无放回选择 theta 个符号位置，每个位置
    异或一个 1~255 非零字节掩码，保证 byte_error_count(original, perturbed)
    == theta（要求 0 <= theta <= 符号数）。
    """
    from core.stable_bits import byte_error_count
    bits = np.asarray(bits, dtype=np.uint8).ravel()
    if bits.size % 8 != 0:
        raise ValueError("bits length must be a multiple of 8")
    n_sym = bits.size // 8
    theta = int(theta)
    if theta < 0 or theta > n_sym:
        raise ValueError(f"theta {theta} out of range [0, {n_sym}]")
    rng = np.random.RandomState(seed)
    sym_idx = rng.choice(n_sym, size=theta, replace=False)
    out = bits.copy()
    for si in sym_idx:
        mask = int(rng.randint(1, 256))  # 1~255 非零字节掩码
        mask_bits = np.unpackbits(np.array([mask], dtype=np.uint8)).astype(np.uint8)
        out[si * 8:(si + 1) * 8] ^= mask_bits
    assert byte_error_count(bits, out) == theta, \
        f"inject_rs_symbol_errors 未达到 byte_error_count=={theta}"
    return out


def make_run_dir(results_dir, prefix: str = "formal_v2"):
    """创建隔离输出目录 结果/formal_v2_<run_id>/（微秒 run_id，禁止覆盖）。"""
    import time as _time
    run_id = (_time.strftime("%Y%m%d_%H%M%S")
              + f"_{_time.time_ns() % 1000000000:09d}")
    out = Path(results_dir) / f"{prefix}_{run_id}"
    out.mkdir(parents=True, exist_ok=False)
    return out


def write_manifest(out_dir, cache_dir, implementation: str,
                   split_policy: str, model: str = "insightface/buffalo_l",
                   seed: int = 20260817):
    """写 manifest.json（git_commit/seed/cache_sha256/环境等）。"""
    import hashlib
    import json
    import subprocess
    import time as _time

    def _git_commit() -> str:
        try:
            cwd = str(Path(__file__).resolve().parent.parent.parent)
            return subprocess.run(
                ["git", "rev-parse", "HEAD"], capture_output=True, text=True,
                cwd=cwd).stdout.strip()
        except Exception:
            return "unknown"

    npy = Path(cache_dir) / "embs_insightface.npy"
    sha = ""
    if npy.exists():
        h = hashlib.sha256()
        with open(npy, "rb") as f:
            for chunk in iter(lambda: f.read(1 << 20), b""):
                h.update(chunk)
        sha = h.hexdigest()

    manifest = {
        "git_commit": _git_commit(),
        "seed": seed,
        "cache_path": str(cache_dir),
        "cache_sha256": sha,
        "split_policy": split_policy,
        "model": model,
        "implementation": implementation,
        "start_time": _time.strftime("%Y-%m-%d %H:%M:%S"),
        "environment": "LFW funneled",
    }
    (Path(out_dir) / "manifest.json").write_text(
        json.dumps(manifest, ensure_ascii=False, indent=2), encoding="utf-8")