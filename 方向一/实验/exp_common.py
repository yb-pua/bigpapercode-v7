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


def load_cache(backend: str = PRIMARY_BACKEND) -> Dict[str, np.ndarray]:
    """加载特征缓存（相对路径 → 512 维向量）。不存在则报错。"""
    embedder = FaceEmbedder(backend=backend, model_root=INSIGHTFACE_ROOT)
    cache = EmbeddingCache(str(CACHE_DIR), embedder)
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