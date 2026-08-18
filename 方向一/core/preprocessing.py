"""预处理：Min-Max 归一化到 [0,1]（逐特征维度，跨样本统计）。"""

from typing import Optional, Tuple

import numpy as np

from .common import get_rng


def minmax_normalize(embeddings: np.ndarray,
                     minima: Optional[np.ndarray] = None,
                     maxima: Optional[np.ndarray] = None,
                     eps: float = 1e-12) -> Tuple[np.ndarray, np.ndarray, np.ndarray]:
    """Min-Max 归一化到 [0,1]。

    参数：
        embeddings: (n, dim) 或 (dim,) 特征矩阵
        minima/maxima: 可传入登记时统计的极值（验证侧复用同一变换）
    返回：
        (归一化结果, minima, maxima)
    """
    arr = np.asarray(embeddings, dtype=np.float64)
    if arr.ndim == 1:
        arr = arr[None, :]
    if minima is None or maxima is None:
        minima = arr.min(axis=0)
        maxima = arr.max(axis=0)
    span = (maxima - minima) + eps
    out = (arr - minima) / span
    out = np.clip(out, 0.0, 1.0)
    if np.asarray(embeddings).ndim == 1:
        return out[0], minima, maxima
    return out, minima, maxima


def quantize_to_bits(normalized: np.ndarray, threshold: float = 0.5) -> np.ndarray:
    """按阈值量化单维为比特（用于稳定比特提取的候选位）。"""
    return (np.asarray(normalized) >= threshold).astype(np.uint8)


def simulate_embeddings(n_samples: int, dim: int, per_person: int = 1,
                        seed: Optional[int] = None) -> np.ndarray:
    """模拟嵌入（insightface/dlib 均不可用时）：按身份分组、带噪声互相关。"""
    rng = get_rng(seed)
    n_persons = n_samples // per_person
    centroids = rng.randn(n_persons, dim).astype(np.float32)
    centroids /= np.linalg.norm(centroids, axis=1, keepdims=True) + 1e-12
    out = np.empty((n_samples, dim), dtype=np.float32)
    for i in range(n_samples):
        person = i // per_person
        noise = rng.randn(dim).astype(np.float32) * 0.15
        vec = centroids[person] + noise
        vec /= np.linalg.norm(vec) + 1e-12
        out[i] = vec
    return out