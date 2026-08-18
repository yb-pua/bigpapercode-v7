"""
特征流量整形（方向二）：帧填充（固定档/随机档）+ 速率平滑（令牌桶）。

- 目标分布 = 均匀（包长档位化）；
- 冗余率 = (整形后流量 - 原始流量)/原始流量 ≤15%（开题承诺）。
- 熵/KL 量化：整形后包长/间隔分布熵提升、与均匀参考 KL 散度下降。
"""

import time
from typing import Callable, Dict, List, Optional, Tuple

import numpy as np

from .common import get_rng

# 固定档位（字节）：覆盖三型业务流原始包长 + 隧道开销
PAD_BINS = [256, 512, 768, 1024, 1448]


def next_bin(length: int, bins: List[int] = None) -> int:
    """向上取整到最近档位；超过最大档则用最大档（含截断告警由调用方处理）。"""
    bins = bins or PAD_BINS
    for b in bins:
        if length <= b:
            return b
    return bins[-1]


class TokenBucket:
    """令牌桶速率平滑：rate B/s，burst 容量。"""

    def __init__(self, rate: float, burst: float = 0.0,
                 now_fn: Optional[Callable[[], float]] = None):
        self.rate = rate
        self.capacity = burst if burst > 0 else rate
        self.tokens = self.capacity
        self.last_ts = (now_fn() if now_fn else time.time())
        self._now_fn = now_fn or time.time

    def _refill(self):
        now = self._now_fn()
        dt = now - self.last_ts
        if dt > 0:
            self.tokens = min(self.capacity, self.tokens + dt * self.rate)
            self.last_ts = now

    def consume(self, n_bytes: int) -> float:
        """尝试取 n 令牌；不足则返回等待秒数（阻塞语义由调用方实现）。"""
        self._refill()
        if self.tokens >= n_bytes:
            self.tokens -= n_bytes
            return 0.0
        need = n_bytes - self.tokens
        return need / self.rate


class Shaper:
    """整形器：帧填充 + 令牌桶速率平滑。"""

    def __init__(self, target_rate: float, mode: str = "fixed",
                 bins: Optional[List[int]] = None, seed: int = 20260817):
        self.mode = mode                       # "fixed" | "random"
        self.bins = bins or PAD_BINS
        self.bucket = TokenBucket(target_rate)
        self._rng = get_rng(seed)

    def shape_length(self, raw_len: int) -> int:
        """包长整形：固定档（uniform 目标）或随机档（[ceil, max] 均匀）。"""
        if self.mode == "random":
            lo = next_bin(raw_len, self.bins)
            hi = self.bins[-1]
            if lo >= hi:
                return lo
            return int(self._rng.randint(lo, hi + 1))
        return next_bin(raw_len, self.bins)

    def delay_for(self, n_bytes: int) -> float:
        """速率平滑：返回需等待秒数（令牌桶）。"""
        return self.bucket.consume(n_bytes)


def redundancy_rate(raw_total: float, shaped_total: float) -> float:
    """带宽冗余率 = (整形后 - 原始)/原始。"""
    if raw_total <= 0:
        return 0.0
    return (shaped_total - raw_total) / raw_total


def distribution_entropy(values: List[float], bins: int = 64) -> float:
    """分布熵 H = -Σ p_i·log2(p_i)（bit）。"""
    if not values:
        return 0.0
    hist, _ = np.histogram(values, bins=bins)
    p = hist / hist.sum()
    p = p[p > 0]
    return float(-(p * np.log2(p)).sum())


def kl_divergence(values: List[float], reference_bins: int = 64) -> float:
    """与均匀参考分布的 KL 散度（nat）：q_i = 1/N。"""
    if not values:
        return 0.0
    hist, _ = np.histogram(values, bins=reference_bins)
    p = hist / hist.sum()
    q = np.full_like(p, 1.0 / len(p))
    p = np.maximum(p, 1e-12)
    return float((p * np.log(p / q)).sum())


def packet_stats(payload_lens: List[int]) -> Dict[str, float]:
    """包长统计（熵 + 均值/方差），用于整形前后对比。"""
    if not payload_lens:
        return {"entropy": 0.0, "mean_bytes": 0.0, "std_bytes": 0.0,
                "n_packets": 0.0}
    arr = np.asarray(payload_lens, dtype=np.float64)
    return {"entropy": distribution_entropy(payload_lens),
            "mean_bytes": float(np.mean(arr)),
            "std_bytes": float(np.std(arr)),
            "n_packets": float(arr.size)}