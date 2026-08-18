"""
稳定比特提取：多数投票（众数）+ 稳定性评分，阈值 0.8。

登记（Gen）：n 张图 → n 组 512 维嵌入 → Min-Max 归一化 → 逐维量化比特 →
    逐位多数投票（众数）→ 逐位稳定性评分（众数占比）→ 稳定位筛选（≥0.8）。
验证（Rep）：单张图 → 同 Min-Max 变换 → 取登记时选定的维度 → 得到稳定序列。

σ 中的 index_mask 仅记录维度位置（非特征值），保证 Rep 可复现同一稳定序列。
"""

from typing import Optional, Tuple

import numpy as np


def majority_vote(bit_matrix: np.ndarray) -> Tuple[np.ndarray, np.ndarray]:
    """多数投票：返回 (众数比特向量, 稳定性评分向量)。

    参数：
        bit_matrix: (n_samples, n_dims) 的 0/1 比特矩阵
    稳定性评分 = 众数占比 ∈ [0,1]。
    """
    bits = np.asarray(bit_matrix, dtype=np.uint8)
    if bits.ndim != 2:
        raise ValueError("bit_matrix must be 2D (n_samples, n_dims)")
    n = bits.shape[0]
    ones = bits.sum(axis=0)
    voted = (ones * 2 >= n).astype(np.uint8)
    stability = np.maximum(ones, n - ones) / float(n)
    return voted, stability


def select_stable(voted_bits: np.ndarray,
                  stability: np.ndarray,
                  threshold: float = 0.8,
                  num_bits: int = 256) -> Tuple[np.ndarray, np.ndarray]:
    """按稳定性阈值筛选稳定位，输出定长稳定序列。

    参数：
        voted_bits: 众数投票比特向量 (n_dims,)
        stability: 稳定性评分向量 (n_dims,)
        threshold: 稳定性阈值（默认 0.8）
        num_bits: 输出序列长度（默认 256 位）
    返回：
        (stable_sequence, index_mask)
        index_mask: (n_dims,) 0/1，1 表示被选中的维度（记录于 σ，供 Rep 复现）
    """
    voted_bits = np.asarray(voted_bits, dtype=np.uint8).ravel()
    stability = np.asarray(stability, dtype=np.float64).ravel()
    n_dims = voted_bits.size
    if n_dims < num_bits:
        raise ValueError(f"n_dims {n_dims} < num_bits {num_bits}")

    mask = np.zeros(n_dims, dtype=np.uint8)
    stable_idx = np.where(stability >= threshold)[0]
    selected = sorted(stable_idx.tolist())
    if len(selected) < num_bits:
        rest = [i for i in range(n_dims) if i not in selected]
        rest = sorted(rest, key=lambda i: (-stability[i], i))
        selected += rest[: num_bits - len(selected)]
    selected = selected[:num_bits]
    mask[selected] = 1
    sequence = voted_bits[selected]
    return sequence, mask


def bits_to_bytes(bits: np.ndarray) -> bytes:
    """比特序列（8 的倍数）→ 字节序列（MSB-first）。"""
    bits = np.asarray(bits, dtype=np.uint8).ravel()
    if bits.size % 8 != 0:
        raise ValueError("bits length must be a multiple of 8")
    out = bytearray()
    for i in range(0, bits.size, 8):
        byte = 0
        for j in range(8):
            byte = (byte << 1) | int(bits[i + j])
        out.append(byte)
    return bytes(out)


def bytes_to_bits(data: bytes, num_bits: Optional[int] = None) -> np.ndarray:
    """字节序列 → 比特序列（MSB-first）。"""
    bits = np.unpackbits(np.frombuffer(data, dtype=np.uint8))
    if num_bits is not None:
        bits = bits[:num_bits]
    return bits.astype(np.uint8)


def byte_error_count(bits_a: np.ndarray, bits_b: np.ndarray) -> int:
    """两个等长比特序列的字节级错误数（错位字节计数）。"""
    ba = bits_to_bytes(np.asarray(bits_a, dtype=np.uint8).ravel())
    bb = bits_to_bytes(np.asarray(bits_b, dtype=np.uint8).ravel())
    return sum(1 for x, y in zip(ba, bb) if x != y)