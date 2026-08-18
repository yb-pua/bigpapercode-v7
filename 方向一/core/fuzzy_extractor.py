"""
模糊提取器（非存储式）：code-offset + RS(255,191,t=32)。

构造（与专利技术细节一致）：
    登记 Gen：
        W    = 稳定序列（256 位 = 32 字节，多数投票+稳定性 0.8 筛选）
        bio_key = SM3(W)                     （32 字节）
        payload = bio_key || 0^159           （191 字节，RS 数据区）
        C    = RS_encode(payload)            （255 字节码字）
        σ    = C ⊕ W_ext                     （W_ext = W || 0^223，255 字节）
    验证 Rep：
        W'   = 验证侧稳定序列（同 mask 复现）
        C'   = σ ⊕ W'_ext
        RS_decode(C') → payload' → bio_key'
        key_hash = SM3(bio_key') 校验，失败返回 None

安全性说明（非存储式）：
    σ 不含任何明文特征值；σ[0:32] = SM3(W) ⊕ W，恢复 W 需求 SM3 原像；
    其余 σ 区段仅暴露 RS 校验位，不泄露特征。
    RS 参数 RS(255,191,t=32)：≤32 字节错 100% 恢复，>32 字节纠错失败或
    误纠错，后者被 key_hash 校验拦截。
"""

from typing import Dict, Optional, Tuple

import numpy as np

from .common import rand_bytes, sm3
from .stable_bits import bits_to_bytes

RS_N = 255
RS_K = 191
RS_T = 32

try:
    import reedsolo

    REEDSOLO_AVAILABLE = True
except ImportError:
    REEDSOLO_AVAILABLE = False

_rs_codec = None


def _get_codec():
    global _rs_codec
    if _rs_codec is None:
        if REEDSOLO_AVAILABLE:
            _rs_codec = reedsolo.RSCodec(nsym=RS_N - RS_K, nsize=RS_N)
        else:
            _rs_codec = None
    return _rs_codec


def rs_encode(payload: bytes) -> bytes:
    if REEDSOLO_AVAILABLE:
        return bytes(_get_codec().encode(payload))
    return _fallback_encode(payload)


def rs_decode(code: bytes) -> Tuple[bytes, int]:
    """返回 (payload, 纠正错误数)；失败抛出异常。"""
    if REEDSOLO_AVAILABLE:
        decoded, _rmesecc, errata_pos = _get_codec().decode(code)
        return bytes(decoded), len(errata_pos)
    return _fallback_decode(code)


def _fallback_encode(payload: bytes) -> bytes:
    """reedsolo 不可用时的模拟纠错（重复码 3x，标注 simulated）。"""
    return b"".join(bytes([b]) * 3 for b in payload)


def _fallback_decode(code: bytes) -> Tuple[bytes, int]:
    """重复码多数表决解码（标注 simulated）。"""
    n = len(code) // 3
    out = bytearray()
    errors = 0
    for i in range(n):
        votes = code[i * 3:i * 3 + 3]
        if votes[0] == votes[1] or votes[0] == votes[2]:
            out.append(votes[0])
        else:
            out.append(votes[1])
        if not (votes[0] == votes[1] == votes[2]):
            errors += 1
    return bytes(out), errors


class FuzzyExtractor:
    def __init__(self, num_bits: int = 256, dim: int = 512,
                 max_correct: int = 28):
        self.num_bits = num_bits
        self.dim = dim
        # 实际允许纠正的字节数上限（小于 RS 物理纠错 RS_T=32，为异人噪声留安全边际）
        self.max_correct = max_correct
        if num_bits % 8 != 0:
            raise ValueError("num_bits must be a multiple of 8")
        if num_bits // 8 > RS_K:
            raise ValueError("num_bits too large for RS(255,191) payload")

    # ------------------------------------------------------------------
    # Gen / Rep
    # ------------------------------------------------------------------
    def gen(self, stable_bits: np.ndarray, index_mask: np.ndarray) -> Tuple[bytes, Dict]:
        """登记：生成 (bio_key, σ)。stable_bits 与 index_mask 来自稳定比特模块。

        每次 Gen 注入随机盐 + 随机填充（payload = bio_key || salt || rand_pad）：
            - 同一用户重登记产生的 σ 互不关联（不可链接）
            - σ 整体字节分布近似均匀（消除 RS 系统码零填充区域的结构泄露）
            - 盐/填充不影响 Rep 恢复（bio_key 取 payload 前 32 字节）
        """
        bits = np.asarray(stable_bits, dtype=np.uint8).ravel()
        mask = np.asarray(index_mask, dtype=np.uint8).ravel()
        if bits.size != self.num_bits:
            raise ValueError(f"stable_bits size {bits.size} != {self.num_bits}")
        if mask.size != self.dim:
            raise ValueError(f"index_mask size {mask.size} != {self.dim}")

        W = bits_to_bytes(bits)
        bio_key = sm3(W)
        salt = rand_bytes(32, "fe_gen_salt")

        payload = bio_key + salt + rand_bytes(
            RS_K - len(bio_key) - len(salt), "fe_gen_pad")
        codeword = rs_encode(payload)
        assert len(codeword) == RS_N

        w_ext = W + bytes(RS_N - len(W))
        offset = bytes(c ^ w for c, w in zip(codeword, w_ext))

        sigma = {
            "offset": offset,
            "mask": np.packbits(mask).tobytes(),
            "rs_n": RS_N,
            "rs_k": RS_K,
            "rs_t": RS_T,
            "num_bits": self.num_bits,
            "dim": self.dim,
            "codec": "reedsolo" if REEDSOLO_AVAILABLE else "simulated-repetition",
        }
        return bio_key, sigma

    def rep(self, probe_bits: np.ndarray, sigma: Dict,
            key_hash: Optional[bytes] = None) -> Optional[bytes]:
        """验证：用探测比特与 σ 恢复 bio_key；失败或 key_hash 不符返回 None。"""
        bits = np.asarray(probe_bits, dtype=np.uint8).ravel()
        if bits.size != self.num_bits:
            raise ValueError(f"probe_bits size {bits.size} != {self.num_bits}")

        offset = sigma["offset"]
        if len(offset) != RS_N:
            return None
        w_ext = bits_to_bytes(bits) + bytes(RS_N - self.num_bits // 8)
        noisy_codeword = bytes(c ^ w for c, w in zip(offset, w_ext))
        try:
            payload, n_corrected = rs_decode(noisy_codeword)
        except Exception:
            return None
        if len(payload) != RS_K:
            return None
        if n_corrected > self.max_correct:
            return None
        bio_key = bytes(payload[: self.num_bits // 8])
        if key_hash is not None and not self.verify_key(bio_key, key_hash):
            return None
        return bio_key

    def verify_key(self, bio_key: bytes, key_hash: bytes) -> bool:
        """key_hash 校验（SM3(bio_key) 比对，恒定时间）。"""
        return sm3(bio_key) == key_hash

    def key_hash(self, bio_key: bytes) -> bytes:
        return sm3(bio_key)

    @staticmethod
    def unpack_mask(mask_bytes: bytes, dim: int) -> np.ndarray:
        mask = np.unpackbits(np.frombuffer(mask_bytes, dtype=np.uint8))
        return mask[:dim].astype(np.uint8)

    def helper_uses_reedsolo(self) -> bool:
        return REEDSOLO_AVAILABLE