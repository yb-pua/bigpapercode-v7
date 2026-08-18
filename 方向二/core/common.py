"""
公共底座：全局固定 SEED 随机源、SM3 哈希、HMAC-SM3、SM4-CBC、指标与 CSV 规约。

随机性约定：本工程一切随机量（盐、nonce、会话密钥、扰动、抽样）均由
全局固定 SEED 派生，禁止 os.urandom，保证全流程可复现。
"""

import json
import time
from pathlib import Path
from typing import Callable, Dict, List, Optional, Sequence, Union

import numpy as np

SEED = 20260817

_rand_counter = 0
_rand_lock = None


def get_rng(seed: int = SEED) -> np.random.RandomState:
    return np.random.RandomState(seed)


def rand_bytes(n: int, label: str = "random") -> bytes:
    """从全局固定 SEED 派生确定性字节流（替代 os.urandom）。"""
    global _rand_counter
    out = bytearray()
    counter = _rand_counter
    while len(out) < n:
        digest = sm3(label.encode("utf-8") + SEED.to_bytes(8, "big") + counter.to_bytes(8, "big"))
        out.extend(digest)
        counter += 1
    _rand_counter = counter
    return bytes(out[:n])


# ---------------------------------------------------------------------------
# SM3（gmalg 真实实现，接口不可用则回退纯 Python 实现并标注）
# ---------------------------------------------------------------------------

_gmalg_available = False
try:
    from gmalg import SM3 as _GmalgSM3

    _gmalg_available = True
except ImportError:
    _gmalg_available = False

_SM3_IMPL = "gmalg" if _gmalg_available else "pure-python(simulated)"


def sm3(data: bytes) -> bytes:
    """SM3 哈希，输出 32 字节。"""
    if _gmalg_available:
        h = _GmalgSM3()
        h.update(bytes(data))
        return bytes(h.value())
    return _sm3_pure_python(bytes(data))


def sm3_hex(data: bytes) -> str:
    return sm3(data).hex()


def _sm3_pure_python(msg: bytes) -> bytes:
    """SM3 参考实现（gmalg 不可用时的模拟回退，标注 simulated）。"""
    IV = [
        0x7380166F, 0x4914B2B9, 0x172442D7, 0xDA8A0600,
        0xA96F30BC, 0x163138AA, 0xE38DEE4D, 0xB0FB0E4E,
    ]
    T = [0x79CC4519] * 16 + [0x7A879D8A] * 48
    MASK = 0xFFFFFFFF

    def rotl(x, n):
        return ((x << n) | (x >> (32 - n))) & MASK

    def p0(x):
        return x ^ rotl(x, 9) ^ rotl(x, 17)

    def p1(x):
        return x ^ rotl(x, 15) ^ rotl(x, 23)

    def ff(x, y, z, j):
        return (x ^ y ^ z) if j < 16 else ((x & y) | (x & z) | (y & z))

    def gg(x, y, z, j):
        return (x ^ y ^ z) if j < 16 else ((x & y) | (~x & z))

    msg = bytearray(msg)
    l = len(msg) * 8
    msg.append(0x80)
    while len(msg) % 64 != 56:
        msg.append(0x00)
    msg += l.to_bytes(8, "big")

    v = list(IV)
    for i in range(0, len(msg), 64):
        block = msg[i:i + 64]
        w = [int.from_bytes(block[j:j + 4], "big") for j in range(0, 64, 4)]
        for j in range(16, 68):
            w.append(p1(w[j - 16] ^ w[j - 9] ^ rotl(w[j - 3], 15)) ^ rotl(w[j - 13], 7) ^ w[j - 6])
        w1 = [w[j] ^ w[j + 4] for j in range(64)]
        a, b, c, d, e, f, g, h = v
        for j in range(64):
            ss1 = rotl((rotl(a, 12) + e + rotl(T[j], j % 32)) & MASK, 7)
            ss2 = ss1 ^ rotl(a, 12)
            tt1 = (ff(a, b, c, j) + d + ss2 + w1[j]) & MASK
            tt2 = (gg(e, f, g, j) + h + ss1 + w[j]) & MASK
            d = c
            c = rotl(b, 9)
            b = a
            a = tt1
            h = g
            g = rotl(f, 19)
            f = e
            e = p0(tt2)
        v = [(x ^ y) & MASK for x, y in zip(v, [a, b, c, d, e, f, g, h])]
    return b"".join(x.to_bytes(4, "big") for x in v)


def hmac_sm3(key: bytes, data: bytes) -> bytes:
    """HMAC-SM3（RFC 2104 构造，底层哈希为 SM3）。"""
    block_size = 64
    if len(key) > block_size:
        key = sm3(key)
    key = key + b"\x00" * (block_size - len(key))
    ipad = bytes(b ^ 0x36 for b in key)
    opad = bytes(b ^ 0x5C for b in key)
    return sm3(opad + sm3(ipad + bytes(data)))


def pbkdf2_sm3(password: bytes, salt: bytes, iterations: int = 10000, dklen: int = 32) -> bytes:
    """PBKDF2 构造（伪随机函数为 HMAC-SM3），用于口令方案对照。"""
    if dklen <= 0:
        raise ValueError("dklen must be positive")
    blocks = []
    counter = 1
    while len(b"".join(blocks)) < dklen:
        u = hmac_sm3(password, salt + counter.to_bytes(4, "big"))
        t = u
        for _ in range(iterations - 1):
            u = hmac_sm3(password, u)
            t = bytes(a ^ b for a, b in zip(t, u))
        blocks.append(t)
        counter += 1
    return b"".join(blocks)[:dklen]


# ---------------------------------------------------------------------------
# SM4-CBC（gmalg 分组原语 + PKCS7 填充，标注为 CBC 模式包装）
# ---------------------------------------------------------------------------

_sm4_gmalg = False
try:
    from gmalg import SM4 as _GmalgSM4Block

    _sm4_gmalg = True
except ImportError:
    _sm4_gmalg = False

_SM4_IMPL = "gmalg(CBC wrapper)" if _sm4_gmalg else "simulated"


def sm4_cbc_encrypt(plaintext: bytes, key: bytes, iv: Optional[bytes] = None) -> bytes:
    """SM4-CBC 加密（PKCS7 填充）。iv 缺省时由全局固定 SEED 派生。"""
    if iv is None:
        iv = rand_bytes(16, "sm4_iv")
    block_key = sm3(key)[:16]
    pad = 16 - (len(plaintext) % 16)
    data = plaintext + bytes([pad]) * pad
    if _sm4_gmalg:
        block = _GmalgSM4Block(block_key)
        prev = iv
        out = bytearray()
        for i in range(0, len(data), 16):
            blk = bytes(a ^ b for a, b in zip(data[i:i + 16], prev))
            enc = block.encrypt(blk)
            out.extend(enc)
            prev = enc
        return iv + bytes(out)
    return iv + _simulated_cipher(data, key, iv)


def sm4_cbc_decrypt(ciphertext: bytes, key: bytes) -> bytes:
    """SM4-CBC 解密（PKCS7 去填充）。"""
    if len(ciphertext) < 32 or len(ciphertext) % 16 != 0:
        raise ValueError("invalid SM4 ciphertext length")
    iv = ciphertext[:16]
    body = ciphertext[16:]
    block_key = sm3(key)[:16]
    if _sm4_gmalg:
        block = _GmalgSM4Block(block_key)
        out = bytearray()
        prev = iv
        for i in range(0, len(body), 16):
            dec = block.decrypt(body[i:i + 16])
            out.extend(bytes(a ^ b for a, b in zip(dec, prev)))
            prev = body[i:i + 16]
    else:
        out = bytearray(_simulated_cipher(body, key, iv))
    pad = out[-1]
    if pad < 1 or pad > 16:
        raise ValueError("invalid SM4 padding")
    return bytes(out[:-pad])


def _simulated_cipher(data: bytes, key: bytes, iv: bytes) -> bytes:
    """gmalg SM4 不可用时的模拟回退（异或流，仅用于可运行性，标注 simulated）。"""
    stream = b""
    counter = 0
    while len(stream) < len(data):
        stream += sm3(key + iv + counter.to_bytes(4, "big"))
        counter += 1
    return bytes(a ^ b for a, b in zip(data, stream))


# ---------------------------------------------------------------------------
# 指标与统计
# ---------------------------------------------------------------------------


def stats_ms(values: Sequence[float]) -> Dict[str, float]:
    """时延统计（ms），含 p50/p90。"""
    arr = np.asarray(values, dtype=np.float64)
    if arr.size == 0:
        return {"count": 0.0, "mean_ms": 0.0, "std_ms": 0.0, "min_ms": 0.0,
                "max_ms": 0.0, "p50_ms": 0.0, "p90_ms": 0.0}
    return {
        "count": float(arr.size),
        "mean_ms": float(np.mean(arr)),
        "std_ms": float(np.std(arr)),
        "min_ms": float(np.min(arr)),
        "max_ms": float(np.max(arr)),
        "p50_ms": float(np.percentile(arr, 50)),
        "p90_ms": float(np.percentile(arr, 90)),
    }


def compute_eer(far: Sequence[float], frr: Sequence[float]) -> float:
    """EER：FAR/FRR 曲线交点（线性插值）。"""
    far = np.asarray(far, dtype=np.float64)
    frr = np.asarray(frr, dtype=np.float64)
    if far.size < 2:
        return 1.0
    diff = far - frr
    idx = np.where(np.diff(np.sign(diff)) != 0)[0]
    if idx.size == 0:
        return float(min(np.min(far), np.min(frr)))
    i = idx[0]
    x = diff[i] / (diff[i] - diff[i + 1] + 1e-12)
    return float(frr[i] + x * (frr[i + 1] - frr[i]))


def compute_auc_roc(fpr: Sequence[float], tpr: Sequence[float]) -> float:
    """AUC：梯形积分。"""
    fpr = np.asarray(fpr, dtype=np.float64)
    tpr = np.asarray(tpr, dtype=np.float64)
    order = np.argsort(fpr)
    fpr, tpr = fpr[order], tpr[order]
    return float(np.trapz(tpr, fpr))


def compute_auc_mann_whitney(genuine_scores: Sequence[float], impostor_scores: Sequence[float]) -> float:
    """AUC = P(genuine < impostor)（Mann-Whitney，样本外推）。"""
    g = np.asarray(genuine_scores, dtype=np.float64)
    i = np.asarray(impostor_scores, dtype=np.float64)
    if g.size == 0 or i.size == 0:
        return 0.5
    if g.size * i.size > 5_000_000:
        rng = get_rng()
        if g.size > 5000:
            g = rng.choice(g, 5000, replace=False)
        if i.size > 5000:
            i = rng.choice(i, 5000, replace=False)
    concat = np.concatenate([g, i])
    sorter = np.argsort(concat, kind="mergesort")
    sorted_vals = concat[sorter]
    ranks = np.empty(concat.size, dtype=np.float64)
    start = 0
    while start < concat.size:
        end = start
        while end < concat.size and sorted_vals[end] == sorted_vals[start]:
            end += 1
        avg_rank = (start + 1 + end) / 2.0
        ranks[sorter[start:end]] = avg_rank
        start = end
    sum_g = ranks[:g.size].sum()
    u = sum_g - g.size * (g.size + 1) / 2.0
    return float(1.0 - u / (g.size * i.size))


# ---------------------------------------------------------------------------
# CSV 规约：英文列名、数值 ≥4 位有效数字
# ---------------------------------------------------------------------------


def format_value(v):
    if isinstance(v, (float, np.floating)):
        v = float(v)
        if abs(v) >= 1e12 or (v != 0 and abs(v) < 1e-9):
            return f"{v:.6g}"
        return f"{v:.8f}"
    if isinstance(v, (int, np.integer)):
        return str(int(v))
    if isinstance(v, bool):
        return "true" if v else "false"
    if isinstance(v, str):
        return v
    if v is None:
        return ""
    return str(v)


def write_csv(path: Union[str, Path], rows: List[Dict[str, object]]) -> None:
    """写 CSV：固定列序（按首行 key 序），≥4 位有效数字。"""
    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True)
    if not rows:
        path.write_text("", encoding="utf-8")
        return
    cols = list(rows[0].keys())
    lines = [",".join(cols)]
    for row in rows:
        lines.append(",".join(format_value(row.get(c, "")) for c in cols))
    path.write_text("\n".join(lines) + "\n", encoding="utf-8")


def read_csv(path: Union[str, Path]) -> List[Dict[str, str]]:
    path = Path(path)
    lines = [ln for ln in path.read_text(encoding="utf-8").strip().splitlines()
             if ln and not ln.startswith("#meta")]
    if not lines:
        return []
    cols = lines[0].split(",")
    return [dict(zip(cols, ln.split(","))) for ln in lines[1:]]


def write_jsonl(path: Union[str, Path], rows: List[Dict[str, object]]) -> None:
    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True)
    with open(path, "a", encoding="utf-8") as f:
        for row in rows:
            f.write(json.dumps(row, ensure_ascii=True) + "\n")


def csv_meta(path: Union[str, Path], meta: Dict[str, object]) -> None:
    """在 CSV 末尾追加元数据行（key=value），标注 seed/环境/模拟状态。"""
    path = Path(path)
    with open(path, "a", encoding="utf-8") as f:
        f.write("#meta " + json.dumps(meta, ensure_ascii=True) + "\n")