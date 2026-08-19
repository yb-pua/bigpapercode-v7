"""A4 密码学原语性能对比实验。

对比组（同硬件同机器）：
    SM3  vs SHA-256          —— 散列
    SM4  vs AES-256          —— 分组密码（CBC）
    SM9  vs SM2 vs RSA-2048 vs ECDSA-P256 —— 签名
    SM9 密钥交换 vs ECDH-P256 —— 密钥交换
输出：
    results/expA4_perf.csv     —— 每原语每次操作的耗时
    results/expA4_summary.csv  —— 平均/中位数/95 分位
"""

import sys
import time
from pathlib import Path

import numpy as np

sys.path.insert(0, str(Path(__file__).resolve().parent.parent.parent))
sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from core.common import csv_meta, sm3, sm4_cbc_encrypt, sm4_cbc_decrypt, write_csv
from core.did import make_user_did
from core.sm9_engine import SM9Engine
from data_config import FIGURES_DIR, RESULTS_DIR
RESULTS_DIR = Path(__file__).resolve().parent / "结果"
FIGURES_DIR = RESULTS_DIR / "figures"
AUDIT_PATH = RESULTS_DIR / "auth_audit.jsonl"
TEE_AUDIT_PATH = RESULTS_DIR / "kdc_tee_audit.jsonl"

N_ITER = 200
_BENCH_N = N_ITER
MSG = b"SM9-Kerberos-biometric-key-2026" * 4


def bench(fn, n=None):
    """返回 n 次调用的耗时列表（秒）。"""
    if n is None:
        n = _BENCH_N
    out = []
    for _ in range(n):
        t0 = time.perf_counter()
        fn()
        out.append(time.perf_counter() - t0)
    return out


def _pad16(data: bytes) -> bytes:
    return data + bytes([16 - len(data) % 16]) * (16 - len(data) % 16)


def main():
    debug = "--debug" in sys.argv
    quick = "--quick" in sys.argv
    global _BENCH_N
    if quick:
        _BENCH_N = 20
    RESULTS_DIR.mkdir(parents=True, exist_ok=True)
    FIGURES_DIR.mkdir(parents=True, exist_ok=True)
    rows = []

    # ---- 散列 ----
    import hashlib
    rows += [{"group": "hash", "algo": "sm3", "op": "hash",
              "seconds": v} for v in bench(lambda: sm3(MSG))]
    rows += [{"group": "hash", "algo": "sha256", "op": "hash",
              "seconds": v} for v in bench(
                  lambda: hashlib.sha256(MSG).digest())]

    # ---- 分组密码 ----
    key32 = sm3(b"aes-key-material") + b"\x00" * 0
    key16 = key32[:16]
    iv = b"\x01" * 16
    rows += [{"group": "cipher", "algo": "sm4_cbc", "op": "encrypt",
              "seconds": v} for v in bench(
                  lambda: sm4_cbc_encrypt(MSG, key32))]
    ct = sm4_cbc_encrypt(MSG, key32)
    rows += [{"group": "cipher", "algo": "sm4_cbc", "op": "decrypt",
              "seconds": v} for v in bench(lambda: sm4_cbc_decrypt(ct, key32))]

    try:
        from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
        from cryptography.hazmat.backends import default_backend
        aes = Cipher(algorithms.AES(key16), modes.CBC(iv))
        enc = aes.encryptor()
        aes_ct = enc.update(_pad16(MSG)) + enc.finalize()

        def aes_enc():
            e = Cipher(algorithms.AES(key16), modes.CBC(iv)).encryptor()
            return e.update(_pad16(MSG)) + e.finalize()

        def aes_dec():
            d = Cipher(algorithms.AES(key16), modes.CBC(iv)).decryptor()
            return d.update(aes_ct) + d.finalize()

        rows += [{"group": "cipher", "algo": "aes256_cbc", "op": "encrypt",
                  "seconds": v} for v in bench(aes_enc)]
        rows += [{"group": "cipher", "algo": "aes256_cbc", "op": "decrypt",
                  "seconds": v} for v in bench(aes_dec)]
    except Exception as e:
        print(f"[A4] cryptography AES unavailable: {e}")

    # ---- 签名 ----
    sm9 = SM9Engine()
    did = make_user_did("perf_user")
    sig = sm9.sign(did, MSG)
    rows += [{"group": "sign", "algo": "sm9", "op": "sign",
              "seconds": v} for v in bench(lambda: sm9.sign(did, MSG))]
    rows += [{"group": "sign", "algo": "sm9", "op": "verify",
              "seconds": v} for v in bench(lambda: sm9.verify(did, MSG, sig))]

    try:
        from cryptography.hazmat.primitives.asymmetric import ec, padding, rsa
        from cryptography.hazmat.primitives import hashes
        from cryptography.hazmat.backends import default_backend
        rsa_key = rsa.generate_private_key(public_exponent=65537,
                                           key_size=2048,
                                           backend=default_backend())
        rsa_sig = rsa_key.sign(MSG, padding.PSS(
            mgf=padding.MGF1(hashes.SHA256()), salt_length=32),
            hashes.SHA256())
        rows += [{"group": "sign", "algo": "rsa2048", "op": "sign",
                  "seconds": v} for v in bench(
                      lambda: rsa_key.sign(
                          MSG, padding.PSS(mgf=padding.MGF1(hashes.SHA256()),
                                           salt_length=32), hashes.SHA256()))]
        pub = rsa_key.public_key()
        rows += [{"group": "sign", "algo": "rsa2048", "op": "verify",
                  "seconds": v} for v in bench(
                      lambda: pub.verify(
                          rsa_sig, MSG,
                          padding.PSS(mgf=padding.MGF1(hashes.SHA256()),
                                      salt_length=32), hashes.SHA256()))]

        ec_key = ec.generate_private_key(ec.SECP256R1(), default_backend())
        ec_sig = ec_key.sign(MSG, ec.ECDSA(hashes.SHA256()))
        ec_pub = ec_key.public_key()
        rows += [{"group": "sign", "algo": "ecdsa_p256", "op": "sign",
                  "seconds": v} for v in bench(
                      lambda: ec_key.sign(MSG, ec.ECDSA(hashes.SHA256())))]
        rows += [{"group": "sign", "algo": "ecdsa_p256", "op": "verify",
                  "seconds": v} for v in bench(
                      lambda: ec_pub.verify(ec_sig, MSG,
                                            ec.ECDSA(hashes.SHA256())))]
    except Exception as e:
        print(f"[A4] cryptography RSA/ECDSA unavailable: {e}")

    # SM2（gmalg）签名
    try:
        from gmalg import SM2
        tmp = SM2()
        sk2, pk2 = tmp.generate_keypair()
        uid2 = b"alice@example.com"
        signer2 = SM2(sk=sk2, uid=uid2)
        verifier2 = SM2(pk=pk2, uid=uid2)
        r2, s2 = signer2.sign(MSG)
        rows += [{"group": "sign", "algo": "sm2", "op": "sign",
                  "seconds": v} for v in bench(lambda: signer2.sign(MSG))]
        rows += [{"group": "sign", "algo": "sm2", "op": "verify",
                  "seconds": v} for v in bench(
                      lambda: verifier2.verify(MSG, r2, s2))]
    except Exception as e:
        print(f"[A4] gmalg SM2 unavailable: {e}")

    # ---- 密钥交换 ----
    did_a, did_b = make_user_did("alice"), make_user_did("bob")
    rows += [{"group": "key_exchange", "algo": "sm9", "op": "initiator",
              "seconds": v} for v in bench(
                  lambda: sm9.key_exchange_initiator(did_a, did_b)[0])]

    try:
        from cryptography.hazmat.primitives.asymmetric import ec
        from cryptography.hazmat.backends import default_backend
        eca = ec.generate_private_key(ec.SECP256R1(), default_backend())
        ecb = ec.generate_private_key(ec.SECP256R1(), default_backend())

        def ecdh():
            pub_b = ecb.public_key()
            return eca.exchange(ec.ECDH(), pub_b)

        rows += [{"group": "key_exchange", "algo": "ecdh_p256", "op": "exchange",
                  "seconds": v} for v in bench(ecdh)]
    except Exception as e:
        print(f"[A4] cryptography ECDH unavailable: {e}")

    write_csv(RESULTS_DIR / "expA4_perf.csv", rows)

    summary = []
    for (group, algo, op), sub in _groupby(rows).items():
        vals = np.array([r["seconds"] for r in sub])
        summary.append({
            "group": group, "algo": algo, "op": op, "n": len(vals),
            "mean_ms": float(vals.mean()) * 1e3,
            "median_ms": float(np.median(vals)) * 1e3,
            "p95_ms": float(np.percentile(vals, 95)) * 1e3,
        })
    write_csv(RESULTS_DIR / "expA4_summary.csv", summary)
    csv_meta(RESULTS_DIR / "expA4_summary.csv", {
        "n_iter": N_ITER, "msg_bytes": len(MSG),
        "cpu": "host-cpu", "impl": "gmalg-1.1.2 / cryptography-50",
    })
    for s in summary:
        print(f"[A4] {s['algo']:<12} {s['op']:<9} "
              f"mean={s['mean_ms']:.3f}ms median={s['median_ms']:.3f}ms")
    log("A4 done -> results/expA4_*.csv")


def _groupby(rows):
    from collections import OrderedDict
    g = OrderedDict()
    for r in rows:
        g.setdefault((r["group"], r["algo"], r["op"]), []).append(r)
    return g


if __name__ == "__main__":
    from exp_common import log
    main()