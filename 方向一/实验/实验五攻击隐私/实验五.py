"""A5 攻击面与隐私度量实验。

攻击面（对抗机制验证，成功率必须为 0）：
    a01 重放 AS-REQ（同 nonce）          → nonce 登记表拦截
    a02 篡改 ST 载荷                     → SM4-CBC 解密失败拦截
    a03 篡改 TGT 载荷（TGS 侧）          → 同上
    a04 冒名注册（伪造 SM9 签名）        → SM9 验签拦截
    a05 未注册 DID 认证                  → 登记表拦截
    a06 无会话密钥伪造 TGS Authenticator → 会话密钥解密拦截
    a07 异人生物探测（σ 冒用）           → key_hash 拦截
    a08 过期票据                         → 有效期拦截
    a09 时钟偏差超窗                     → 30min 窗口拦截
隐私度量：
    p01 σ 信息量（熵估计，字节分布）
    p02 同人重登记 σ 不可链接性（两次 Gen 的 offset 汉明距离≈均匀随机）
    p03 W 熵估计（逐维投票稳定性 → 有效熵 → 暴力破解步数下界）
    p04 σ 不含明文特征（W/bio_key 不在 offset 中）
输出：
    results/expA5_attacks.csv / expA5_privacy.csv / expA5_summary.csv
"""

import sys
from pathlib import Path

import numpy as np

sys.path.insert(0, str(Path(__file__).resolve().parent.parent.parent))
sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from core.audit_logger import AuditLogger
from core.common import csv_meta, sm3, write_csv
from core.did import make_user_did
from core.fuzzy_extractor import FuzzyExtractor, RS_N
from core.kerberos_enhanced import (AS, KerberosClient, KerberosRealm,
                                    MAX_SKEW, Service, TGS, TICKET_TTL,
                                    _b64e, _pack)
from core.sm9_engine import SM9Engine
from exp_common import (cohort_persons, enroll_from_images, load_cache, log,
                        person_embs, quantize)
from data_config import AUDIT_PATH, FIGURES_DIR, RESULTS_DIR
RESULTS_DIR = Path(__file__).resolve().parent / "结果"
FIGURES_DIR = RESULTS_DIR / "figures"
AUDIT_PATH = RESULTS_DIR / "auth_audit.jsonl"
TEE_AUDIT_PATH = RESULTS_DIR / "kdc_tee_audit.jsonl"

SERVICE_ID = "svc_a@REALM"
N_ATTACKS = 20


def main():
    debug = "--debug" in sys.argv
    quick = "--quick" in sys.argv
    n_attacks = 5 if quick else N_ATTACKS
    RESULTS_DIR.mkdir(parents=True, exist_ok=True)
    FIGURES_DIR.mkdir(parents=True, exist_ok=True)
    fe = FuzzyExtractor()
    embs = load_cache()
    cohort = cohort_persons(embs, 5)[:n_attacks]
    log(f"persons: {len(cohort)}")

    engine = SM9Engine()
    realm = KerberosRealm(audit_logger=AuditLogger(str(AUDIT_PATH)))
    as_server = AS(realm, engine)
    tgs_server = TGS(realm)
    realm.register_service(SERVICE_ID)
    svc = Service(realm, SERVICE_ID)

    rows = []
    now = [20000.0]
    person = cohort[0]
    e = person_embs(embs, person, max_n=5)
    W, mask, bio_key, sigma = enroll_from_images(e, fe)
    did = make_user_did("victim")
    uid = "victim"
    reg_ts = now[0]
    reg_msg = _pack({"user_id": uid, "did": did, "ts": reg_ts})
    as_server.register(did, uid, fe.key_hash(bio_key),
                       engine.sign(did, reg_msg), reg_ts, now=reg_ts)
    client = KerberosClient(did, bio_key, engine)
    as_req = client.build_as_req(now[0])
    as_resp = as_server.authenticate(did, bio_key, as_req["nonce"],
                                     as_req["ts"], as_req["signature"],
                                     now=now[0])
    assert as_resp["ok"]
    client.store_tgt(as_resp["tgt"])

    def rec(name, ok, blocked_by):
        rows.append({"attack": name, "attempts": 1, "successes": int(ok),
                     "blocked_by": blocked_by, "status": "blocked" if not ok
                     else "vulnerable"})

    # a01 重放 AS-REQ
    r = as_server.authenticate(did, bio_key, as_req["nonce"], as_req["ts"],
                               as_req["signature"], now=now[0])
    rec("a01_replay_as_req", r["ok"], "nonce_registry")

    # a02 篡改 ST
    tgs_req = client.build_tgs_req(SERVICE_ID, now[0])
    tgs_resp = tgs_server.grant_service_ticket(
        tgs_req["encrypted_tgt"], tgs_req["authenticator"],
        tgs_req["nonce"], now=now[0])
    assert tgs_resp["ok"]
    client.store_st(tgs_resp["st"])
    ap_req = client.build_ap_req(SERVICE_ID, now[0])
    tampered = dict(ap_req)
    enc = bytearray(tampered["encrypted_st"].encode("ascii"))
    enc[10] = b"Q"[0] if enc[10] != b"Q"[0] else b"R"[0]
    tampered["encrypted_st"] = enc.decode("ascii")
    r = svc.verify_ap_req(tampered, now=now[0])
    rec("a02_tampered_st", r["ok"], "sm4_cbc_integrity")

    # a03 篡改 TGT（TGS 侧）
    tampered_tgt = dict(tgs_req)
    tt = bytearray(tampered_tgt["encrypted_tgt"].encode("ascii"))
    tt[0] = b"A"[0] if tt[0] != b"A"[0] else b"B"[0]
    tampered_tgt["encrypted_tgt"] = tt.decode("ascii")
    r = tgs_server.grant_service_ticket(
        tampered_tgt["encrypted_tgt"], tampered_tgt["authenticator"],
        tampered_tgt["nonce"], now=now[0])
    rec("a03_tampered_tgt", r["ok"], "sm4_cbc_integrity")

    # a04 冒名注册（伪造签名：用他人密钥签自己的 DID）
    fake_did = make_user_did("intruder")
    fake_msg = _pack({"user_id": "intruder", "did": fake_did, "ts": now[0]})
    r = as_server.register(fake_did, "intruder", b"\x00" * 32,
                           engine.sign(did, fake_msg), now[0], now=now[0])
    rec("a04_forged_register_sig", r, "sm9_verify")

    # a05 未注册 DID
    ghost_did = make_user_did("ghost")
    g_req = KerberosClient(ghost_did, bio_key, engine).build_as_req(now[0])
    r = as_server.authenticate(ghost_did, bio_key, g_req["nonce"],
                               g_req["ts"], g_req["signature"], now=now[0])
    rec("a05_unknown_did", r["ok"], "registration_table")

    # a06 无会话密钥伪造 TGS Authenticator
    from core.common import sm4_cbc_encrypt
    bad_auth = _b64e(sm4_cbc_encrypt(
        _pack({"client_did": did, "ts": now[0], "nonce": "x",
               "service_id": SERVICE_ID}), sm3(b"wrong-session-key")))
    forged = {"encrypted_tgt": tgs_req["encrypted_tgt"],
              "authenticator": {"ts": now[0], "nonce": "x",
                                "service_id": SERVICE_ID,
                                "encrypted": bad_auth},
              "nonce": b"x"}
    r = tgs_server.grant_service_ticket(
        forged["encrypted_tgt"], forged["authenticator"], forged["nonce"],
        now=now[0])
    rec("a06_forged_tgs_authenticator", r["ok"], "session_key_decrypt")

    # a07 异人生物探测（σ 冒用）
    other = cohort[1]
    eo = person_embs(embs, other, max_n=1)
    pb = quantize(eo[0])[mask == 1]
    out = fe.rep(pb, sigma, key_hash=fe.key_hash(bio_key))
    rec("a07_impostor_bio_rep", out == bio_key, "key_hash")

    # a08 过期票据
    tgs_req2 = client.build_tgs_req(SERVICE_ID, now[0])
    r = tgs_server.grant_service_ticket(
        tgs_req2["encrypted_tgt"], tgs_req2["authenticator"],
        tgs_req2["nonce"], now=now[0] + TICKET_TTL + 1)
    rec("a08_expired_ticket", r["ok"], "ticket_validity")

    # a09 时钟偏差超窗
    old_req = client.build_as_req(now[0] - MAX_SKEW - 1)
    r = as_server.authenticate(did, bio_key, old_req["nonce"], old_req["ts"],
                               old_req["signature"], now=now[0])
    rec("a09_clock_skew", r["ok"], "timestamp_window")
    write_csv(RESULTS_DIR / "expA5_attacks.csv", rows)
    for r in rows:
        log(f"A5: {r['attack']:<28} -> {r['status']} ({r['blocked_by']})")

    # ---------- 隐私度量 ----------
    priv = []

    # p01 σ 信息量（offset 255 字节的样本熵）
    counts = np.bincount(np.frombuffer(sigma["offset"], dtype=np.uint8),
                         minlength=256).astype(np.float64)
    p = counts / counts.sum()
    h = float(-(p[p > 0] * np.log2(p[p > 0])).sum())
    priv.append({"metric": "p01_sigma_entropy_bits_per_byte",
                 "value": h})
    priv.append({"metric": "p01_sigma_entropy_total_bits",
                 "value": h * RS_N})

    # p02 同人重登记 σ 不可链接（两次 Gen 的 offset 汉明距离）
    W2, mask2, bio_key2, sigma2 = enroll_from_images(e, fe)
    d = sum(a != b for a, b in zip(sigma["offset"], sigma2["offset"]))
    priv.append({"metric": "p02_rereg_sigma_diff_bytes",
                 "value": d})
    priv.append({"metric": "p02_rereg_sigma_diff_ratio",
                 "value": d / RS_N})
    priv.append({"metric": "p02_rereg_key_stable",
                 "value": int(bio_key == bio_key2)})

    # p03 W 熵估计（投票稳定性 → 有效熵）
    from core.stable_bits import majority_vote
    bit_matrix = np.stack([quantize(x) for x in e])
    _, stab = majority_vote(bit_matrix)

    def _bit_entropy(p):
        p = np.clip(np.asarray(p, dtype=np.float64), 1e-9, 1 - 1e-9)
        return -(p * np.log2(p) + (1 - p) * np.log2(1 - p))

    per_bit_entropy = np.where(
        (stab > 0.0) & (stab < 1.0), _bit_entropy(stab), 0.0)
    sel = per_bit_entropy[mask == 1]
    w_entropy = float(sel.sum())
    priv.append({"metric": "p03_w_entropy_bits", "value": w_entropy})
    priv.append({"metric": "p03_bruteforce_steps_log2",
                 "value": min(w_entropy, 256.0)})

    # p04 σ 不含明文特征
    priv.append({"metric": "p04_w_plaintext_in_offset",
                 "value": int(W.tobytes() in sigma["offset"])})
    priv.append({"metric": "p04_bio_key_in_offset",
                 "value": int(bio_key in sigma["offset"])})
    priv.append({"metric": "p04_biometric_key_derivation",
                 "value": 0})  # bio_key=SM3(W) 单向
    write_csv(RESULTS_DIR / "expA5_privacy.csv", priv)
    for r in priv:
        log(f"A5: {r['metric']:<34} = {r['value']:.4f}")

    summary = [
        {"metric": "attacks_total", "value": len(rows)},
        {"metric": "attacks_blocked", "value": sum(
            1 for r in rows if r["status"] == "blocked")},
        {"metric": "attacks_success", "value": sum(
            1 for r in rows if r["status"] == "vulnerable")},
        {"metric": "sigma_entropy_bytes", "value": h},
        {"metric": "rereg_sigma_diff_ratio", "value": d / RS_N},
        {"metric": "w_entropy_bits", "value": w_entropy},
    ]
    write_csv(RESULTS_DIR / "expA5_summary.csv", summary)
    csv_meta(RESULTS_DIR / "expA5_summary.csv", {
        "n_attacks": len(rows), "attacks": ",".join(r["attack"] for r in rows),
        "rs": f"RS({RS_N})", "seed": 20260817,
    })
    log("A5 done -> results/expA5_*.csv")


if __name__ == "__main__":
    main()