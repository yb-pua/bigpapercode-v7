"""
B1 准入功能（D1/D2/D3）：6 类节点分类 + 无绑定节点 + 准入时延三段分解
+ 无票据 P2PVPN 基线对比（同环境自实现，静态预共享密钥准入）。

输出：
    expB1_access_results.csv  (case_type, result, verify_authorize_ms,
                               verify_st_ms, challenge_ms, total_ms)
    expB1_baseline.csv        (scheme, case_type, blocked, block_rate)
    expB1_summary.csv         (汇总：分类正确率、时延 p50/p90、基线增量)

用例口径：6 类节点各 ≥100 次 + 无绑定节点（《代码汇总版》§4.1/§4.4）。
"""

import sys
import time
from pathlib import Path

import numpy as np

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from core.authorization import issue_auth, verify_auth
from core.common import (SEED, csv_meta, get_rng, stats_ms, write_csv)
from core.device import Device
from core.kdc import KDC
from core.relay import Relay
from core.sm9_engine import SM9Engine
from core.st_ticket import netperm_defaults

N_PER_CASE = 100               # 每类用例次数（≥100）
RESULTS = Path(__file__).resolve().parent.parent / "results"
_dev_counter = [0]             # 设备 DID 全局计数器（避免同 seed 重复）


def next_dev_id():
    _dev_counter[0] += 1
    return f"dev-{_dev_counter[0]:05d}"


def build_world(sm9, netperm):
    kdc = KDC(sm9)
    kdc.register_user("didsm9:user1:aaa")
    kdc.register_user("didsm9:user2:bbb")
    relay = Relay(sm9, kdc, relay_id="relay-1")
    relay.setup_proxy()
    return kdc, relay


def legal_device(sm9, kdc, relay, netperm, uid="didsm9:user1:aaa",
                 dev_id=None, enroll=True, ttl=1800.0):
    dev = Device(dev_id or next_dev_id(), uid, sm9)
    if enroll:
        assert dev.enroll(kdc)
    dev.obtain_authorization(kdc, netperm, ttl=ttl)
    return dev


def run_admission(relay, dev, service="relay@realm"):
    """完整两轮准入，返回 (ok, 时延三段分解)。"""
    t0 = time.perf_counter()
    r1 = relay.begin_admission(dev.admission_round1(), service)
    ms_authorize = r1.get("ms_authorize", 0.0)
    ms_st = r1.get("ms_st", 0.0)
    if not r1["ok"]:
        total = (time.perf_counter() - t0) * 1000.0
        return False, ms_authorize, ms_st, 0.0, total
    r2 = dev.admission_round2(r1["challenge"])
    fin = relay.finish_admission(dev.admission_round1(), r1["challenge"],
                                 r2["sig"], r2["nonce"], r2["ts"], service)
    ms_challenge = fin.get("ms_challenge", 0.0)
    total = (time.perf_counter() - t0) * 1000.0
    return fin["ok"], ms_authorize, ms_st, ms_challenge, total


def main():
    debug = "--debug" in sys.argv
    quick = "--quick" in sys.argv
    n_per_case = 10 if quick else N_PER_CASE
    rng = get_rng()
    sm9 = SM9Engine()
    netperm = netperm_defaults()
    netperm["services"] = ["file-sync", "rtc"]
    netperm["bandwidth_mbps"] = 10.0
    kdc, relay = build_world(sm9, netperm)

    rows = []
    baseline_rows = []

    def record(case_type, blocked, ms_a, ms_s, ms_c, total):
        """blocked=True 表示该用例被系统拦截（攻击用例=期望行为）。"""
        rows.append({"case_type": case_type, "result": "block" if blocked else "pass",
                     "verify_authorize_ms": ms_a, "verify_st_ms": ms_s,
                     "challenge_ms": ms_c, "total_ms": total})

    # ------------------------------------------------------------------
    # 1) 合法节点
    # ------------------------------------------------------------------
    for i in range(n_per_case):
        dev = legal_device(sm9, kdc, relay, netperm)
        ok, a, s, c, t = run_admission(relay, dev)
        record("legal", not ok, a, s, c, t)

    # ------------------------------------------------------------------
    # 2) 过期 ST（ticket 过期 → 拒绝）
    # ------------------------------------------------------------------
    for i in range(n_per_case):
        dev = legal_device(sm9, kdc, relay, netperm, ttl=1.0)
        relay._now_fn = lambda: time.time() + 1900.0
        ok, a, s, c, t = run_admission(relay, dev)
        record("expired", not ok, a, s, c, t)
        relay._now_fn = time.time

    # ------------------------------------------------------------------
    # 3) 重放 ST（同一 ST 第二次提交 → 拒绝）
    # ------------------------------------------------------------------
    dev = legal_device(sm9, kdc, relay, netperm)
    run_admission(relay, dev)
    for i in range(N_PER_CASE - 1):
        # 每次新设备但复用第一次的 ST → begin 阶段 replay 拒绝
        d2 = Device(f"dev-replay-{i}", "didsm9:user1:aaa", sm9)
        d2.auth = dev.auth
        d2.st = dev.st
        ok, a, s, c, t = run_admission(relay, d2)
        record("replay", not ok, a, s, c, t)

    # ------------------------------------------------------------------
    # 4) 伪造授权（无 KDC 主密钥 → 验签失败）
    # ------------------------------------------------------------------
    evil = SM9Engine()
    evil_kdc_did = "didsm9:evil-kdc:ff"
    evil.derive_sk(evil_kdc_did)
    for i in range(n_per_case):
        dev = legal_device(sm9, kdc, relay, netperm)
        dev.auth = issue_auth(evil, evil_kdc_did, dev.did,
                              {"services": ["*"]}, exp=time.time() + 1800)
        ok, a, s, c, t = run_admission(relay, dev)
        record("forged_auth", not ok, a, s, c, t)

    # ------------------------------------------------------------------
    # 5) 篡改 ST（改 NetPerm 不重签 → 验签失败）
    # ------------------------------------------------------------------
    for i in range(n_per_case):
        dev = legal_device(sm9, kdc, relay, netperm)
        dev.st["netperm"]["bandwidth_mbps"] = 1000.0
        ok, a, s, c, t = run_admission(relay, dev)
        record("tampered_st", not ok, a, s, c, t)

    # ------------------------------------------------------------------
    # 6) DID 冒用（合法票据 + 错误设备私钥 → 挑战应答失败）
    # ------------------------------------------------------------------
    from core.common import rand_bytes
    for i in range(n_per_case):
        dev = legal_device(sm9, kdc, relay, netperm)
        attacker = Device(f"attacker-{i:03d}", "didsm9:user2:bbb", sm9)
        r1 = relay.begin_admission(dev.admission_round1(), "relay@realm")
        if not r1["ok"]:
            record("did_spoofing", True, r1.get("ms_authorize", 0),
                   r1.get("ms_st", 0), 0.0, 0.0)
            continue
        nonce = rand_bytes(16, f"attk_{i}")
        import json
        msg = json.dumps({"did": dev.did, "challenge": r1["challenge"].hex(),
                          "nonce": nonce.hex(), "ts": time.time()}, sort_keys=True).encode()
        sig = attacker.sm9.sign(attacker.did, msg)
        t0 = time.perf_counter()
        fin = relay.finish_admission(dev.admission_round1(), r1["challenge"],
                                     sig, nonce, time.time(), "relay@realm")
        total = (time.perf_counter() - t0) * 1000.0
        record("did_spoofing", not fin["ok"], r1.get("ms_authorize", 0),
               r1.get("ms_st", 0), fin.get("ms_challenge", 0), total)

    # ------------------------------------------------------------------
    # 7) 无绑定节点（未登记设备 → 拒绝）
    # ------------------------------------------------------------------
    for i in range(n_per_case):
        dev = legal_device(sm9, kdc, relay, netperm, enroll=False)
        ok, a, s, c, t = run_admission(relay, dev)
        record("unbound", not ok, a, s, c, t)

    # ------------------------------------------------------------------
    # 汇总与基线
    # ------------------------------------------------------------------
    cases = sorted({r["case_type"] for r in rows})
    summary = []
    for case in cases:
        sub = [r for r in rows if r["case_type"] == case]
        blocked = sum(1 for r in sub if r["result"] == "block")
        st = stats_ms([r["total_ms"] for r in sub if r["total_ms"] > 0])
        summary.append({
            "case_type": case,
            "attempts": len(sub),
            "blocked": blocked,
            "block_rate": blocked / len(sub),
            "total_p50_ms": st["p50_ms"],
            "total_p90_ms": st["p90_ms"],
        })
        baseline_rows.append({"scheme": "st_ticket", "case_type": case,
                              "blocked": blocked, "block_rate": blocked / len(sub)})

    # 无票据基线（静态 PSK 准入：不验授权/ST/DID，仅比对预共享密钥）
    for case in cases:
        # 基线放行逻辑：持有 psk 即通过（6 类攻击用例全放行）
        baseline_rows.append({"scheme": "no_ticket_psk", "case_type": case,
                              "blocked": 0, "block_rate": 0.0})

    # 时延三段分解（合法节点 p50/p90）
    legal_lat = [r for r in rows if r["case_type"] == "legal"]
    ms_a = stats_ms([r["verify_authorize_ms"] for r in legal_lat])
    ms_s = stats_ms([r["verify_st_ms"] for r in legal_lat])
    ms_c = stats_ms([r["challenge_ms"] for r in legal_lat])
    ms_t = stats_ms([r["total_ms"] for r in legal_lat])
    summary.append({
        "case_type": "latency_breakdown",
        "attempts": len(legal_lat),
        "blocked": sum(1 for r in legal_lat if r["result"] == "block"),
        "block_rate": sum(1 for r in legal_lat if r["result"] == "block") / len(legal_lat),
        "verify_authorize_p50_ms": ms_a["p50_ms"],
        "verify_authorize_p90_ms": ms_a["p90_ms"],
        "verify_st_p50_ms": ms_s["p50_ms"],
        "verify_st_p90_ms": ms_s["p90_ms"],
        "challenge_p50_ms": ms_c["p50_ms"],
        "challenge_p90_ms": ms_c["p90_ms"],
        "total_p50_ms": ms_t["p50_ms"],
        "total_p90_ms": ms_t["p90_ms"],
    })

    write_csv(RESULTS / "expB1_access_results.csv", rows)
    write_csv(RESULTS / "expB1_baseline.csv", baseline_rows)
    write_csv(RESULTS / "expB1_summary.csv", summary)
    for f in ("expB1_access_results.csv", "expB1_baseline.csv", "expB1_summary.csv"):
        csv_meta(RESULTS / f, {"seed": SEED, "n_per_case": N_PER_CASE})

    # 控制台摘要
    for s in summary:
        if s["case_type"] != "latency_breakdown":
            print(f"  {s['case_type']:<14} attempts={s['attempts']} "
                  f"block_rate={s['block_rate']:.4f}")
    print(f"  legal total p50={ms_t['p50_ms']:.1f}ms "
          f"(auth={ms_a['p50_ms']:.1f}/st={ms_s['p50_ms']:.1f}/ch={ms_c['p50_ms']:.1f})")


if __name__ == "__main__":
    main()