"""
B0 组网基础设施：节点发现/拓扑可行性 + NAT 类型对量化 + 兜底率推导。

输出（独立 formal_v2_<run_id> 目录，不覆盖旧 CSV）：
    discovery.csv       (discover_ms, topology_entries, connect_ok)
    nat.csv             (nat_type_pair, direct_ok, relay_needed,
                         latency_direct_ms, latency_relay_ms, assumed_simulated)
    summary.csv         (发现时延 p50/p90、兜底率、理论直连率)
    manifest.json       (git_commit / dirty_worktree / mode / seed / simulated)

口径（D2 拍板）：NAT 类型分布 = 均匀四类；直连必须双方同时判定可行；
latency_direct_ms/latency_relay_ms 为本机回环假设值（assumed_simulated），
不声称真实公网穿透率。
"""

import json
import subprocess
import sys
import time
from pathlib import Path

import numpy as np

sys.path.insert(0, str(Path(__file__).resolve().parent.parent.parent))

from core.common import (SEED, csv_meta, get_rng, stats_ms, write_csv)
from core.device import Device
from core.discovery import DiscoveryService
from core.kdc import KDC
from core.nat_layer import NAT_TYPES, VirtualNAT, derive_relay_needed, try_punch
from core.relay import Relay
from core.sm9_engine import SM9Engine
from core.st_ticket import netperm_defaults

N_PRE = 30                     # 预试验规模（方案 §7：B0/B1 先 30 台）
N_REPEAT = 30                  # NAT 类型对重复次数
RESULTS = Path(__file__).resolve().parent / "结果"
REPO_ROOT = Path(__file__).resolve().parent.parent.parent.parent


def _git_head() -> str:
    try:
        return subprocess.check_output(
            ["git", "rev-parse", "HEAD"], cwd=str(REPO_ROOT),
            stderr=subprocess.DEVNULL).decode().strip()
    except Exception:
        return "unknown"


def _git_dirty() -> bool:
    try:
        out = subprocess.check_output(
            ["git", "status", "--porcelain"], cwd=str(REPO_ROOT),
            stderr=subprocess.DEVNULL).decode().strip()
        return bool(out)
    except Exception:
        return True


def main():
    quick = "--quick" in sys.argv
    n_pre = 6 if quick else N_PRE
    n_repeat = 6 if quick else N_REPEAT
    run_id = time.strftime("%Y%m%d_%H%M%S") + f"_{time.time_ns() % 1000000000:09d}"
    out_dir = RESULTS / f"formal_v2_{run_id}"
    out_dir.mkdir(parents=True, exist_ok=False)

    rng = get_rng()
    sm9 = SM9Engine()
    kdc = KDC(sm9)
    ctx1 = kdc.auth_context.issue("didsm9:user1:aaa", "src-1", "ev-1")
    assert kdc.register_user_context(ctx1)
    relay = Relay(sm9, kdc, relay_id="relay-1")
    relay.setup_proxy()
    netperm = netperm_defaults()
    netperm["services"] = ["file-sync", "rtc"]
    netperm["bandwidth_mbps"] = 10.0

    # ------------------------------------------------------------------
    # 发现/拓扑（预试验 n_pre 台）
    # ------------------------------------------------------------------
    ds = DiscoveryService(relay_dids=[relay.relay_did])
    discovery_rows = []
    latencies = []
    for i in range(n_pre):
        dev = Device(f"dev-{i:03d}", "didsm9:user1:aaa", sm9)
        assert dev.enroll(kdc)
        dev.obtain_authorization(kdc, netperm)
        t0 = time.perf_counter()
        ds.register_device(dev.did, f"127.0.0.1:{10000 + i}")
        found = ds.find_node(dev.did)
        ds_elapsed = (time.perf_counter() - t0) * 1000.0
        latencies.append(ds_elapsed)
        # 新设备发现 → 双方完成 ST 准入 → 会话凭证
        ok_link = False
        if found:
            r1 = relay.begin_admission(dev.admission_round1(), "relay@realm")
            if r1["ok"]:
                r2 = dev.admission_round2(r1["challenge_id"], r1["challenge"],
                                          r1["request_digest"])
                fin = relay.finish_admission(r1["challenge_id"], r1["challenge"],
                                             r2["sig"], r2["nonce"], r2["ts"],
                                             "relay@realm")
                ok_link = fin["ok"]
        discovery_rows.append({
            "discover_ms": ds_elapsed,
            "topology_entries": ds.device_count(),
            "connect_ok": ok_link,
        })

    topo = ds.build_topology()
    topo_size = sum(len(v) for v in topo.values())

    # ------------------------------------------------------------------
    # NAT 类型对量化（16 对 × n_repeat 次；双向判定）
    # ------------------------------------------------------------------
    nat_rows = []
    direct_ok_by_pair = {}
    for src in NAT_TYPES:
        for dst in NAT_TYPES:
            ok = 0
            for _ in range(n_repeat):
                a = VirtualNAT(src)
                b = VirtualNAT(dst)
                if a.punch(dst) and b.punch(src):   # 双向判定：双方同时成立
                    ok += 1
            direct_ok = ok / n_repeat
            direct_ok_by_pair[(src, dst)] = direct_ok
            nat_rows.append({
                "nat_type_pair": f"{src}->{dst}",
                "direct_ok": direct_ok,
                "relay_needed": 1.0 - direct_ok,
                "latency_direct_ms": 1.2,        # assumed_simulated（本机回环假设）
                "latency_relay_ms": 2.4,         # assumed_simulated（多一跳假设）
                "assumed_simulated": True,
            })

    # 均匀分布兜底率（D2 口径）
    uniform = {t: 0.25 for t in NAT_TYPES}
    relay_p, direct_p = derive_relay_needed(uniform)
    theory_ok = sum(1 for s in NAT_TYPES for d in NAT_TYPES
                    if try_punch(s, d) and try_punch(d, s))
    theory_ok /= len(NAT_TYPES) ** 2

    st = stats_ms(latencies)
    summary = [{
        "n_devices": n_pre,
        "discover_p50_ms": st["p50_ms"],
        "discover_p90_ms": st["p90_ms"],
        "topology_entries": topo_size,
        "connect_ok_rate": sum(r["connect_ok"] for r in discovery_rows) / n_pre,
        "nat_pairs": len(nat_rows),
        "theory_direct_rate": theory_ok,
        "derived_relay_needed": relay_p,        # 均匀分布推导
        "derived_direct_rate": direct_p,
        "nat_distribution": "uniform(0.25,0.25,0.25,0.25)",
    }]

    write_csv(out_dir / "discovery.csv", discovery_rows)
    write_csv(out_dir / "nat.csv", nat_rows)
    write_csv(out_dir / "summary.csv", summary)
    manifest = {
        "git_commit": _git_head(),
        "dirty_worktree": _git_dirty(),
        "mode": "quick" if quick else "formal",
        "seed": SEED,
        "n_pre": n_pre,
        "n_repeat": n_repeat,
        "simulated_components": [
            "VirtualNAT/punch (no real STUN/TURN/socket)",
            "latency_direct_ms/latency_relay_ms (assumed_simulated loopback)",
        ],
    }
    (out_dir / "manifest.json").write_text(
        json.dumps(manifest, ensure_ascii=False, indent=2), encoding="utf-8")
    for f in ("discovery.csv", "nat.csv", "summary.csv"):
        csv_meta(out_dir / f, {"seed": SEED, "mode": manifest["mode"],
                               "n_pre": n_pre, "n_repeat": n_repeat})
    print(f"B0 done: discovery p50={st['p50_ms']:.2f}ms, "
          f"connect_ok={summary[0]['connect_ok_rate']:.2%}, "
          f"derived_relay_needed={relay_p:.4f}, theory_direct={theory_ok:.4f}")


if __name__ == "__main__":
    main()
