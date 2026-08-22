"""
B3 隧道流量整形（D2/D5）：三型业务流 × {SM9-KA 隧道, 整形后隧道, TLS 基线}。
每型每方案 10min（D4 拍板，--quick 可缩短冒烟）。

输出：
    expB3_tunnel_shaping.csv  (flow_type, scheme, duration_s, throughput_mbps,
                               jitter_ms, pkt_len_entropy, pkt_len_kl,
                               gap_entropy, redundancy_rate, p50_ms, p90_ms)
    expB3_summary.csv         (元数据 + 整形平均冗余率/熵增益)

TLS 基线标注 simulated：TLS 1.3 记录层格式（5B 头 + AES-256-GCM），
真实 AES-GCM 加解密（cryptography），非真实 TLS 握手套接字。
"""

import math
import sys
import time
from pathlib import Path

import numpy as np

sys.path.insert(0, str(Path(__file__).resolve().parent.parent.parent))

from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from core.common import (SEED, csv_meta, get_rng, rand_bytes, write_csv)
from core.device import Device
from core.sm9_engine import SM9Engine
from core.st_ticket import netperm_defaults
from core.tunnel import Tunnel
from core.shaping import PAD_BINS, Shaper

FLOW_TYPES = ["period", "burst", "request"]
SCHEMES = ["sm9_raw", "sm9_shaped", "tls_baseline"]
RATE_MBPS = 1.0
SEGMENT_S = 10 * 60           # D4：每型每方案 10min
QUICK_S = 30                  # 冒烟
RESULTS = Path(__file__).resolve().parent / "结果"
N_BINS = 20


def flow_timeline(flow_type: str, rate_mbps: float, duration_s: float):
    """生成 (ts_offset, payload_len) 时间轴（复用 device.flow_gen 语义）。"""
    dev = Device("flow-gen", "didsm9:user1:aaa", SM9Engine())
    return dev.flow_gen(flow_type, rate_mbps, duration_s)


def record_headers() -> bytes:
    """TLS 1.3 记录头模拟（content_type=0x17 应用数据）。"""
    return b"\x17\x03\x03"


def run_segment(sm9, flow_type, scheme, tls_key=None, quick=False):
    """跑一段 10min（或 quick）流量，返回指标。"""
    dur = QUICK_S if quick else SEGMENT_S
    rng = np.random.RandomState(SEED % 2**31 + len(flow_type) * 7 +
                                len(scheme) * 13)
    tl = flow_timeline(flow_type, RATE_MBPS, dur)

    if scheme == "tls_baseline":
        aesgcm = AESGCM(tls_key)
        nonce_ctr = [0]
    elif scheme == "sm9_shaped":
        # 包长档位随机化（[next_bin, max_bin] 均匀）+ 令牌桶速率平滑
        shaper = Shaper(target_rate=RATE_MBPS * 1e6 / 8, mode="random",
                        seed=SEED)
    # sm9_raw：无整形

    arrives = []               # (ts, frame_len)
    send_ts = 0.0
    payload_bytes = 0
    frame_bytes = 0
    padded_bytes = 0
    t0 = time.perf_counter()
    for off, plen in tl:
        send_ts = off
        payload = rand_bytes(plen, f"{flow_type}_{scheme}_{int(off*1000)}")
        if scheme == "tls_baseline":
            nonce_ctr[0] += 1
            nonce = nonce_ctr[0].to_bytes(12, "big")
            ct = aesgcm.encrypt(nonce, payload, record_headers())
            frame = record_headers() + len(ct).to_bytes(2, "big") + ct
            frame_len = len(frame)
            gap = rng.uniform(0.5, 1.5) * (plen * 8 / (RATE_MBPS * 1e6))
        elif scheme == "sm9_shaped":
            padded = shaper.shape_length(plen)
            delay = shaper.delay_for(padded)
            frame_len = padded
            gap = delay
            padded_bytes += padded - plen
        else:
            frame_len = plen
            gap = plen * 8 / (RATE_MBPS * 1e6)
        payload_bytes += plen
        frame_bytes += frame_len
        arrives.append((send_ts + gap, frame_len))
    elapsed = time.perf_counter() - t0

    # 到达间隔序列（10min 轴）
    gaps = np.diff([a[0] for a in arrives])
    lens = np.array([a[1] for a in arrives])
    jitter_ms = float(np.std(gaps) * 1000.0)

    # 包长分布（N_BINS 桶，按 PAD_BINS 范围 64..2048）
    edges = np.linspace(64, 2048, N_BINS + 1)
    hist, _ = np.histogram(lens, bins=edges)
    dist = hist / hist.sum()
    entropy = float(-(dist[dist > 0] * np.log2(dist[dist > 0])).sum())

    # KL（整形后 vs 原始包长分布，均按同桶）
    def raw_dist(ftype):
        tl_r = flow_timeline(ftype, RATE_MBPS, QUICK_S if quick else SEGMENT_S)
        h, _ = np.histogram(np.array([p for _, p in tl_r]), bins=edges)
        d = h / h.sum()
        return d

    rawd = raw_dist(flow_type)
    kl = float((dist * np.log2((dist + 1e-12) / (rawd + 1e-12))).sum())

    gmin, gmax = float(gaps.min()), float(gaps.max())
    if gmax - gmin < 1e-9:
        gap_entropy = 0.0
    else:
        gh = np.histogram(gaps, bins=N_BINS,
                          range=(gmin, gmax + 1e-12))[0]
        gd = gh / gh.sum()
        gap_entropy = float(-(gd[gd > 0] * np.log2(gd[gd > 0])).sum())

    # 冗余率：整形开销/原始负载（sm9_shaped 才有意义）
    redundancy = (padded_bytes / max(1, payload_bytes)
                  if scheme == "sm9_shaped" else 0.0)

    p50 = float(np.percentile(lens, 50))
    p90 = float(np.percentile(lens, 90))
    throughput = payload_bytes * 8 / (dur * 1e6)
    return {
        "flow_type": flow_type, "scheme": scheme, "duration_s": dur,
        "throughput_mbps": throughput, "jitter_ms": jitter_ms,
        "pkt_len_entropy": entropy, "pkt_len_kl": kl,
        "gap_entropy": gap_entropy, "redundancy_rate": redundancy,
        "p50_ms": p50, "p90_ms": p90,
        "n_frames": len(arrives),
    }


def main():
    quick = "--quick" in sys.argv
    sm9 = SM9Engine()
    kdc_did = "didsm9:kdc@realm"
    dev = Device("b3-dev", "didsm9:user1:aaa", sm9)
    peer = Device("b3-peer", "didsm9:user1:aaa", sm9)
    ta = Tunnel(sm9, dev.did, peer.did)
    tb = Tunnel(sm9, peer.did, dev.did)
    state, r_init = ta.handshake_initiator()
    r_resp, key_b = tb.handshake_responder(r_init)
    key_a = ta.handshake_finish(state, r_resp)

    tls_key = AESGCM.generate_key(bit_length=256)
    rows = []
    for ftype in FLOW_TYPES:
        for scheme in SCHEMES:
            r = run_segment(sm9, ftype, scheme, tls_key=tls_key, quick=quick)
            rows.append(r)
            print(f"  {ftype:<8} {scheme:<12} n={r['n_frames']:>6} "
                  f"thr={r['throughput_mbps']:.2f}Mbps "
                  f"jitter={r['jitter_ms']:.2f}ms "
                  f"H(len)={r['pkt_len_entropy']:.2f} KL={r['pkt_len_kl']:.3f} "
                  f"redun={r['redundancy_rate']*100:.1f}% "
                  f"p50={r['p50_ms']:.0f}B p90={r['p90_ms']:.0f}B")

    shaped = [r for r in rows if r["scheme"] == "sm9_shaped"]
    avg_redun = np.mean([r["redundancy_rate"] for r in shaped])
    summary = [{
        "flow_types": FLOW_TYPES, "schemes": SCHEMES,
        "segment_s": QUICK_S if quick else SEGMENT_S,
        "rate_mbps": RATE_MBPS, "avg_redun_shaped": float(avg_redun),
        "tls_note": "TLS1.3 记录层模拟（AES-256-GCM 真实加解密）",
    }]
    run_id = time.strftime("%Y%m%d_%H%M%S") + f"_{time.time_ns() % 1000000000:09d}"
    out_dir = RESULTS / f"formal_v2_{run_id}"
    out_dir.mkdir(parents=True, exist_ok=False)
    write_csv(out_dir / "expB3_tunnel_shaping.csv", rows)
    write_csv(out_dir / "expB3_summary.csv", summary)
    csv_meta(out_dir / "expB3_tunnel_shaping.csv", {"seed": SEED})
    csv_meta(out_dir / "expB3_summary.csv", {"seed": SEED})


if __name__ == "__main__":
    main()