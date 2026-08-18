"""
B2 扩展性（D3/D4）：N=10/50/100/200 准入时延 + 聚合吞吐/e2e 时延/丢包
+ OpenVPN 基线（D1-A：--dev null 控制面，数据面标注模拟，B 方案参数预留）
+ 故障注入（kill 中继 vs kill 网关）。

输出：
    expB2_scalability.csv  (N, scheme, admit_p50, admit_p90, throughput_mbps,
                            e2e_latency_ms, loss_rate, relay_cpu_pct, relay_mem_mb)
    expB2_failover.csv     (scheme, failure_point, session_break_range, recovery_time)
    expB2_summary.csv      (汇总 + OpenVPN 基线模式标注)

模拟标注：隧道数据面为本机内存模拟（真实 SM4 加密 + 转发路径），
每设备恒定背景流 1Mbps；OpenVPN 数据面标注 simulated（--dev null 控制面）。
"""

import json
import socket
import subprocess
import sys
import tempfile
import threading
import time
from pathlib import Path

import numpy as np

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from core.common import (SEED, csv_meta, get_rng, rand_bytes, stats_ms,
                         write_csv)
from core.device import Device
from core.kdc import KDC
from core.relay import Relay
from core.sm9_engine import SM9Engine
from core.st_ticket import netperm_defaults
from core.tunnel import Tunnel

SCALE_GRADIENTS = [10, 50, 100, 200]
BG_MBPS_PER_DEV = 1.0
SAMPLING_S = 20.0
RESULTS = Path(__file__).resolve().parent.parent / "results"


# ----------------------------------------------------------------------
# 本文方案：N 台设备准入 + 隧道流量模拟
# ----------------------------------------------------------------------

def run_ours(sm9, kdc, relay, netperm, n: int, duration: float = SAMPLING_S):
    """准入全部 N 台 → 每设备 1Mbps 背景流 + 测试流 → 吞吐/时延/丢包。"""
    devices = []
    admit_times = []
    for i in range(n):
        dev = Device(f"scal-dev-{i:04d}", "didsm9:user1:aaa", sm9)
        assert dev.enroll(kdc)
        dev.obtain_authorization(kdc, netperm)
        t0 = time.perf_counter()
        ok = admission(relay, dev)
        admit_times.append((time.perf_counter() - t0) * 1000.0)
        if not ok:
            raise RuntimeError(f"admission failed at i={i}")
        devices.append(dev)

    # 隧道建立（每设备与同网 peer 协商）
    tunnels = []
    peer = Device(f"scal-peer", "didsm9:user1:aaa", sm9)
    for dev in devices:
        ta = Tunnel(sm9, dev.did, peer.did)
        tb = Tunnel(sm9, peer.did, dev.did)
        state, r_init = ta.handshake_initiator()
        r_resp, key_b = tb.handshake_responder(r_init)
        key_a = ta.handshake_finish(state, r_resp)
        tunnels.append((ta, key_a, "10.200.1.1"))

    # 流量模拟：每设备 1Mbps 背景流（1448B 帧 → ~86 pkt/s）+ 采样
    pkt_rate = int(BG_MBPS_PER_DEV * 1e6 / 8 / 1448)
    n_sent = np.zeros(n, dtype=np.int64)
    n_recv = np.zeros(n, dtype=np.int64)
    e2e_lat = []
    lock = threading.Lock()
    stop = threading.Event()

    def sender(idx, ta, key, vaddr):
        seq = 0
        while not stop.is_set():
            payload = rand_bytes(1400, f"bg_{idx}_{seq % 10}")
            t0 = time.perf_counter()
            frame = ta.frame_encrypt(payload, vaddr, seq, key=key)
            n_sent[idx] += 1
            # 转发路径（模拟中继）：立即送达（本机回环）
            try:
                v, p, s = ta.frame_decrypt(frame, key=key)
                e2e = (time.perf_counter() - t0) * 1000.0
                with lock:
                    e2e_lat.append(e2e)
                n_recv[idx] += 1
            except Exception:
                pass
            seq += 1
            time.sleep(1.0 / pkt_rate)

    threads = []
    for i, (ta, key, vaddr) in enumerate(tunnels):
        t = threading.Thread(target=sender, args=(i, ta, key, vaddr),
                             daemon=True)
        t.start()
        threads.append(t)
    time.sleep(duration)
    stop.set()
    for t in threads:
        t.join()

    total_sent = int(n_sent.sum())
    total_recv = int(n_recv.sum())
    throughput_mbps = total_recv * 1448 * 8 / (duration * 1e6)
    loss_rate = 1.0 - total_recv / max(1, total_sent)
    e2e = stats_ms(e2e_lat)
    admit = stats_ms(admit_times)
    return {
        "admit_p50_ms": admit["p50_ms"],
        "admit_p90_ms": admit["p90_ms"],
        "throughput_mbps": throughput_mbps,
        "e2e_latency_ms": e2e["p50_ms"],
        "loss_rate": loss_rate,
    }


def admission(relay, dev):
    r1 = relay.begin_admission(dev.admission_round1(), "relay@realm")
    if not r1["ok"]:
        return False, r1
    r2 = dev.admission_round2(r1["challenge"])
    return relay.finish_admission(dev.admission_round1(), r1["challenge"],
                                  r2["sig"], r2["nonce"], r2["ts"],
                                  "relay@realm")["ok"]


# ----------------------------------------------------------------------
# OpenVPN 基线（D1-A：--dev null 控制面，数据面模拟标注；B 方案参数预留）
# ----------------------------------------------------------------------

OPENVPN_DATAPLANE_MODE = "simulated"   # D1-A 拍板；改 "real_tun" 需 sudo（预留 B）


def gen_openvpn_pki(workdir: Path):
    """自签 CA + server/client 证书（openssl）。"""
    ca_key = workdir / "ca.key"
    ca_crt = workdir / "ca.crt"
    for name, ext in (("server", "server_ext"), ("client", "client_ext")):
        key = workdir / f"{name}.key"
        csr = workdir / f"{name}.csr"
        crt = workdir / f"{name}.crt"
        subprocess.run(["openssl", "req", "-newkey", "rsa:2048", "-nodes",
                        "-keyout", str(key), "-out", str(csr), "-subj",
                        f"/CN={name}"], check=True, capture_output=True)
        subprocess.run(["openssl", "x509", "-req", "-in", str(csr), "-CA",
                        str(ca_crt), "-CAkey", str(ca_key), "-CAcreateserial",
                        "-out", str(crt), "-days", "1"], check=True,
                       capture_output=True)


def measure_openvpn_handshake(n: int) -> dict:
    """--dev null 控制面：server + n 个 client 完成 TLS 握手的时延。"""
    with tempfile.TemporaryDirectory() as td:
        td = Path(td)
        subprocess.run(["openssl", "req", "-x509", "-newkey", "rsa:2048",
                        "-nodes", "-keyout", str(td / "ca.key"),
                        "-out", str(td / "ca.crt"), "-days", "1",
                        "-subj", "/CN=test-ca"], check=True, capture_output=True)
        for name in ("server", "client"):
            key, csr, crt = td / f"{name}.key", td / f"{name}.csr", td / f"{name}.crt"
            subprocess.run(["openssl", "req", "-newkey", "rsa:2048", "-nodes",
                            "-keyout", str(key), "-out", str(csr),
                            "-subj", f"/CN={name}"], check=True,
                           capture_output=True)
            subprocess.run(["openssl", "x509", "-req", "-in", str(csr), "-CA",
                            str(td / "ca.crt"), "-CAkey", str(td / "ca.key"),
                            "-CAcreateserial", "-out", str(crt), "-days", "1"],
                           check=True, capture_output=True)
        port = 12941
        srv_log = td / "server.log"
        srv = subprocess.Popen([
            "openvpn", "--dev", "null", "--server", "10.8.0.0", "255.255.255.0",
            "--port", str(port), "--proto", "udp", "--ca", str(td / "ca.crt"),
            "--cert", str(td / "server.crt"), "--key", str(td / "server.key"),
            "--daemon", "--log-append", str(srv_log), "--verb", "3",
            "--ifconfig-noexec"], stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL)
        try:
            time.sleep(1.5)
            handshakes = []
            for i in range(n):
                cli_log = td / f"client{i}.log"
                t0 = time.perf_counter()
                subprocess.run([
                    "openvpn", "--dev", "null", "--client", "--remote",
                    "127.0.0.1", str(port), "--proto", "udp", "--ca",
                    str(td / "ca.crt"), "--cert", str(td / "client.crt"),
                    "--key", str(td / "client.key"), "--connect-retry", "0",
                    "--daemon", "--log-append", str(cli_log), "--verb", "3",
                    "--ifconfig-noexec"], check=True, timeout=60,
                    capture_output=True)
                # 等待握手完成（"Initialization Sequence Completed"）
                deadline = time.time() + 30
                done = False
                while time.time() < deadline:
                    log = cli_log.read_text(encoding="utf-8", errors="ignore")
                    if "Initialization Sequence Completed" in log:
                        done = True
                        break
                    time.sleep(0.1)
                handshakes.append((time.perf_counter() - t0) * 1000.0 if done else None)
                subprocess.run(["pkill", "-f", f"client{i}.log"],
                               capture_output=True)
            return {"openvpn_handshake_ms": handshakes}
        finally:
            subprocess.run(["pkill", "-f", "12941"], capture_output=True)
            subprocess.run(["pkill", "-f", f"{td}/client"],
                           capture_output=True)


# ----------------------------------------------------------------------
# 故障注入
# ----------------------------------------------------------------------

def run_failover(sm9, kdc, relay, netperm, n=50):
    """kill 中继（本文）→ 中断范围/恢复时间；OpenVPN kill 网关为标注模拟。"""
    devices = []
    for i in range(n):
        dev = Device(f"fo-dev-{i:04d}", "didsm9:user1:aaa", sm9)
        assert dev.enroll(kdc)
        dev.obtain_authorization(kdc, netperm)
        assert admission(relay, dev)
        devices.append(dev)

    # 中断范围：中继侧 admitted 数量 = 全部（kill 前）
    before = len(relay.admitted)
    relay.admitted.clear()                     # 模拟中继崩溃
    # 恢复时间：设备重新准入（重连）
    t0 = time.perf_counter()
    for dev in devices:
        assert admission(relay, dev)
    recovery = (time.perf_counter() - t0) * 1000.0
    return {
        "session_break_range": before,
        "recovery_time": recovery,
    }


def main():
    debug = "--debug" in sys.argv
    quick = "--quick" in sys.argv
    sm9 = SM9Engine()
    netperm = netperm_defaults()
    netperm["services"] = ["file-sync", "rtc"]
    netperm["bandwidth_mbps"] = 10.0

    gradients = [10] if quick else SCALE_GRADIENTS
    rows = []
    for n in gradients:
        kdc = KDC(sm9)
        kdc.register_user("didsm9:user1:aaa")
        relay = Relay(sm9, kdc, relay_id="relay-1")
        relay.setup_proxy()
        t0 = time.perf_counter()
        ours = run_ours(sm9, kdc, relay, netperm, n)
        elapsed = time.perf_counter() - t0
        rows.append({
            "N": n, "scheme": "st_ticket_sm9",
            "admit_p50_ms": ours["admit_p50_ms"],
            "admit_p90_ms": ours["admit_p90_ms"],
            "throughput_mbps": ours["throughput_mbps"],
            "e2e_latency_ms": ours["e2e_latency_ms"],
            "loss_rate": ours["loss_rate"],
            "relay_cpu_pct": 0.0,               # 本机回环模拟，不采样外部进程
            "relay_mem_mb": 0.0,
        })
        print(f"  N={n}: admit_p50={ours['admit_p50_ms']:.1f}ms "
              f"thr={ours['throughput_mbps']:.1f}Mbps "
              f"loss={ours['loss_rate']:.4f} elapsed={elapsed:.0f}s")

    # OpenVPN 基线（控制面握手，N=10 规模；数据面标注 simulated）
    try:
        ov = measure_openvpn_handshake(3 if quick else 10)
        ov_ok = [m for m in ov["openvpn_handshake_ms"] if m is not None]
        ov_p50 = float(np.percentile(ov_ok, 50)) if ov_ok else -1.0
        ov_p90 = float(np.percentile(ov_ok, 90)) if ov_ok else -1.0
        print(f"  openvpn handshake p50={ov_p50:.1f}ms (n={len(ov_ok)})")
    except Exception as e:
        print(f"  openvpn baseline failed: {type(e).__name__}: {e}")
        ov_p50 = ov_p90 = -1.0
    rows.append({
        "N": 10, "scheme": "openvpn",
        "admit_p50_ms": ov_p50, "admit_p90_ms": ov_p90,
        "throughput_mbps": -1.0,                # 数据面模拟（D1-A）
        "e2e_latency_ms": -1.0, "loss_rate": -1.0,
        "relay_cpu_pct": -1.0, "relay_mem_mb": -1.0,
    })

    # 故障注入
    kdc = KDC(sm9)
    kdc.register_user("didsm9:user1:aaa")
    relay = Relay(sm9, kdc, relay_id="relay-1")
    relay.setup_proxy()
    fo = run_failover(sm9, kdc, relay, netperm, n=10 if quick else 50)
    failover_rows = [
        {"scheme": "st_ticket_sm9", "failure_point": "relay_killed",
         "session_break_range": fo["session_break_range"],
         "recovery_time": fo["recovery_time"]},
        {"scheme": "openvpn", "failure_point": "gateway_killed",
         "session_break_range": -1, "recovery_time": -1.0,
         "note": "数据面标注模拟（D1-A）"},
    ]

    summary = [{
        "scale_gradients": gradients,
        "bg_mbps_per_dev": BG_MBPS_PER_DEV,
        "openvpn_mode": OPENVPN_DATAPLANE_MODE,
        "dataplane_note": "本机内存模拟：真实 SM4 加密+转发路径",
        "openvpn_handshake_p50_ms": ov_p50,
    }]

    write_csv(RESULTS / "expB2_scalability.csv", rows)
    write_csv(RESULTS / "expB2_failover.csv", failover_rows)
    write_csv(RESULTS / "expB2_summary.csv", summary)
    for f in ("expB2_scalability.csv", "expB2_failover.csv",
              "expB2_summary.csv"):
        csv_meta(RESULTS / f, {"seed": SEED,
                               "openvpn_dataplane": OPENVPN_DATAPLANE_MODE})


if __name__ == "__main__":
    main()