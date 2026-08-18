"""
C2 签名链性能：并发 100/500（1000 参数预留）req/s；本文 vs OAuth 基线。
输出：expC2_performance.csv（scheme, concurrency, p50_ms, p90_ms, p99_ms,
      qps, msg_bytes）
"""

import json
import sys
import threading
import time
from pathlib import Path

import numpy as np

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from core.claims_checker import ClaimsChecker
from core.common import SEED, csv_meta, write_csv
from core.did import make_user_did
from core.kdc import KDC
from core.mcp_agent import MCPAgent
from core.mcp_protocol import build_tools_call, inject_tickets
from core.mcp_server import MCPServer
from core.oauth_baseline import OAuthBaseline
from core.sm9_engine import SM9Engine
from core.st_ticket import STService, netperm_defaults

SERVICE = "mcp-server@realm"
CONCURRENCIES = [100, 500]          # 1000 参数预留（--conc1000）
N_REQ = 1000
RESULTS = Path(__file__).resolve().parent.parent / "results"


def run_ours_bench(sm9, kdc, agent, netperm, claims, concurrency, n_req):
    st = STService(sm9, kdc.kdc_did)
    server = MCPServer(sm9, st, SERVICE,
                       claims_checker=ClaimsChecker(
                           tools=["file.read"], actions=["read"]),
                       tools={"file.read": lambda a: {"ok": 1}})
    lat = []
    lock = threading.Lock()
    last = {}

    def worker(wid):
        my_agent = MCPAgent(f"docker{55550000 + wid:x}", "user1", sm9, kdc,
                            user_did=make_user_did("user1"))
        my_agent.register()
        for i in range(n_req // concurrency):
            my_agent.obtain_tickets(SERVICE, netperm, claims)
            cmd = {"tool": "file.read", "action": "read",
                   "args": {"path": f"/d/{wid}/{i}"}}
            t0 = time.perf_counter()
            ts = time.time()
            sa, su = my_agent.sign_chain(cmd, ts, f"r{wid}_{i}", {"s": "x"})
            msg = build_tools_call(f"r{wid}_{i}", "file.read", cmd["args"],
                                   extra={"cmd": cmd, "ts": ts,
                                          "ctx": {"s": "x"},
                                          "sig_agent": sa.hex(),
                                          "sig_user": su.hex(),
                                          "agent_did": my_agent.agent_did,
                                          "user_did": my_agent.user_did})
            headers = inject_tickets(msg, my_agent.st_data,
                                     my_agent.st_net)
            resp = server.handle_call(msg, headers)
            assert "result" in resp
            with lock:
                lat.append((time.perf_counter() - t0) * 1000.0)
                last["msg"] = msg
                last["headers"] = headers

    threads = [threading.Thread(target=worker, args=(w,))
               for w in range(concurrency)]
    t0 = time.perf_counter()
    for t in threads:
        t.start()
    for t in threads:
        t.join()
    elapsed = time.perf_counter() - t0
    lats = np.array(lat)
    # 消息尺寸：取最后一次请求的报文+头部（含双 ST 与双签名）
    msg_bytes = len(json.dumps(last["msg"]).encode()) + \
        len(json.dumps(last["headers"]).encode())
    return {
        "scheme": "ours", "concurrency": concurrency,
        "p50_ms": float(np.percentile(lats, 50)),
        "p90_ms": float(np.percentile(lats, 90)),
        "p99_ms": float(np.percentile(lats, 99)),
        "qps": len(lats) / elapsed,
        "msg_bytes": msg_bytes,
    }


def run_oauth_bench(oa, token, concurrency, n_req):
    lat = []
    lock = threading.Lock()
    last = {}

    def worker(wid):
        for i in range(n_req // concurrency):
            cmd = {"tool": "file.read", "action": "read",
                   "args": {"path": f"/d/{wid}/{i}"}}
            t0 = time.perf_counter()
            oa.call_tool(token, "mcp-client", cmd)
            with lock:
                lat.append((time.perf_counter() - t0) * 1000.0)

    threads = [threading.Thread(target=worker, args=(w,))
               for w in range(concurrency)]
    t0 = time.perf_counter()
    for t in threads:
        t.start()
    for t in threads:
        t.join()
    elapsed = time.perf_counter() - t0
    lats = np.array(lat)
    cmd = {"tool": "file.read", "action": "read", "args": {}}
    return {
        "scheme": "oauth", "concurrency": concurrency,
        "p50_ms": float(np.percentile(lats, 50)),
        "p90_ms": float(np.percentile(lats, 90)),
        "p99_ms": float(np.percentile(lats, 99)),
        "qps": len(lats) / elapsed,
        "msg_bytes": len(json.dumps(cmd).encode()) + 64,   # token 头部
    }


def main():
    debug = "--debug" in sys.argv
    quick = "--quick" in sys.argv
    if debug:
        print("[debug] expC2 main start")

    conc = ([10, 50] if quick else CONCURRENCIES)
    if "--conc1000" in sys.argv:
        conc = conc + [1000]          # D3：1000 预留参数

    sm9 = SM9Engine()
    kdc = KDC(sm9)
    user_did = make_user_did("user1")
    kdc.register_user(user_did)
    netperm = netperm_defaults()
    netperm["services"] = [SERVICE]
    claims = {"tools": ["file.read"], "actions": ["read"]}
    agent = MCPAgent("docker4444444444444444", "user1", sm9, kdc,
                     user_did=user_did)
    agent.register()

    oa = OAuthBaseline(cache_auth_state=True)
    oa.register_client("mcp-client")
    code = oa.authorize("mcp-client", ["mcp-server"], "v")
    token = oa.exchange("mcp-client", code, "v")

    n_req = 50 if quick else N_REQ
    rows = []
    for c in conc:
        r = run_ours_bench(sm9, kdc, agent, netperm, claims, c, n_req)
        rows.append(r)
        print(f"  ours c={c}: p50={r['p50_ms']:.1f}ms p90={r['p90_ms']:.1f}ms "
              f"p99={r['p99_ms']:.1f}ms qps={r['qps']:.0f} "
              f"msg={r['msg_bytes']}B")
    for c in conc:
        r = run_oauth_bench(oa, token, c, n_req)
        rows.append(r)
        print(f"  oauth c={c}: p50={r['p50_ms']:.2f}ms "
              f"p90={r['p90_ms']:.2f}ms p99={r['p99_ms']:.2f}ms "
              f"qps={r['qps']:.0f} msg={r['msg_bytes']}B")

    write_csv(RESULTS / "expC2_performance.csv", rows)
    csv_meta(RESULTS / "expC2_performance.csv", {"seed": SEED,
                                                 "n_req": n_req,
                                                 "concurrency": conc})


if __name__ == "__main__":
    main()