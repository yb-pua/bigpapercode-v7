"""
C1 分级授权功能：场景 A（数据查询 ST_data 四步验证）/ 场景 B（协同任务
多 Agent 链式）/ 场景 C（跨域转发 mcp_gateway ST_net）；审计 ticket_id 贯通。
输出：expC1_scenarios.csv、expC1_audit.csv
"""

import sys
import time
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent.parent))

from core.audit_logger import AuditLogger
from core.claims_checker import ClaimsChecker
from core.common import SEED, csv_meta, rand_bytes, write_csv
from core.did import make_user_did
from core.kdc import KDC
from core.mcp_agent import MCPAgent
from core.mcp_gateway import MCPGateway
from core.mcp_protocol import build_tools_call, inject_tickets
from core.mcp_server import MCPServer
from core.p2p_handoff import issue_simulated_p2p_session
from core.sm9_engine import SM9Engine
from core.st_ticket import STService, netperm_defaults
from 实验.run_support import start_run, write_manifest

SERVICE = "mcp-server@realm"
GW_SERVICE = "mcp-gateway@realm"
TOOLS = ["file.read", "file.write", "db.query", "agent.run"]
ACTIONS = ["read", "write", "execute", "manage"]
RESULTS = Path(__file__).resolve().parent / "结果"
AUDIT_LOG = Path("/tmp/exp3_c1_audit.log")


def build_signed(agent, cmd, ts=None, req_id=None, ctx=None):
    ts = ts if ts is not None else time.time()
    req_id = req_id or rand_bytes(8, "c1").hex()
    ctx = ctx or {"session": agent.env_id[:12]}
    sig_a, sig_u = agent.sign_chain(cmd, ts, req_id, ctx)
    msg = build_tools_call(req_id, cmd["tool"], cmd["args"], extra={
        "cmd": cmd, "ts": ts, "ctx": ctx,
        "sig_agent": sig_a.hex(), "sig_user": sig_u.hex(),
        "agent_did": agent.agent_did, "user_did": agent.user_did,
    })
    headers = inject_tickets(msg, agent.st_data, agent.st_net)
    return msg, headers


def main():
    debug = "--debug" in sys.argv
    quick = "--quick" in sys.argv
    out_dir, run_state = start_run(RESULTS)
    if debug:
        print("[debug] expC1 main start")

    sm9 = SM9Engine()
    kdc = KDC(sm9)
    user_did = make_user_did("user1")
    kdc.register_user(user_did)
    netperm = netperm_defaults()
    netperm["services"] = [GW_SERVICE]
    claims = {"tools": ["file.read", "db.query"], "actions": ["read"]}

    agent_a = MCPAgent("docker1111111111111111", "user1", sm9, kdc,
                       user_did=user_did)
    agent_b = MCPAgent("docker2222222222222222", "user1", sm9, kdc,
                       user_did=user_did)
    agent_a.register()
    agent_b.register()
    session_a = issue_simulated_p2p_session(
        kdc, agent_a.agent_did, user_did, netperm, label="c1-agent-a")
    session_b = issue_simulated_p2p_session(
        kdc, agent_b.agent_did, user_did, netperm, label="c1-agent-b")
    agent_a.obtain_tickets(SERVICE, netperm, claims, session_a)
    agent_b.obtain_tickets(SERVICE, netperm, claims, session_b)

    logger = AuditLogger(str(AUDIT_LOG))
    logger.clear()
    st = STService(sm9, kdc.kdc_did, audit_logger=logger)
    checker = ClaimsChecker(tools=TOOLS, actions=ACTIONS)
    server = MCPServer(sm9, st, SERVICE, kdc=kdc, claims_checker=checker,
                       audit_logger=logger,
                       tools={"file.read": lambda a: {"data": "ok"}})
    gw = MCPGateway(sm9, st, GW_SERVICE, audit_logger=logger)

    scenario_rows = []
    audit_tids = []

    # ------------------------------------------------------------------
    # 场景 A：数据查询（单 Agent 四步验证）
    # ------------------------------------------------------------------
    t0 = time.perf_counter()
    ok_a = True
    n_a = 6 if quick else 30
    for i in range(n_a):
        agent_a.obtain_tickets(SERVICE, netperm, claims, session_a)
        msg, headers = build_signed(agent_a, {
            "tool": "file.read", "action": "read",
            "args": {"path": f"/data/{i}"}})
        resp = server.handle_call(msg, headers)
        if "result" not in resp:
            ok_a = False
    lat_a = (time.perf_counter() - t0) * 1000.0 / n_a
    scenario_rows.append({"scenario": "A_data_query", "steps": 4,
                          "passed": 1 if ok_a else 0, "reject_reason": "",
                          "latency_ms": round(lat_a, 2)})
    audit_tids.append(agent_a.st_data["ticket_id"])

    # ------------------------------------------------------------------
    # 场景 B：协同任务（多 Agent 链式：A 查询 → B 汇总）
    # ------------------------------------------------------------------
    ok_b = True
    t0 = time.perf_counter()
    n_b = 3 if quick else 10
    for i in range(n_b):
        agent_a.obtain_tickets(SERVICE, netperm, claims, session_a)
        msg_a, headers_a = build_signed(agent_a, {
            "tool": "db.query", "action": "read",
            "args": {"sql": f"select {i}"}})
        if "result" not in server.handle_call(msg_a, headers_a):
            ok_b = False
        agent_b.obtain_tickets(SERVICE, netperm, claims, session_b)
        msg_b, headers_b = build_signed(agent_b, {
            "tool": "db.query", "action": "read",
            "args": {"sql": f"aggregate {i}"}})
        if "result" not in server.handle_call(msg_b, headers_b):
            ok_b = False
    lat_b = (time.perf_counter() - t0) * 1000.0 / (2 * n_b)
    scenario_rows.append({"scenario": "B_collab_chain", "steps": 8,
                          "passed": 1 if ok_b else 0, "reject_reason": "",
                          "latency_ms": round(lat_b, 2)})
    audit_tids += [agent_a.st_data["ticket_id"], agent_b.st_data["ticket_id"]]

    # ------------------------------------------------------------------
    # 场景 C：跨域转发（网关 ST_net 验证 + 转发；载荷不解密）
    # ------------------------------------------------------------------
    ok_c = True
    t0 = time.perf_counter()
    n_c = 3 if quick else 10
    for i in range(n_c):
        agent_a.obtain_tickets(GW_SERVICE, netperm, claims, session_a)
        msg, headers = build_signed(agent_a, {
            "tool": "file.read", "action": "read", "args": {}})
        r = gw.forward(msg, headers,
                       expected_net_perm={"services": [GW_SERVICE]})
        if "error" in r:
            ok_c = False
    lat_c = (time.perf_counter() - t0) * 1000.0 / n_c
    scenario_rows.append({"scenario": "C_cross_domain", "steps": 2,
                          "passed": 1 if ok_c else 0, "reject_reason": "",
                          "latency_ms": round(lat_c, 2)})
    audit_tids.append(agent_a.st_net["ticket_id"])

    # 反例：ST_net 过期 → 网关拒绝
    expired_pair = rand_bytes(16, "c1-expired-pair").hex()
    agent_a.st_net = kdc.st.issue_dual_ticket(
        agent_a.agent_did, GW_SERVICE, "net", netperm,
        times={"start": time.time() - 3000, "end": time.time() - 2000},
        pair_id=expired_pair, user_did=user_did,
        parent_ticket_id=session_a["parent_ticket_id"])
    msg, headers = build_signed(agent_a, {"tool": "file.read", "action": "read",
                                          "args": {}})
    r = gw.forward(msg, headers)
    scenario_rows.append({"scenario": "C_expired_st_net_rejected", "steps": 1,
                          "passed": 1 if "error" in r else 0,
                          "reject_reason": "st_net expired",
                          "latency_ms": 0.0})

    # ------------------------------------------------------------------
    # 审计贯通：全链 ticket_id 匹配率 / 缺失率
    # ------------------------------------------------------------------
    entries = logger.entries()
    log_tids = [e["ticket_id"] for e in entries if e.get("ticket_id")]
    matched = sum(1 for t in audit_tids if t in log_tids)
    chain_rate = matched / max(1, len(audit_tids))
    missing = sum(1 for e in entries if not e.get("ticket_id"))
    audit_rows = [{
        "calls": len(entries),
        "chain_complete_rate": round(chain_rate, 4),
        "audit_missing_rate": round(missing / max(1, len(entries)), 4),
    }]

    write_csv(out_dir / "expC1_scenarios.csv", scenario_rows)
    write_csv(out_dir / "expC1_audit.csv", audit_rows)
    meta = {"seed": SEED, "mode": "quick" if quick else "formal",
            "n_a": n_a, "n_b": n_b, "n_c": n_c}
    csv_meta(out_dir / "expC1_scenarios.csv", meta)
    csv_meta(out_dir / "expC1_audit.csv", meta)
    for s in scenario_rows:
        print(f"  {s['scenario']:<28} passed={s['passed']} "
              f"latency={s['latency_ms']}ms")
    print(f"  audit: calls={audit_rows[0]['calls']} "
          f"chain_rate={audit_rows[0]['chain_complete_rate']} "
          f"missing_rate={audit_rows[0]['audit_missing_rate']}")
    write_manifest(
        out_dir, run_state, mode="quick" if quick else "formal", seed=SEED,
        parameters={"n_a": n_a, "n_b": n_b, "n_c": n_c},
        simulated_components=["MCP JSON-RPC tools/call",
                              "Direction-2 session credential handoff",
                              "in-process MCP gateway/tool execution"],
    )


if __name__ == "__main__":
    main()
