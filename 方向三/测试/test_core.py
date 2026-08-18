"""方向三 core 单测：双 ST / 双签名链 / 四步验证 / 网关 / OAuth 缺陷 / 审计链。
对应《代码汇总版》§5.5 验收项 3/4/5/6/7。
"""

import json
import sys
import time
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from core.audit_logger import AuditLogger
from core.claims_checker import ClaimsChecker
from core.common import rand_bytes
from core.did import make_user_did
from core.kdc import KDC
from core.mcp_agent import MCPAgent, env_id
from core.mcp_gateway import MCPGateway, request_ticket_id
from core.mcp_protocol import (HEADER_ST_DATA, HEADER_ST_NET, build_tools_call,
                               inject_tickets, parse_request)
from core.mcp_server import MCPServer
from core.noauth_baseline import NoAuthBaseline
from core.oauth_baseline import OAuthBaseline
from core.sm9_engine import SM9Engine
from core.st_ticket import (REALM, MAX_SKEW, STService, TICKET_TTL,
                            netperm_defaults)

SERVICE = "mcp-server@realm"
TOOLS = ["file.read", "file.write", "db.query", "agent.run"]
ACTIONS = ["read", "write", "execute", "manage"]
NET_PERM = netperm_defaults()
NET_PERM["services"] = ["mcp-gateway"]


@pytest.fixture
def world():
    sm9 = SM9Engine()
    kdc = KDC(sm9)
    user_did = make_user_did("user1")
    kdc.register_user(user_did)
    agent = MCPAgent("docker0123456789abcdef", "user1", sm9, kdc,
                     user_did=user_did)
    assert agent.register()
    claims = {"tools": ["file.read", "db.query"], "actions": ["read", "execute"]}
    agent.obtain_tickets(SERVICE, NET_PERM, claims)
    st = STService(sm9, kdc.kdc_did)
    checker = ClaimsChecker(tools=TOOLS, actions=ACTIONS)
    server = MCPServer(sm9, st, SERVICE, claims_checker=checker)
    gw = MCPGateway(sm9, st, SERVICE)
    return dict(sm9=sm9, kdc=kdc, agent=agent, server=server, gw=gw,
                claims=claims)


# ----------------------------------------------------------------------
# 双 ST（验收 7）
# ----------------------------------------------------------------------

def test_dual_ticket_kinds(world):
    st_net, st_data = world["agent"].st_net, world["agent"].st_data
    assert st_net["st_kind"] == "net"
    assert st_data["st_kind"] == "data"
    assert st_net["perm"]["services"] == ["mcp-gateway"]
    assert st_data["perm"]["claims"]["tools"] == ["file.read", "db.query"]


def test_st_expired_rejected(world):
    t = time.time()
    st = world["kdc"].issue_dual_ticket(
        world["agent"].agent_did, SERVICE, "data",
        {"claims": world["claims"]},
        times={"start": t - 2000, "end": t - 1000})
    r = world["server"].st.verify_st(st, SERVICE, st_kind="data")
    assert not r["ok"] and r["error"] == "ticket_out_of_window"


def test_st_future_skew_beyond_30min_rejected(world):
    t = time.time()
    st = world["kdc"].issue_dual_ticket(
        world["agent"].agent_did, SERVICE, "data",
        {"claims": world["claims"]},
        times={"start": t + MAX_SKEW + 60, "end": t + 4000})
    r = world["server"].st.verify_st(st, SERVICE, st_kind="data")
    assert not r["ok"] and r["error"] == "ticket_out_of_window"


def test_st_replay_second_rejected(world):
    st = world["agent"].st_data
    cache = {}
    assert world["server"].st.verify_st(st, SERVICE, st_kind="data",
                                        replay_cache=cache)["ok"]
    r = world["server"].st.verify_st(st, SERVICE, st_kind="data",
                                     replay_cache=cache)
    assert not r["ok"] and r["error"] == "replay_detected"


def test_st_forged_sig_rejected(world):
    evil = SM9Engine()
    evil_kdc = "didsm9:evil:ff"
    evil.derive_sk(evil_kdc)
    forged = dict(world["agent"].st_data)
    payload = {k: v for k, v in forged.items() if k != "sig"}
    forged["sig"] = evil.sign(evil_kdc, json.dumps(
        payload, sort_keys=True).encode()).hex()
    r = world["server"].st.verify_st(forged, SERVICE, st_kind="data")
    assert not r["ok"] and r["error"] == "signature_invalid"


# ----------------------------------------------------------------------
# 四步验证（验收 3）
# ----------------------------------------------------------------------

def make_req(world, tool="file.read", action="read", ts=None, mutate=None):
    agent = world["agent"]
    cmd = {"tool": tool, "action": action, "args": {"path": "/tmp/x"}}
    ts = ts if ts is not None else time.time()
    req_id = rand_bytes(8, "test").hex()
    ctx = {"session": "test"}
    sig_a, sig_u = agent.sign_chain(cmd, ts, req_id, ctx)
    msg = build_tools_call(req_id, tool, cmd["args"], extra={
        "cmd": cmd, "ts": ts, "ctx": ctx,
        "sig_agent": sig_a.hex(), "sig_user": sig_u.hex(),
        "agent_did": agent.agent_did, "user_did": agent.user_did,
    })
    headers = inject_tickets(msg, agent.st_data, agent.st_net)
    if mutate:
        mutate(msg, headers)
    return msg, headers


def test_normal_call_passes(world):
    msg, headers = make_req(world)
    resp = world["server"].handle_call(msg, headers)
    assert resp["result"]["executed"] is True


def test_tampered_cmd_rejected(world):
    msg, headers = make_req(world, mutate=lambda m, h: (
        m["params"]["cmd"]["args"].update({"path": "/etc/passwd"})))
    resp = world["server"].handle_call(msg, headers)
    assert "error" in resp


def test_unsigned_replay_rejected(world):
    msg, headers = make_req(world)
    assert world["server"].handle_call(msg, headers)["result"]
    # 原样重放：ST 单次缓存 → 拒绝
    resp = world["server"].handle_call(msg, headers)
    assert "error" in resp


def test_privilege_escalation_rejected(world):
    msg, headers = make_req(world, tool="agent.run", action="execute")
    resp = world["server"].handle_call(msg, headers)
    assert "error" in resp and "perm_denied" in resp["error"]["message"]


def test_stolen_st_wrong_private_key_rejected(world):
    """DID 冒用：合法票据 + 错误设备私钥。"""
    sm9, kdc = world["sm9"], world["kdc"]
    attacker = MCPAgent("docker9999999999999999", "user1", sm9, kdc)
    attacker.st_net = world["agent"].st_net
    attacker.st_data = world["agent"].st_data
    cmd = {"tool": "file.read", "action": "read", "args": {}}
    ts = time.time()
    sig_a, sig_u = attacker.sign_chain(cmd, ts, "r1", {"session": "s"})
    msg = build_tools_call("r1", "file.read", {}, extra={
        "cmd": cmd, "ts": ts, "ctx": {"session": "s"},
        "sig_agent": sig_a.hex(), "sig_user": sig_u.hex(),
        "agent_did": attacker.agent_did, "user_did": attacker.user_did,
    })
    headers = inject_tickets(msg, attacker.st_data, attacker.st_net)
    resp = world["server"].handle_call(msg, headers)
    assert "error" in resp


# ----------------------------------------------------------------------
# 双签名链（验收 4）
# ----------------------------------------------------------------------

def test_chain_order_correct(world):
    agent = world["agent"]
    cmd = {"tool": "file.read", "action": "read", "args": {}}
    ts, req_id, ctx = time.time(), "r1", {"session": "s"}
    sig_a, sig_u = agent.sign_chain(cmd, ts, req_id, ctx)
    assert len(sig_a) == 97 and len(sig_u) == 97
    # 链序语义：σ_user 的输入含 σ_agent（先设备后用户）
    from core.common import sm3
    cmd_b = json.dumps(cmd, sort_keys=True).encode()
    m1 = sm3(cmd_b + int(ts).to_bytes(8, "big") + req_id.encode())
    assert agent.sm9.verify(agent.agent_did, m1, sig_a)
    m2 = sm3(cmd_b + sig_a + json.dumps(ctx, sort_keys=True).encode())
    assert agent.sm9.verify(agent.user_did, m2, sig_u)


def test_remove_user_sig_layer_fails(world):
    msg, headers = make_req(world)
    del msg["params"]["sig_user"]
    resp = world["server"].handle_call(msg, headers)
    assert "error" in resp


# ----------------------------------------------------------------------
# 网关（验收 8 场景 C 支撑）
# ----------------------------------------------------------------------

def test_gateway_admit_and_forward(world):
    msg, headers = make_req(world)
    r = world["gw"].forward(msg, headers)
    assert r["result"]["forwarded"] is True
    assert world["gw"].forwarded == 1


def test_gateway_st_net_expired_rejected(world):
    msg, headers = make_req(world)
    headers[HEADER_ST_NET] = json.dumps(
        {**world["agent"].st_net, "times": {"start": time.time() - 2000,
                                            "end": time.time() - 1000}})
    r = world["gw"].forward(msg, headers)
    assert "error" in r


def test_gateway_ticket_id_audit(world):
    msg, headers = make_req(world)
    tid = request_ticket_id(msg, headers)
    assert tid == world["agent"].st_net["ticket_id"]


# ----------------------------------------------------------------------
# OAuth 基线缺陷（验收 5）
# ----------------------------------------------------------------------

def test_oauth_caller_confusion_blocked_rate_approx_0(world):
    oa = OAuthBaseline(cache_auth_state=True)
    oa.register_client("victim")
    oa.register_client("attacker")
    code = oa.authorize("victim", ["file.read"], "verifier1")
    token = oa.exchange("victim", code, "verifier1")
    # 调用者混淆：attacker 用 victim 的 token 调用
    blocked = 0
    for i in range(100):
        r = oa.call_tool(token, "attacker", {"tool": "file.read"})
        if not r["ok"]:
            blocked += 1
    assert blocked == 0            # 基线缺陷：授权态缓存复用 → 全部放行
    assert oa.call_tool(token, "victim", {"tool": "file.read"})["ok"]


def test_oauth_revoked_token_rejected():
    oa = OAuthBaseline()
    oa.register_client("c1")
    code = oa.authorize("c1", ["db.query"], "v")
    token = oa.exchange("c1", code, "v")
    oa.revoke(token)
    assert not oa.call_tool(token, "c1", {"tool": "db.query"})["ok"]


def test_noauth_allows_everything():
    na = NoAuthBaseline()
    assert na.call_tool({"tool": "agent.run"})["ok"]
    assert na.calls == 1


# ----------------------------------------------------------------------
# 协议层（验收 10 常量可查）
# ----------------------------------------------------------------------

def test_protocol_headers():
    msg = build_tools_call("r1", "file.read", {"p": 1})
    assert msg["method"] == "tools/call"
    st = {"ticket_id": "abc"}
    headers = inject_tickets(msg, st, {"ticket_id": "def"})
    assert headers[HEADER_ST_DATA] == json.dumps(st, sort_keys=True)
    parsed = parse_request(msg, headers)
    assert parsed["tool"] == "file.read"
    assert parsed["st_data"]["ticket_id"] == "abc"
    assert parsed["st_net"]["ticket_id"] == "def"


def test_env_id_types():
    ids = [env_id("docker"), env_id("linux"), env_id("windows"),
           env_id("vmware")]
    assert len(ids[0]) == 64
    assert len(ids[1]) == 32
    assert len(ids[2]) == 36
    assert len(ids[3]) == 36
    assert len(set(ids)) == 4


def test_audit_chain_ticket_id(world):
    logger = AuditLogger("/tmp/exp3_audit_test.log")
    logger.clear()
    st = STService(world["sm9"], world["kdc"].kdc_did, audit_logger=logger)
    server = MCPServer(world["sm9"], st, SERVICE,
                       claims_checker=ClaimsChecker(tools=TOOLS,
                                                    actions=ACTIONS),
                       audit_logger=logger)
    msg, headers = make_req(world)
    resp = server.handle_call(msg, headers)
    assert resp["result"]["executed"] is True
    rows = logger.entries()
    tids = [r["ticket_id"] for r in rows if r.get("ticket_id")]
    assert len(tids) == 3          # st_net + st_data 验票 + mcp_call 三条审计
    # st_data 的 ticket_id 贯通（后两条一致）
    assert tids[1] == tids[2] == world["agent"].st_data["ticket_id"]