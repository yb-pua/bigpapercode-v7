"""
C3 指令攻击与正确性：≥500 条指令（正常60/篡改16/越权16/重放8），
三方案（无管控/OAuth/本文）各跑一遍；6 类攻击矩阵；三档消融。
输出：expC3_instruction_results.csv、expC3_attack_matrix.csv、
      expC3_ablation.csv
"""

import json
import sys
import time
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent.parent))

from core.claims_checker import ClaimsChecker
from core.common import SEED, csv_meta, rand_bytes, sm3, write_csv
from core.did import make_user_did
from core.kdc import KDC
from core.mcp_agent import MCPAgent
from core.mcp_protocol import build_tools_call, inject_tickets
from core.mcp_server import MCPServer
from core.noauth_baseline import NoAuthBaseline
from core.oauth_baseline import OAuthBaseline
from core.p2p_handoff import issue_simulated_p2p_session
from core.sm9_engine import SM9Engine
from core.st_ticket import STService, netperm_defaults
from 实验.run_support import start_run, write_manifest

SERVICE = "mcp-server@realm"
TOOLS = ["file.read", "file.write", "db.query", "agent.run"]
ACTIONS = ["read", "write", "execute", "manage"]
N_CMDS = 500
RATIOS = {"normal": 0.60, "tampered": 0.16, "priv_esc": 0.16, "replay": 0.08}
RESULTS = Path(__file__).resolve().parent / "结果"


def gen_commands(n=N_CMDS, seed=SEED):
    """确定性生成指令流：type ∈ normal/tampered/priv_esc/replay。"""
    import numpy as np
    rng = np.random.RandomState(seed)
    n_n = int(n * RATIOS["normal"])
    n_t = int(n * RATIOS["tampered"])
    n_p = int(n * RATIOS["priv_esc"])
    n_r = n - n_n - n_t - n_p
    types = ["normal"] * n_n + ["tampered"] * n_t + ["priv_esc"] * n_p + \
        ["replay"] * n_r
    rng.shuffle(types)
    cmds = []
    for i, t in enumerate(types):
        tool = rng.choice(["file.read", "db.query"]) if t != "priv_esc" \
            else rng.choice(["file.write", "agent.run"])
        cmds.append({"type": t, "tool": tool, "action": "read",
                     "args": {"path": f"/d/{i}", "sql": f"q{i}"}})
    return cmds


class Runner:
    """本文方案执行器：每请求重签双 ST（单次缓存约束）+ 四步验证。"""

    def __init__(self, sm9, kdc, agent, session_credential,
                 netperm, claims, service=SERVICE,
                 verify_user_signature=True, verify_st_data=True):
        self.sm9, self.kdc, self.agent = sm9, kdc, agent
        self.netperm, self.claims = netperm, claims
        self.session_credential = session_credential
        self.service = service
        st = STService(sm9, kdc.kdc_did)
        self.server = MCPServer(sm9, st, service, kdc=kdc,
                                claims_checker=ClaimsChecker(tools=TOOLS,
                                                             actions=ACTIONS),
                                tools={"file.read": lambda a: {"ok": 1}},
                                verify_user_signature=verify_user_signature,
                                verify_st_data=verify_st_data)
        self.evil = SM9Engine()
        self.evil_kdc = "didsm9:evil:ff"
        self.evil.derive_sk(self.evil_kdc)
        self.last = None                     # 最近一次 (msg, headers)

    def _fresh_tickets(self):
        self.agent.obtain_tickets(self.service, self.netperm, self.claims,
                                  self.session_credential)

    def _signed(self, cmd, ts=None, req_id=None):
        ts = ts if ts is not None else time.time()
        req_id = req_id or rand_bytes(8, "c3").hex()
        sa, su = self.agent.sign_chain(cmd, ts, req_id, {"session": "s"})
        msg = build_tools_call(req_id, cmd["tool"], cmd["args"], extra={
            "cmd": cmd, "ts": ts, "ctx": {"session": "s"},
            "sig_agent": sa.hex(), "sig_user": su.hex(),
            "agent_did": self.agent.agent_did,
            "user_did": self.agent.user_did})
        return msg, inject_tickets(msg, self.agent.st_data, self.agent.st_net)

    def call(self, cmd, mode="full"):
        """mode: full（全量）/ no_user_sig（消融：去用户签名层）/ no_st_data。"""
        if cmd["type"] == "unregistered_agent":
            rogue = MCPAgent("docker-unregistered", "user1", self.sm9,
                             self.kdc, user_did=self.agent.user_did)
            session = issue_simulated_p2p_session(
                self.kdc, rogue.agent_did, rogue.user_did,
                self.netperm, label="c3-unregistered")
            try:
                rogue.obtain_tickets(self.service, self.netperm,
                                     self.claims, session)
                return True
            except RuntimeError:
                return False
        if cmd["type"] == "invalid_parent_session":
            other = MCPAgent("docker-other-session", "user1", self.sm9,
                             self.kdc, user_did=self.agent.user_did)
            other.register()
            other_session = issue_simulated_p2p_session(
                self.kdc, other.agent_did, other.user_did,
                self.netperm, label="c3-other-session")
            access = self.kdc.issue_dual_access(
                self.agent.agent_did, self.agent.user_did, other_session,
                self.service, self.netperm, self.claims)
            return access is not None
        if cmd["type"] == "dual_st_mix":
            self._fresh_tickets()
            st_net_first = self.agent.st_net
            self._fresh_tickets()
            self.agent.st_net = st_net_first
            msg, h = self._signed(cmd)
            return "result" in self.server.handle_call(msg, h)
        if cmd["type"] == "user_agent_mismatch":
            self._fresh_tickets()
            user2 = make_user_did("user2")
            self.sm9.derive_sk(user2)
            ts = time.time()
            req_id = rand_bytes(8, "c3-user-mismatch").hex()
            ctx = {"session": "colluding-user"}
            cmd_b = json.dumps(cmd, sort_keys=True).encode()
            m1 = sm3(cmd_b + int(ts).to_bytes(8, "big") + req_id.encode()
                     + self.agent.st_net["ticket_id"].encode()
                     + self.agent.st_data["ticket_id"].encode()
                     + self.agent.agent_did.encode() + user2.encode())
            sig_agent = self.sm9.sign(self.agent.agent_did, m1)
            m2 = sm3(cmd_b + sig_agent
                     + json.dumps(ctx, sort_keys=True).encode())
            sig_user = self.sm9.sign(user2, m2)
            msg = build_tools_call(req_id, cmd["tool"], cmd["args"], extra={
                "cmd": cmd, "ts": ts, "ctx": ctx,
                "sig_agent": sig_agent.hex(), "sig_user": sig_user.hex(),
                "agent_did": self.agent.agent_did, "user_did": user2})
            h = inject_tickets(msg, self.agent.st_data, self.agent.st_net)
            return "result" in self.server.handle_call(msg, h)
        if cmd["type"] == "replay":
            # 重放：原样重发上一次请求（ST 单次缓存 → 本文拦截）
            if self.last is None:
                self._fresh_tickets()
                msg, h = self._signed(cmd)
                self.server.handle_call(msg, h)     # 建立基线
                self.last = (msg, h)
            msg, h = self.last
            resp = self.server.handle_call(msg, h)
            return "result" in resp
        self._fresh_tickets()
        if cmd["type"] == "tampered":
            msg, h = self._signed(cmd)
            msg["params"]["cmd"]["args"]["path"] += "/PWNED"   # 篡改不重签
        elif cmd["type"] == "priv_esc":
            msg, h = self._signed(cmd)                          # 越权 tool
        elif cmd["type"] == "forged_st":
            self._fresh_tickets()
            msg, h = self._signed(cmd)
            st_bad = dict(self.agent.st_data)
            st_bad["sig"] = self.evil.sign(
                self.evil_kdc, json.dumps(
                    {k: v for k, v in st_bad.items() if k != "sig"},
                    sort_keys=True).encode()).hex()
            h["X-ST-Ticket"] = json.dumps(st_bad)
        elif cmd["type"] == "did_spoof":
            self._fresh_tickets()
            sa, su = self.agent.sign_chain(cmd, time.time(), "r", {"s": "x"})
            msg = build_tools_call("r", cmd["tool"], cmd["args"], extra={
                "cmd": cmd, "ts": time.time(), "ctx": {"s": "x"},
                "sig_agent": sa.hex(), "sig_user": su.hex(),
                "agent_did": "didsm9:attacker:ff",
                "user_did": self.agent.user_did})
            h = inject_tickets(msg, self.agent.st_data, self.agent.st_net)
        elif cmd["type"] == "confusion":
            # 调用者混淆：attacker 身份 + victim 的合法请求组件
            self._fresh_tickets()
            sa, su = self.agent.sign_chain(cmd, time.time(), "r2",
                                           {"s": "y"})
            msg = build_tools_call("r2", cmd["tool"], cmd["args"], extra={
                "cmd": cmd, "ts": time.time(), "ctx": {"s": "y"},
                "sig_agent": sa.hex(), "sig_user": su.hex(),
                "agent_did": self.agent.agent_did,
                "user_did": "didsm9:other-user:ff"})
            h = inject_tickets(msg, self.agent.st_data, self.agent.st_net)
        else:
            msg, h = self._signed(cmd)
        resp = self.server.handle_call(msg, h)
        self.last = (msg, h)
        return "result" in resp

    def call_attack(self, attack: str) -> bool:
        """真消融攻击：返回是否被放行（True=逃逸）。请求仍携带被篡改字段。"""
        if attack == "tamper_user_sig":
            # 篡改用户签名（Agent 签名保持有效，用户签名无效）
            self._fresh_tickets()
            cmd = {"tool": "file.read", "action": "read",
                   "args": {"path": "/a"}}
            msg, h = self._signed(cmd)
            msg["params"]["sig_user"] = rand_bytes(97, "evil_user").hex()
        elif attack == "tamper_st_claims":
            # 篡改 ST_data 的 claims（增加 agent.run 权限），不重新签票
            self._fresh_tickets()
            cmd = {"tool": "agent.run", "action": "execute",
                   "args": {"path": "/x"}}
            msg, h = self._signed(cmd)
            st_bad = dict(self.agent.st_data)
            st_bad["perm"] = {"claims": {
                "tools": ["file.read", "agent.run"],
                "actions": ["read", "execute"]}}
            h["X-ST-Ticket"] = json.dumps(st_bad)
        else:
            raise ValueError(f"unknown attack: {attack}")
        resp = self.server.handle_call(msg, h)
        return "result" in resp


def main():
    debug = "--debug" in sys.argv
    quick = "--quick" in sys.argv
    out_dir, run_state = start_run(RESULTS)
    if debug:
        print("[debug] expC3 main start")

    sm9 = SM9Engine()
    kdc = KDC(sm9)
    user_did = make_user_did("user1")
    kdc.register_user(user_did)
    netperm = netperm_defaults()
    netperm["services"] = [SERVICE]
    claims = {"tools": ["file.read", "db.query"], "actions": ["read"]}
    agent = MCPAgent("docker3333333333333333", "user1", sm9, kdc,
                     user_did=user_did)
    agent.register()
    session = issue_simulated_p2p_session(
        kdc, agent.agent_did, user_did, netperm, label="c3-agent")

    n_cmds = 50 if quick else N_CMDS
    cmds = gen_commands(n=n_cmds)
    runner = Runner(sm9, kdc, agent, session, netperm, claims)

    # ------------------------------------------------------------------
    # 指令流三方案
    # ------------------------------------------------------------------
    oa = OAuthBaseline(cache_auth_state=True)
    oa.register_client("mcp-client")
    code = oa.authorize("mcp-client", ["mcp-server"], "v")
    token = oa.exchange("mcp-client", code, "v")
    na = NoAuthBaseline()

    instr_rows = []
    for scheme in ("ours", "oauth", "noauth"):
        stats = {"normal": [0, 0], "tampered": [0, 0],
                 "priv_esc": [0, 0], "replay": [0, 0]}
        for c in cmds:
            if scheme == "ours":
                passed = runner.call(c, mode="full")
            elif scheme == "oauth":
                passed = oa.call_tool(token, "mcp-client", c)["ok"]
            else:
                passed = na.call_tool(c)["ok"]
            stats[c["type"]][0] += 1
            stats[c["type"]][1] += 1 if passed else 0
        for t, (total, passed) in stats.items():
            instr_rows.append({"case_type": t, "scheme": scheme,
                               "total": total, "passed": passed,
                               "blocked": total - passed,
                               "block_rate": (total - passed) / total})
        print(f"  {scheme}: " + " ".join(
            f"{t}={1 - p / m:.2f}" for t, (m, p) in stats.items()))

    # ------------------------------------------------------------------
    # 攻击矩阵（6 类 × 3 方案）
    # ------------------------------------------------------------------
    attack_rows = []
    attack_types = ("tampered", "priv_esc", "replay", "forged_st",
                    "did_spoof", "confusion", "unregistered_agent",
                    "invalid_parent_session", "dual_st_mix",
                    "user_agent_mismatch")
    for atype in attack_types:
        for scheme in ("ours", "oauth", "noauth"):
            blocked = 0
            n = 5 if quick else 20
            for i in range(n):
                c = {"type": atype,
                     "tool": "agent.run" if atype == "priv_esc" else "file.read",
                     "action": "read",
                     "args": {"path": f"/x/{i}"}}
                if scheme == "ours":
                    p = runner.call(c, mode="full")
                elif scheme == "oauth":
                    p = oa.call_tool(token, "mcp-client", c)["ok"]
                else:
                    p = na.call_tool(c)["ok"]
                if not p:
                    blocked += 1
            attack_rows.append({"attack_type": atype, "scheme": scheme,
                                "attempts": n, "blocked": blocked,
                                "block_rate": blocked / n})
            if atype in ("tampered", "priv_esc", "replay") or scheme == "ours":
                pass
        print(f"  attack {atype}: " + " ".join(
            f"{r['scheme']}={r['block_rate']:.2f}"
            for r in attack_rows if r["attack_type"] == atype))

    # ------------------------------------------------------------------
    # 消融（本文三档 × 攻击类）
    # ------------------------------------------------------------------
    ablation_rows = []
    configs = {
        "full": (True, True),
        "no_user_signature_verify": (False, True),
        "no_st_data_verify": (True, False),
    }
    for cfg, (vus, vsd) in configs.items():
        r = Runner(sm9, kdc, agent, session, netperm, claims,
                   verify_user_signature=vus, verify_st_data=vsd)
        # 正常请求：应全部通过
        n_normal = 5 if quick else 20
        normal_pass = 0
        for i in range(n_normal):
            if r.call({"type": "normal", "tool": "file.read",
                       "action": "read", "args": {"path": f"/a/{i}"}}):
                normal_pass += 1
        normal_pass_rate = normal_pass / n_normal

        escape_map = {}
        for attack in ("tamper_user_sig", "tamper_st_claims"):
            n_att = 5 if quick else 20
            escape = 0
            for i in range(n_att):
                if r.call_attack(attack):
                    escape += 1
            attack_escape_rate = escape / n_att
            attack_block_rate = 1.0 - attack_escape_rate
            escape_map[attack] = attack_escape_rate
            ablation_rows.append({
                "config": cfg, "attack": attack,
                "normal_pass_rate": normal_pass_rate,
                "attack_block_rate": attack_block_rate,
                "attack_escape_rate": attack_escape_rate,
                "n": n_att,
            })
        print(f"  ablation {cfg}: normal_pass={normal_pass_rate:.2f} "
              f"user_sig_escape={escape_map['tamper_user_sig']:.2f} "
              f"st_claims_escape={escape_map['tamper_st_claims']:.2f}")

    write_csv(out_dir / "expC3_instruction_results.csv", instr_rows)
    write_csv(out_dir / "expC3_attack_matrix.csv", attack_rows)
    write_csv(out_dir / "expC3_ablation.csv", ablation_rows)
    for f in ("expC3_instruction_results.csv", "expC3_attack_matrix.csv",
              "expC3_ablation.csv"):
        csv_meta(out_dir / f, {"seed": SEED,
                               "mode": "quick" if quick else "formal",
                               "n_cmds": n_cmds,
                               "n_attack": 5 if quick else 20,
                               "ratios": RATIOS})
    write_manifest(
        out_dir, run_state, mode="quick" if quick else "formal", seed=SEED,
        parameters={"n_cmds": n_cmds,
                    "n_attack": 5 if quick else 20,
                    "attack_types": list(attack_types),
                    "ratios": RATIOS},
        simulated_components=["MCP JSON-RPC tools/call",
                              "Direction-2 session credential handoff",
                              "OAuth bearer-token and no-auth baselines"],
    )


if __name__ == "__main__":
    main()
