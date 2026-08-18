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

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from core.claims_checker import ClaimsChecker
from core.common import SEED, csv_meta, rand_bytes, write_csv
from core.did import make_user_did
from core.kdc import KDC
from core.mcp_agent import MCPAgent
from core.mcp_protocol import build_tools_call, inject_tickets
from core.mcp_server import MCPServer
from core.noauth_baseline import NoAuthBaseline
from core.oauth_baseline import OAuthBaseline
from core.sm9_engine import SM9Engine
from core.st_ticket import STService, netperm_defaults

SERVICE = "mcp-server@realm"
TOOLS = ["file.read", "file.write", "db.query", "agent.run"]
ACTIONS = ["read", "write", "execute", "manage"]
N_CMDS = 500
RATIOS = {"normal": 0.60, "tampered": 0.16, "priv_esc": 0.16, "replay": 0.08}
RESULTS = Path(__file__).resolve().parent.parent / "results"


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

    def __init__(self, sm9, kdc, agent, netperm, claims, service=SERVICE):
        self.sm9, self.kdc, self.agent = sm9, kdc, agent
        self.netperm, self.claims = netperm, claims
        self.service = service
        st = STService(sm9, kdc.kdc_did)
        self.server = MCPServer(sm9, st, service,
                                claims_checker=ClaimsChecker(tools=TOOLS,
                                                             actions=ACTIONS),
                                tools={"file.read": lambda a: {"ok": 1}})
        self.evil = SM9Engine()
        self.evil_kdc = "didsm9:evil:ff"
        self.evil.derive_sk(self.evil_kdc)
        self.last = None                     # 最近一次 (msg, headers)

    def _fresh_tickets(self):
        self.agent.obtain_tickets(self.service, self.netperm, self.claims)

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
        if mode == "no_user_sig":
            msg["params"].pop("sig_user", None)
        if mode == "no_st_data":
            h.pop("X-ST-Ticket", None)
        resp = self.server.handle_call(msg, h)
        self.last = (msg, h)
        return "result" in resp


def main():
    debug = "--debug" in sys.argv
    quick = "--quick" in sys.argv
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

    n_cmds = 50 if quick else N_CMDS
    cmds = gen_commands(n=n_cmds)
    runner = Runner(sm9, kdc, agent, netperm, claims)

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
    for atype in ("tampered", "priv_esc", "replay", "forged_st",
                  "did_spoof", "confusion"):
        for scheme in ("ours", "oauth", "noauth"):
            blocked = 0
            n = 20
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
    for cfg, mode in (("full", "full"), ("no_user_sig", "no_user_sig"),
                      ("no_st_data", "no_st_data")):
        for atype in ("normal", "tampered", "priv_esc", "replay"):
            n = 20
            blocked = 0
            for i in range(n):
                c = {"type": atype,
                     "tool": "agent.run" if atype == "priv_esc" else "file.read",
                     "action": "read",
                     "args": {"path": f"/a/{i}"}}
                p = runner.call(c, mode=mode)
                if atype == "normal":
                    if not p:
                        blocked += 1
                else:
                    if not p:
                        blocked += 1
            ablation_rows.append({"config": cfg, "case_type": atype,
                                  "block_rate": blocked / n,
                                  "note": f"n={n}"})
        print(f"  ablation {cfg}: " + " ".join(
            f"{r['case_type']}={r['block_rate']:.2f}"
            for r in ablation_rows if r["config"] == cfg))

    write_csv(RESULTS / "expC3_instruction_results.csv", instr_rows)
    write_csv(RESULTS / "expC3_attack_matrix.csv", attack_rows)
    write_csv(RESULTS / "expC3_ablation.csv", ablation_rows)
    for f in ("expC3_instruction_results.csv", "expC3_attack_matrix.csv",
              "expC3_ablation.csv"):
        csv_meta(RESULTS / f, {"seed": SEED, "n_cmds": n_cmds,
                               "ratios": RATIOS})


if __name__ == "__main__":
    main()