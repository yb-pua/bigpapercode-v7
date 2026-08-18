"""
MCP 服务端（方向三）：四步验证 → 权限匹配 → 转发执行 → 审计。

四步验证（§5.2）：
  ① 双 ST 校验（ST_data + ST_net：签名/时效/权限范围/单次使用）
  ② 签名链校验（σ_agent 验 SM3(Cmd‖ts‖req_id)；σ_user 验 SM3(Cmd‖σ_agent‖ctx)）
  ③ DID 一致性（签名者 DID == 票据 Principal）
  ④ 权限匹配（ClaimsChecker.match(action, tool, claims)）
"""

import json
import time
from typing import Callable, Dict, Optional, Tuple

from .claims_checker import ClaimsChecker
from .common import sm3
from .mcp_protocol import parse_request, result_error, result_ok
from .st_ticket import STService, make_st_replay_cache

STAGE_NAMES = ["st_net", "st_data", "chain", "did_consistency", "perm"]


class MCPServer:
    """MCP 服务端中间件（C）：四步验证 + 工具执行（模拟）。"""

    def __init__(self, sm9, st_service: STService, service: str,
                 claims_checker: Optional[ClaimsChecker] = None,
                 audit_logger=None, now_fn: Optional[Callable[[], float]] = None,
                 tools: Optional[Dict[str, Callable]] = None):
        self.sm9 = sm9
        self.st = st_service
        self.service = service
        self.checker = claims_checker or ClaimsChecker()
        self.audit = audit_logger
        self._now_fn = now_fn or time.time
        self.tools = tools or {}
        self.replay_net = make_st_replay_cache()
        self.replay_data = make_st_replay_cache()

    def now(self) -> float:
        return self._now_fn()

    # ------------------------------------------------------------------
    def verify_four_steps(self, request: dict,
                          expected_net_perm: Optional[dict] = None,
                          require_chain: bool = True) -> dict:
        """四步验证单测接口。request 为 parse_request 结构。"""
        stages = {}
        t0 = time.perf_counter()

        # ① 双 ST
        r_net = self.st.verify_st(request["st_net"], self.service,
                                  st_kind="net",
                                  expected_perm=expected_net_perm,
                                  replay_cache=self.replay_net,
                                  now=self.now())
        stages["st_net"] = (time.perf_counter() - t0) * 1000.0
        if not r_net["ok"]:
            return {"ok": False, "stage": "st_net", "ms": stages,
                    "error": r_net["error"]}
        t0 = time.perf_counter()
        r_data = self.st.verify_st(request["st_data"], self.service,
                                   st_kind="data",
                                   replay_cache=self.replay_data,
                                   now=self.now())
        stages["st_data"] = (time.perf_counter() - t0) * 1000.0
        if not r_data["ok"]:
            return {"ok": False, "stage": "st_data", "ms": stages,
                    "error": r_data["error"]}

        # ② 签名链
        extra = request["extra"]
        cmd = extra["cmd"]
        cmd_b = json.dumps(cmd, sort_keys=True).encode()
        ts = float(extra["ts"])
        req_id = str(extra.get("req_id") or request["req_id"])
        ctx = extra["ctx"]
        sig_agent = bytes.fromhex(extra["sig_agent"])
        if "sig_user" not in extra:
            stages["chain"] = (time.perf_counter() - t0) * 1000.0
            return {"ok": False, "stage": "chain", "ms": stages,
                    "error": "signature_chain_invalid"}
        sig_user = bytes.fromhex(extra["sig_user"])
        t0 = time.perf_counter()
        m1 = sm3(cmd_b + int(ts).to_bytes(8, "big") + req_id.encode())
        ok_agent = self.sm9.verify(extra["agent_did"], m1, sig_agent)
        if require_chain:
            m2 = sm3(cmd_b + sig_agent +
                     json.dumps(ctx, sort_keys=True).encode())
            ok_user = self.sm9.verify(extra["user_did"], m2, sig_user)
            ok_chain = ok_agent and ok_user
        else:
            ok_chain = ok_agent          # 消融：去用户签名层
        stages["chain"] = (time.perf_counter() - t0) * 1000.0
        if not ok_chain:
            return {"ok": False, "stage": "chain", "ms": stages,
                    "error": "signature_chain_invalid"}

        # ③ DID 一致性
        t0 = time.perf_counter()
        if request["st_data"]["principal"] != extra["agent_did"] or \
                request["st_net"]["principal"] != extra["agent_did"]:
            stages["did_consistency"] = (time.perf_counter() - t0) * 1000.0
            return {"ok": False, "stage": "did_consistency", "ms": stages,
                    "error": "did_mismatch"}
        stages["did_consistency"] = (time.perf_counter() - t0) * 1000.0

        # ④ 权限匹配
        t0 = time.perf_counter()
        tool = cmd.get("tool")
        action = cmd.get("action", "read")
        allowed = self.checker.match(action, tool,
                                     st_data=request["st_data"])
        stages["perm"] = (time.perf_counter() - t0) * 1000.0
        if not allowed:
            return {"ok": False, "stage": "perm", "ms": stages,
                    "error": "perm_denied"}
        return {"ok": True, "stage": "all", "ms": stages,
                "claims": r_data["claims"]}

    # ------------------------------------------------------------------
    def handle_call(self, msg: dict, headers: Dict[str, str],
                    expected_net_perm: Optional[dict] = None) -> dict:
        """MCP 服务端入口：解析 → 四步验证 → 执行工具（模拟）→ 审计。"""
        request = parse_request(msg, headers)
        if request["st_data"] is None or request["st_net"] is None:
            return result_error(request["req_id"], -32600,
                                "missing ST tickets")
        v = self.verify_four_steps(request, expected_net_perm)
        if not v["ok"]:
            if self.audit is not None:
                self.audit.log("mcp_call", f"rejected:{v['error']}",
                               msg.get("id"),
                               ticket_id=request["st_data"].get("ticket_id"))
            return result_error(request["req_id"], -32603, v["error"])
        tool = request["tool"]
        result = self.tools[tool](request["args"]) if tool in self.tools \
            else {"executed": True, "tool": tool}
        if self.audit is not None:
            self.audit.log("mcp_call", "success", msg.get("id"),
                           ticket_id=request["st_data"]["ticket_id"])
        return result_ok(request["req_id"], result)