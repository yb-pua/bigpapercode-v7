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

STAGE_NAMES = ["st_net", "st_data", "binding", "chain", "perm"]


class MCPServer:
    """MCP 服务端中间件（C）：四步验证 + 工具执行（模拟）。"""

    def __init__(self, sm9, st_service: STService, service: str,
                 kdc=None,
                 claims_checker: Optional[ClaimsChecker] = None,
                 audit_logger=None, now_fn: Optional[Callable[[], float]] = None,
                 tools: Optional[Dict[str, Callable]] = None,
                 verify_user_signature: bool = True,
                 verify_st_data: bool = True):
        self.sm9 = sm9
        self.st = st_service
        self.service = service
        self.kdc = kdc
        self.checker = claims_checker or ClaimsChecker()
        self.audit = audit_logger
        self._now_fn = now_fn or time.time
        self.tools = tools or {}
        self.replay_net = make_st_replay_cache()
        self.replay_data = make_st_replay_cache()
        # 消融开关：跳过对应验证（请求仍携带该字段，服务端不校验）
        self.verify_user_signature = verify_user_signature
        self.verify_st_data = verify_st_data

    def now(self) -> float:
        return self._now_fn()

    # ------------------------------------------------------------------
    def _cross_field_error(self, request: dict, extra: dict) -> Optional[str]:
        """双票 + 请求的跨字段绑定一致性；任一不一致返回明确错误码。"""
        st_net = request["st_net"]
        st_data = request["st_data"]
        agent_did = extra.get("agent_did")
        user_did = extra.get("user_did")
        if st_net.get("agent_did", st_net.get("principal")) != agent_did:
            return "did_mismatch"
        if st_data.get("agent_did", st_data.get("principal")) != agent_did:
            return "did_mismatch"
        if st_net.get("user_did", "") != user_did:
            return "user_device_mismatch"
        if st_data.get("user_did", "") != user_did:
            return "user_device_mismatch"
        if st_net.get("pair_id", "") != st_data.get("pair_id", ""):
            return "pair_mismatch"
        if st_net.get("parent_ticket_id", "") != st_data.get("parent_ticket_id", ""):
            return "parent_ticket_mismatch"
        if self.kdc is not None:
            owner = self.kdc.owner_of(agent_did)
            if owner != user_did:
                return "binding_rejected"
        return None

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
        if self.verify_st_data:
            r_data = self.st.verify_st(request["st_data"], self.service,
                                       st_kind="data",
                                       replay_cache=self.replay_data,
                                       now=self.now())
            stages["st_data"] = (time.perf_counter() - t0) * 1000.0
            if not r_data["ok"]:
                return {"ok": False, "stage": "st_data", "ms": stages,
                        "error": r_data["error"]}
        else:
            # 消融：跳过 ST_data 的签名/时效/重放验证（票据仍供后续绑定/权限检查）
            stages["st_data"] = (time.perf_counter() - t0) * 1000.0
            r_data = {"ok": True, "claims": {
                "client_did": request["st_data"].get("principal"),
                "ticket_id": request["st_data"].get("ticket_id"),
                "service_id": self.service,
                "st_kind": "data",
                "perm": request["st_data"].get("perm", {}),
                "issued_time": float(request["st_data"].get("issued_time", 0)),
                "validity": 0.0,
            }}

        # ①.5 跨字段绑定（双票 + 请求 + 绑定表）
        extra = request["extra"]
        t0 = time.perf_counter()
        err = self._cross_field_error(request, extra)
        stages["binding"] = (time.perf_counter() - t0) * 1000.0
        if err is not None:
            return {"ok": False, "stage": "binding", "ms": stages, "error": err}

        # ② 签名链（σ_agent 绑定 Cmd‖ts‖req_id‖双票ID‖双DID）
        cmd = extra["cmd"]
        cmd_b = json.dumps(cmd, sort_keys=True).encode()
        ts = float(extra["ts"])
        req_id = str(extra.get("req_id") or request["req_id"])
        ctx = extra["ctx"]
        sig_agent = bytes.fromhex(extra["sig_agent"])
        verify_user = self.verify_user_signature and require_chain
        if verify_user and "sig_user" not in extra:
            stages["chain"] = (time.perf_counter() - t0) * 1000.0
            return {"ok": False, "stage": "chain", "ms": stages,
                    "error": "signature_chain_invalid"}
        t0 = time.perf_counter()
        st_net_id = request["st_net"].get("ticket_id", "")
        st_data_id = request["st_data"].get("ticket_id", "")
        agent_did = extra["agent_did"]
        user_did = extra["user_did"]
        m1 = sm3(cmd_b + int(ts).to_bytes(8, "big") + req_id.encode()
                 + st_net_id.encode() + st_data_id.encode()
                 + agent_did.encode() + user_did.encode())
        ok_agent = self.sm9.verify(agent_did, m1, sig_agent)
        if verify_user:
            sig_user = bytes.fromhex(extra["sig_user"])
            m2 = sm3(cmd_b + sig_agent +
                     json.dumps(ctx, sort_keys=True).encode())
            ok_user = self.sm9.verify(user_did, m2, sig_user)
            ok_chain = ok_agent and ok_user
        else:
            ok_chain = ok_agent          # 消融：跳过用户签名验证
        stages["chain"] = (time.perf_counter() - t0) * 1000.0
        if not ok_chain:
            return {"ok": False, "stage": "chain", "ms": stages,
                    "error": "signature_chain_invalid"}

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