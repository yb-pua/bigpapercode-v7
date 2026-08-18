"""
MCP 网关（方向三）：跨域转发（场景 C）。验证 ST_net + SM9 授权 + DID 一致性；
转发不读业务载荷（仅按 Cmd 路由），审计以 ticket_id 贯通。
"""

import json
import time
from typing import Callable, Dict, Optional, Tuple

from .common import sm3
from .mcp_protocol import parse_request, result_error
from .st_ticket import STService, make_st_replay_cache


class MCPGateway:
    """跨域网关：ST_net 验证 + 转发（不解密/不读业务载荷）。"""

    def __init__(self, sm9, st_service: STService, service: str,
                 audit_logger=None, now_fn: Optional[Callable[[], float]] = None):
        self.sm9 = sm9
        self.st = st_service
        self.service = service
        self.audit = audit_logger
        self._now_fn = now_fn or time.time
        self.replay_net = make_st_replay_cache()
        self.forwarded = 0
        self.payload_read_bytes = 0

    def now(self) -> float:
        return self._now_fn()

    def admit(self, msg: dict, headers: Dict[str, str],
              expected_net_perm: Optional[dict] = None) -> dict:
        """网关准入：ST_net 签名/时效/范围/单次 + DID 一致性（链上 agent）。"""
        request = parse_request(msg, headers)
        if request["st_net"] is None:
            return {"ok": False, "error": "missing_st_net"}
        r = self.st.verify_st(request["st_net"], self.service, st_kind="net",
                              expected_perm=expected_net_perm,
                              replay_cache=self.replay_net, now=self.now())
        if not r["ok"]:
            return {"ok": False, "error": r["error"]}
        if request["st_net"]["principal"] != request["extra"]["agent_did"]:
            return {"ok": False, "error": "did_mismatch"}
        return {"ok": True, "claims": r["claims"]}

    def forward(self, msg: dict, headers: Dict[str, str],
                expected_net_perm: Optional[dict] = None) -> dict:
        """验证 ST_net 后转发；载荷不解密（payload_read_bytes 恒 0 为证据）。"""
        a = self.admit(msg, headers, expected_net_perm)
        if not a["ok"]:
            if self.audit is not None:
                self.audit.log("gateway", f"rejected:{a['error']}",
                               msg.get("id"))
            return result_error(msg.get("id"), -32603, a["error"])
        self.forwarded += 1
        if self.audit is not None:
            tid = request_ticket_id(msg, headers)
            self.audit.log("gateway", "forward", msg.get("id"), ticket_id=tid)
        return {"jsonrpc": "2.0", "id": msg.get("id"),
                "result": {"forwarded": True}}


def request_ticket_id(msg: dict, headers: Dict[str, str]) -> Optional[str]:
    """从头部 ST 取 ticket_id（审计关联，不解密载荷）。"""
    import json as _json
    st = headers.get("X-ST-Ticket-Net")
    if st:
        try:
            return _json.loads(st).get("ticket_id")
        except Exception:
            return None
    return None