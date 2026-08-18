"""
MCP 协议层（方向三）：JSON-RPC 2.0 `tools/call` 报文 + X-ST-Ticket 双头部注入。
MCP 层为轻量 JSON-RPC 模拟（标注"MCP 模拟"，无真实 MCP SDK）。
"""

import json
from typing import Dict, Optional, Tuple

JSONRPC_VERSION = "2.0"
HEADER_ST_DATA = "X-ST-Ticket"        # ST_data：MCP 服务端验证
HEADER_ST_NET = "X-ST-Ticket-Net"     # ST_net：网关验证
METHOD_TOOLS_CALL = "tools/call"


def build_tools_call(req_id: str, tool: str, args: dict,
                     extra: Optional[dict] = None) -> dict:
    """构造 MCP tools/call JSON-RPC 报文（模拟）。"""
    params = {"name": tool, "arguments": args}
    if extra:
        params.update(extra)
    return {
        "jsonrpc": JSONRPC_VERSION,
        "id": req_id,
        "method": METHOD_TOOLS_CALL,
        "params": params,
    }


def inject_tickets(msg: dict, st_data: dict, st_net: dict) -> Dict[str, str]:
    """B 头部注入：返回头部字典（双 ST 序列化为 JSON）。"""
    return {
        HEADER_ST_DATA: json.dumps(st_data, sort_keys=True),
        HEADER_ST_NET: json.dumps(st_net, sort_keys=True),
    }


def parse_request(msg: dict, headers: Dict[str, str]) -> dict:
    """C 服务端中间件解析：合并报文 + 双头部 → 统一请求结构。"""
    st_data = json.loads(headers[HEADER_ST_DATA]) if HEADER_ST_DATA in headers else None
    st_net = json.loads(headers[HEADER_ST_NET]) if HEADER_ST_NET in headers else None
    return {
        "jsonrpc": msg.get("jsonrpc"),
        "req_id": msg.get("id"),
        "method": msg.get("method"),
        "tool": msg.get("params", {}).get("name"),
        "args": msg.get("params", {}).get("arguments", {}),
        "extra": {k: v for k, v in msg.get("params", {}).items()
                  if k not in ("name", "arguments")},
        "st_data": st_data,
        "st_net": st_net,
    }


def result_ok(req_id: str, result: dict) -> dict:
    """MCP 成功响应（模拟）。"""
    return {"jsonrpc": JSONRPC_VERSION, "id": req_id, "result": result}


def result_error(req_id: str, code: int, message: str) -> dict:
    """MCP 错误响应（模拟）。"""
    return {"jsonrpc": JSONRPC_VERSION, "id": req_id,
            "error": {"code": code, "message": message}}