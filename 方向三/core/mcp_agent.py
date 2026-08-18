"""
MCP Agent（方向三）：环境标识锚点 + 双 DID + 双签名链 + 双 ST 请求构造。

- Agent 设备 DID = make_device_did(env_id, owner_user_id)
- 用户生物 DID = make_user_did(owner_user_id)
- 双签名链（先设备后用户）：
    σ_agent = Sign(设备sk, SM3(Cmd ‖ ts ‖ req_id))
    σ_user  = Sign(生物sk, SM3(Cmd ‖ σ_agent ‖ ctx))
- 请求结构：{Cmd, ts, req_id, ctx, σ_agent, σ_user, agent_did, user_did}
"""

import json
import time
from typing import Dict, List, Optional, Tuple

from .common import rand_bytes, sm3
from .did import make_device_did, make_user_did
from .mcp_protocol import build_tools_call, inject_tickets
from .st_ticket import STService

REQ_ID_BYTES = 8


def env_id(env_type: str, seed: int = 20260817) -> str:
    """4 类环境唯一标识模拟生成（标注"环境标识模拟"）。"""
    import hashlib
    raw = hashlib.sha256(f"{env_type}:{seed}".encode()).hexdigest()
    if env_type == "docker":
        return raw[:64]
    if env_type == "linux":
        return raw[:32]
    if env_type == "windows":
        return raw[:36].upper()
    if env_type == "vmware":
        return f"{raw[:8]}-{raw[8:12]}-{raw[12:16]}-{raw[16:20]}-{raw[20:32]}"
    raise ValueError(f"unknown env_type: {env_type}")


class MCPAgent:
    """MCP 客户端代理：持双 DID，构造双签名链请求。"""

    def __init__(self, env_id: str, owner_user_id: str, sm9,
                 kdc, user_did: Optional[str] = None):
        self.env_id = env_id
        self.owner_user_id = owner_user_id
        self.sm9 = sm9
        self.kdc = kdc
        self.agent_did = make_device_did(env_id, owner_user_id)
        self.user_did = user_did or make_user_did(owner_user_id)
        self.sm9.derive_sk(self.agent_did)
        self.sm9.derive_sk(self.user_did)
        self.st_net = None
        self.st_data = None

    # ------------------------------------------------------------------
    def register(self) -> bool:
        """KDC 登记（设备绑定用户）。"""
        return self.kdc.register_device(self.agent_did, self.user_did)

    def obtain_tickets(self, service: str, netperm: dict,
                       claims: dict) -> Tuple[dict, dict]:
        """申请双 ST：ST_net（组网）+ ST_data（claims 数据权限）。"""
        self.st_net = self.kdc.issue_dual_ticket(
            self.agent_did, service, "net", netperm)
        self.st_data = self.kdc.issue_dual_ticket(
            self.agent_did, service, "data", {"claims": claims})
        return self.st_net, self.st_data

    # ------------------------------------------------------------------
    def sign_chain(self, cmd: dict, ts: float, req_id: str,
                   ctx: dict) -> Tuple[bytes, bytes]:
        """双签名链：先设备后用户。返回 (σ_agent, σ_user)。"""
        cmd_b = json.dumps(cmd, sort_keys=True).encode()
        m1 = sm3(cmd_b + int(ts).to_bytes(8, "big") + req_id.encode())
        sig_agent = self.sm9.sign(self.agent_did, m1)
        m2 = sm3(cmd_b + sig_agent + json.dumps(ctx, sort_keys=True).encode())
        sig_user = self.sm9.sign(self.user_did, m2)
        return sig_agent, sig_user

    def build_request(self, cmd: dict, ts: Optional[float] = None,
                      req_id: Optional[str] = None,
                      ctx: Optional[dict] = None) -> Tuple[dict, Dict[str, str]]:
        """构造 MCP 请求（报文 + 双 ST 头部）。"""
        ts = ts if ts is not None else time.time()
        req_id = req_id or rand_bytes(REQ_ID_BYTES, f"req_{self.agent_did}").hex()
        ctx = ctx or {"session": self.env_id[:12]}
        sig_agent, sig_user = self.sign_chain(cmd, ts, req_id, ctx)
        msg = build_tools_call(req_id, cmd.get("tool", ""),
                               cmd.get("args", {}),
                               extra={
                                   "cmd": cmd,
                                   "ts": ts,
                                   "ctx": ctx,
                                   "sig_agent": sig_agent.hex(),
                                   "sig_user": sig_user.hex(),
                                   "agent_did": self.agent_did,
                                   "user_did": self.user_did,
                               })
        return msg, inject_tickets(msg, self.st_data, self.st_net)