"""
OAuth 基线（方向三）：授权码 + PKCE + token 直连（同环境自实现）。
忠实复刻实测现状缺陷：一次性授权后 server 级授权态缓存复用
（cache_auth_state=True 默认），供 C3-6 调用者混淆攻击打穿对照。
"""

import hashlib
import json
import secrets
from typing import Dict, Optional, Tuple


class OAuthBaseline:
    """OAuth 2.1 直连基线（授权码 + PKCE，token 直连工具）。"""

    def __init__(self, cache_auth_state: bool = True):
        self.cache_auth_state = cache_auth_state
        self.clients = {}                 # client_id -> {name}
        self.auth_codes = {}              # code -> {client_id, verifier, scopes}
        self.tokens = {}                  # token -> {client_id, scopes}
        self.auth_state = {}              # client_id -> scopes（授权态缓存）

    def register_client(self, client_id: str) -> None:
        self.clients[client_id] = {"id": client_id}

    def authorize(self, client_id: str, scopes: list,
                  code_verifier: str) -> Optional[str]:
        """授权端点：颁发授权码（PKCE 记录 verifier）。"""
        if client_id not in self.clients:
            return None
        code = secrets.token_hex(16)
        self.auth_codes[code] = {
            "client_id": client_id, "verifier": code_verifier,
            "scopes": list(scopes),
        }
        return code

    def exchange(self, client_id: str, code: str,
                 code_verifier: str) -> Optional[str]:
        """token 端点：验证 PKCE → 颁发 token；记录授权态缓存。"""
        ac = self.auth_codes.pop(code, None)
        if ac is None or ac["client_id"] != client_id:
            return None
        if not secrets.compare_digest(ac["verifier"], code_verifier):
            return None
        token = secrets.token_hex(24)
        self.tokens[token] = {"client_id": client_id, "scopes": ac["scopes"]}
        if self.cache_auth_state:
            self.auth_state[client_id] = ac["scopes"]
        return token

    def call_tool(self, token: str, client_id: str, cmd: dict) -> dict:
        """工具调用：缺陷复刻——token 有效且其归属 client 有授权态缓存即放行，
        **不验证调用者身份与 token 绑定**（C3-6 调用者混淆由此打穿）；
        scope 为 server 级粒度，不区分 tool（C3-2 越权由此放行）。"""
        if token not in self.tokens:
            return {"ok": False, "error": "invalid_token"}
        if self.cache_auth_state:
            owner = self.tokens[token]["client_id"]
            scopes = self.auth_state.get(owner)
            if scopes is None:
                return {"ok": False, "error": "client_not_authorized"}
        return {"ok": True, "result": {"executed": True, "tool": cmd.get("tool")}}

    def revoke(self, token: str) -> None:
        self.tokens.pop(token, None)