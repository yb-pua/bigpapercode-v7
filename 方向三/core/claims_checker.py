"""
权限声明检查（方向三）：tool + action 级权限匹配。
ST_data 的 claims={tools, actions}，ClaimsChecker 做四步验证的第④步。
"""

from typing import Dict, List, Optional


class ClaimsChecker:
    """权限矩阵匹配器：claims 内 tool/action 级判定。"""

    def __init__(self, tools: Optional[List[str]] = None,
                 actions: Optional[List[str]] = None):
        # 全局可用 tool/action 白名单（权限矩阵的列）
        self.tools = list(tools) if tools else []
        self.actions = list(actions) if actions else []

    @staticmethod
    def _claims_of(st_data_claims: Optional[dict],
                   perm: Optional[dict] = None) -> dict:
        """从 ST_data 票据取 claims；兜底取 perm 字段。"""
        if st_data_claims:
            return st_data_claims
        if perm:
            return perm.get("claims", {})
        return {}

    def match(self, action: str, tool: str,
              claims: Optional[dict] = None,
              st_data: Optional[dict] = None,
              perm: Optional[dict] = None) -> bool:
        """判定 action+tool 是否在授权范围内。
        claims/perm/st_data 三选一（st_data 票据优先解析）。"""
        c = self._claims_of(claims, perm)
        if st_data is not None:
            perm_ = st_data.get("perm", {})
            c = perm_.get("claims", perm_)
        if not c:
            return False
        tools = c.get("tools", [])
        actions = c.get("actions", [])
        if tool not in tools:
            return False
        if "*" in actions or action in actions:
            return True
        return False

    def in_scope(self, action: str, tool: str,
                 st_data: Optional[dict] = None,
                 claims: Optional[dict] = None) -> bool:
        """测试/实验用别名。"""
        return self.match(action, tool, claims=claims, st_data=st_data)

    def __repr__(self) -> str:
        return f"ClaimsChecker(tools={len(self.tools)}, actions={len(self.actions)})"