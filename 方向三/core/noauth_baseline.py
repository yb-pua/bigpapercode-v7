"""
无管控基线（方向三）：裸 MCP 直连工具，无任何认证（安全功能=0，显式声明）。
"""


class NoAuthBaseline:
    """无认证直连工具：所有调用放行（安全属性全部为 0，作对照下界）。"""

    def __init__(self):
        self.calls = 0

    def call_tool(self, cmd: dict) -> dict:
        self.calls += 1
        return {"ok": True,
                "result": {"executed": True, "tool": cmd.get("tool")}}