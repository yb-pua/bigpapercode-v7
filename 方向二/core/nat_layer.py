"""
虚拟 NAT 层（方向二）：4 类 NAT + 打洞判定表（RFC 4787/5389/5766 理论矩阵）。

类型：full_cone / restricted_cone / port_restricted / symmetric。

判定表（写死，README 记录假设）：
    - full_cone 接受任意入包 → 可与一切类型直连；
    - restricted_cone 仅接受"曾向其发过包"的源 IP → 与 symmetric 失败；
    - port_restricted 额外要求精确源端口 → 与 restricted/symmetric 失败
      （对方换端口/端口不匹配）；同型对假设端口保持稳定 → 可行；
    - symmetric 每连接独立端口映射 → 仅可连 full_cone。
兜底率推导：按 NAT 类型分布计算需中继兜底比例（可复算，README 记录）。
"""

from typing import Dict, List, Optional, Tuple

NAT_TYPES = ["full_cone", "restricted_cone", "port_restricted", "symmetric"]

# 打洞可行性判定表：(src_type, dst_type) -> 直连可行？
PUNCH_MATRIX = {
    ("full_cone", "full_cone"): True,
    ("full_cone", "restricted_cone"): True,
    ("full_cone", "port_restricted"): True,
    ("full_cone", "symmetric"): True,
    ("restricted_cone", "full_cone"): True,
    ("restricted_cone", "restricted_cone"): True,
    ("restricted_cone", "port_restricted"): True,
    ("restricted_cone", "symmetric"): False,
    ("port_restricted", "full_cone"): True,
    ("port_restricted", "restricted_cone"): False,
    ("port_restricted", "port_restricted"): True,
    ("port_restricted", "symmetric"): False,
    ("symmetric", "full_cone"): True,
    ("symmetric", "restricted_cone"): False,
    ("symmetric", "port_restricted"): False,
    ("symmetric", "symmetric"): False,
}


def try_punch(src_type: str, dst_type: str) -> bool:
    """打洞判定：类型对 → 直连可行？"""
    return PUNCH_MATRIX.get((src_type, dst_type), False)


def derive_relay_needed(nat_distribution: Dict[str, float]) -> Tuple[float, float]:
    """兜底率推导：随机设备对（独立同分布）需中继的比例。
    返回 (需中继比例, 可直连比例)。分布字典如 {"full_cone": 0.25, ...}。
    推导式（README 可复算）：P(需中继) = Σ_{s,d} p_s·p_d·(1 - punch(s,d))。
    """
    types = list(nat_distribution.keys())
    probs = [nat_distribution[t] for t in types]
    direct = 0.0
    for i, s in enumerate(types):
        for j, d in enumerate(types):
            if try_punch(s, d):
                direct += probs[i] * probs[j]
    return (1.0 - direct), direct


class VirtualNAT:
    """设备侧虚拟 NAT 层：类型可配；打洞逻辑 = 判定表 + 模拟端口映射。"""

    def __init__(self, nat_type: str = "full_cone", port_stable: bool = True):
        if nat_type not in NAT_TYPES:
            raise ValueError(f"unknown NAT type: {nat_type}")
        self.nat_type = nat_type
        self.port_stable = port_stable

    def punch(self, dst_type: str) -> bool:
        """本节点向对端类型打洞：判定表结果 ∧ 端口稳定性约束。"""
        if not try_punch(self.nat_type, dst_type):
            return False
        if self.nat_type == "port_restricted" and not self.port_stable:
            return False
        return True