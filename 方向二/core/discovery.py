"""
节点发现与拓扑（简化方案）：协调服务注册/公告 + find_node（DHT 简化替代）
+ 中继邻居表星型拓扑（《代码汇总版》§4.3 discovery.py）。

标注：以集中信令替代 DHT 实现节点发现，拓扑为星型；
证明"分布式组网技术可支撑票据化准入"即可。
"""

import time
from typing import Callable, Dict, List, Optional


class DiscoveryService:
    """协调服务（controller 兼任）：设备注册/公告 + find_node + 拓扑构建。"""

    def __init__(self, relay_dids: Optional[List[str]] = None,
                 now_fn: Optional[Callable[[], float]] = None):
        self._registry: Dict[str, dict] = {}          # did -> {addr, registered_at}
        self._relays: List[str] = list(relay_dids or [])
        self._now_fn = now_fn or time.time

    def register_device(self, did: str, addr: str) -> dict:
        entry = {"did": did, "addr": addr, "registered_at": self._now_fn()}
        self._registry[did] = entry
        return entry

    def unregister_device(self, did: str) -> None:
        self._registry.pop(did, None)

    def find_node(self, did: str) -> Optional[str]:
        """查询节点地址；未知返回 None。"""
        entry = self._registry.get(did)
        return entry["addr"] if entry else None

    def add_relay(self, relay_did: str) -> None:
        if relay_did not in self._relays:
            self._relays.append(relay_did)

    def build_topology(self) -> dict:
        """星型拓扑：中继邻居表 = 全部已注册设备（按默认中继分组）。"""
        topology = {relay_did: [] for relay_did in self._relays}
        for did in self._registry:
            if self._relays:
                relay = self._relays[hash(did) % len(self._relays)]
                topology[relay].append(did)
        return topology

    def device_count(self) -> int:
        return len(self._registry)