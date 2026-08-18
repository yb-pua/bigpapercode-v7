"""
绑定表：user_bio_did ↔ device_did（模拟生物 DID，联动校验用）。

设备入网须关联已认证用户（绑定表 user_bio_did↔device_did）；
无绑定 / 绑定用户未认证 → 拒绝（《代码汇总版》§4.2 绑定校验）。
"""

from typing import Dict, List, Optional, Tuple


class BindingTable:
    """用户↔设备绑定表。"""

    def __init__(self):
        self._device_to_user: Dict[str, str] = {}
        self._user_to_devices: Dict[str, List[str]] = {}

    def bind(self, user_bio_did: str, device_did: str) -> None:
        self._device_to_user[device_did] = user_bio_did
        self._user_to_devices.setdefault(user_bio_did, [])
        if device_did not in self._user_to_devices[user_bio_did]:
            self._user_to_devices[user_bio_did].append(device_did)

    def unbind(self, device_did: str) -> None:
        user = self._device_to_user.pop(device_did, None)
        if user is not None:
            devices = self._user_to_devices.get(user, [])
            if device_did in devices:
                devices.remove(device_did)

    def owner_of(self, device_did: str) -> Optional[str]:
        """设备归属的用户生物 DID；未绑定返回 None。"""
        return self._device_to_user.get(device_did)

    def is_bound(self, device_did: str) -> bool:
        return device_did in self._device_to_user

    def devices_of(self, user_bio_did: str) -> List[str]:
        return list(self._user_to_devices.get(user_bio_did, []))

    def count(self) -> int:
        return len(self._device_to_user)

    def items(self) -> List[Tuple[str, str]]:
        return list(self._device_to_user.items())