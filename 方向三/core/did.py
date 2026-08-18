"""
DID（去中心化标识）：didsm9:<user_id>:<SM3哈希>，冲突重试。

冲突重试策略：首次 h0 = SM3(user_id)；若与既有 DID 冲突（不同 user_id 产生
同一 DID），则 h_{n+1} = SM3(user_id || n)，直至无冲突。
"""

from typing import Dict, Optional

from .common import sm3


def _hash(user_id: str, retry: int) -> str:
    data = user_id.encode("utf-8")
    if retry:
        data += retry.to_bytes(4, "big")
    return sm3(data).hex()


class DIDRegistry:
    """DID 注册表：维护 user_id → DID 映射，提供冲突检测与重试。"""

    def __init__(self):
        self._user_to_did: Dict[str, str] = {}
        self._did_to_user: Dict[str, str] = {}

    def register(self, user_id: str, retry_limit: int = 16) -> str:
        if user_id in self._user_to_did:
            return self._user_to_did[user_id]
        for retry in range(retry_limit):
            did = make_user_did(user_id, retry)
            if did not in self._did_to_user:
                self._user_to_did[user_id] = did
                self._did_to_user[did] = user_id
                return did
        raise RuntimeError(f"DID collision beyond retry limit for {user_id}")

    def lookup(self, did: str) -> Optional[str]:
        return self._did_to_user.get(did)

    def user_did(self, user_id: str) -> Optional[str]:
        return self._user_to_did.get(user_id)


def make_user_did(user_id: str, retry: int = 0) -> str:
    """构造用户 DID：didsm9:<user_id>:<SM3哈希>。retry>0 表示冲突重试轮次。"""
    return f"didsm9:{user_id}:{_hash(user_id, retry)}"


def make_device_did(device_id: str, owner_user_id: str, retry: int = 0) -> str:
    """构造设备 DID：didsm9:<device_id>@<user_id>:<SM3哈希>。"""
    composite = f"{device_id}@{owner_user_id}"
    return f"didsm9:{composite}:{_hash(composite, retry)}"