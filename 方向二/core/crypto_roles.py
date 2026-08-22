"""
最小角色隔离（接口级，模拟）：限制各角色可用的 SM9 接口。

- VerifyOnlySM9：只允许 verify，不暴露 sign / derive_sk / proxy_sign。
- RestrictedSigner：只允许为指定 DID 集合签名。
- DeviceCrypto：只允许设备自己的 DID 签名 + 密钥交换。

标注：接口级角色隔离模拟，不等价于硬件密钥隔离。
"""


class VerifyOnlySM9:
    """只读验签器：中继/服务侧只能 verify，无法签名（接口隔离）。"""

    def __init__(self, sm9_engine):
        self._sm9 = sm9_engine

    def verify(self, did, message, signature):
        return self._sm9.verify(did, message, signature)


class RestrictedSigner:
    """受限签名器：只允许为指定 DID 集合签名（Relay 只能签 relay_did）。"""

    def __init__(self, sm9_engine, allowed_dids):
        self._sm9 = sm9_engine
        self._allowed = set(allowed_dids)

    def sign(self, did, message):
        if did not in self._allowed:
            raise PermissionError(f"sign for {did} not allowed")
        return self._sm9.sign(did, message)

    def verify(self, did, message, signature):
        return self._sm9.verify(did, message, signature)


class DeviceCrypto:
    """设备密码接口：只允许设备自己的 DID 签名 + 密钥交换。"""

    def __init__(self, sm9_engine, device_did):
        self._sm9 = sm9_engine
        self._did = device_did

    def sign(self, did, message):
        if did != self._did:
            raise PermissionError("device can only sign its own DID")
        return self._sm9.sign(did, message)

    def verify(self, did, message, signature):
        return self._sm9.verify(did, message, signature)

    def key_exchange_initiator(self, peer_did):
        return self._sm9.key_exchange_initiator(self._did, peer_did)

    def key_exchange_responder(self, peer_did, r_init):
        return self._sm9.key_exchange_responder(self._did, peer_did, r_init)

    def key_exchange_initiator_finish(self, state, r_resp):
        return self._sm9.key_exchange_initiator_finish(state, r_resp)
