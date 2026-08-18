"""
安全隧道（方向二）：SM9 密钥协商（两端以对方 DID 为公钥）→ 会话密钥；
SM4 加密载荷 + SM3 完整性 + 明文虚拟地址头（中继按地址头路由、不解密载荷）。

帧格式：
    frame = vaddr(4B) || sm4_cbc_encrypt(payload || seq(4B) || sm3(vaddr||seq||payload))
完整性：SM3(vaddr || seq || payload)，随载荷一起加密。
"""

import struct
from typing import Optional, Tuple

from .common import rand_bytes, sm3, sm4_cbc_decrypt, sm4_cbc_encrypt

VADDR_LEN = 4
SEQ_LEN = 4
MAC_LEN = 32


class Tunnel:
    """SM9 密钥协商 + 帧封装。会话密钥一致（验收 5）。"""

    def __init__(self, sm9_engine, my_did: str, peer_did: str):
        self.sm9 = sm9_engine
        self.my_did = my_did
        self.peer_did = peer_did
        self.session_key: Optional[bytes] = None

    # ------------------------------------------------------------------
    # 握手（复用 sm9_engine.key_exchange_*）
    # ------------------------------------------------------------------
    def handshake_initiator(self):
        """发起方：返回 (state, r_init)。"""
        return self.sm9.key_exchange_initiator(self.my_did, self.peer_did)

    def handshake_responder(self, r_init: bytes) -> Tuple[bytes, bytes]:
        """响应方：返回 (r_resp, session_key)。"""
        r_resp, key = self.sm9.key_exchange_responder(self.my_did, self.peer_did, r_init)
        self.session_key = key
        return r_resp, key

    def handshake_finish(self, state, r_resp: bytes) -> bytes:
        """发起方收尾：返回会话密钥。"""
        key = self.sm9.key_exchange_initiator_finish(state, r_resp)
        self.session_key = key
        return key

    # ------------------------------------------------------------------
    # 帧封装
    # ------------------------------------------------------------------
    def frame_encrypt(self, payload: bytes, dst_vaddr: str, seq: int,
                      key: Optional[bytes] = None) -> bytes:
        """封装：明文虚拟地址头 + SM4-CBC 密文（payload‖seq‖SM3 完整性）。"""
        key = key if key is not None else self.session_key
        if key is None:
            raise ValueError("tunnel session key not established")
        vaddr = bytes(int(x) for x in dst_vaddr.split("."))
        if len(vaddr) != VADDR_LEN:
            raise ValueError("invalid vaddr")
        mac = sm3(vaddr + struct.pack(">I", seq) + payload)
        inner = payload + struct.pack(">I", seq) + mac
        return vaddr + sm4_cbc_encrypt(inner, key)

    def frame_decrypt(self, frame: bytes, key: Optional[bytes] = None
                      ) -> Tuple[str, bytes, int]:
        """解封装：验 SM3 完整性 → 返回 (dst_vaddr, payload, seq)。"""
        key = key if key is not None else self.session_key
        if key is None:
            raise ValueError("tunnel session key not established")
        vaddr = ".".join(str(b) for b in frame[:VADDR_LEN])
        inner = sm4_cbc_decrypt(frame[VADDR_LEN:], key)
        payload = inner[:-SEQ_LEN - MAC_LEN]
        seq = struct.unpack(">I", inner[-SEQ_LEN - MAC_LEN:-MAC_LEN])[0]
        mac = inner[-MAC_LEN:]
        expected = sm3(frame[:VADDR_LEN] + struct.pack(">I", seq) + payload)
        if mac != expected:
            raise ValueError("integrity check failed")
        return vaddr, payload, seq

    def is_established(self) -> bool:
        return self.session_key is not None