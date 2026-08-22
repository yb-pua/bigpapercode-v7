"""
安全隧道（方向二）：SM9 密钥协商 → 会话密钥 → enc/mac 密钥派生；
SM4 加密载荷 + HMAC-SM3 完整性 + seq 重放拒绝 + 明文虚拟地址头路由。

密钥派生：
    enc_key = SM3(session_key || "enc")
    mac_key = SM3(session_key || "mac")

帧格式：
    frame = vaddr(4B) || seq(4B) || ciphertext || HMAC-SM3(mac_key, vaddr||seq||ciphertext)

完整性：HMAC-SM3 覆盖 vaddr/seq/ciphertext；MAC 失败不返回明文。
重放：接收端维护已接收 seq 集合，相同 seq 第二次返回 frame_replay。
"""

import hmac as _hmac
import struct
from typing import Optional, Tuple

from .common import hmac_sm3, sm3, sm4_cbc_decrypt, sm4_cbc_encrypt

VADDR_LEN = 4
SEQ_LEN = 4
MAC_LEN = 32


def _derive_keys(session_key: bytes) -> Tuple[bytes, bytes]:
    enc_key = sm3(session_key + b"enc")
    mac_key = sm3(session_key + b"mac")
    return enc_key, mac_key


class Tunnel:
    """SM9 密钥协商 + 帧封装（HMAC-SM3 + seq 重放拒绝）。"""

    def __init__(self, sm9_engine, my_did: str, peer_did: str):
        self.sm9 = sm9_engine
        self.my_did = my_did
        self.peer_did = peer_did
        self.session_key: Optional[bytes] = None
        self._received_seqs = set()   # 接收序号集合（重放拒绝）

    # ------------------------------------------------------------------
    # 握手（复用 sm9_engine.key_exchange_*）
    # ------------------------------------------------------------------
    def handshake_initiator(self):
        return self.sm9.key_exchange_initiator(self.my_did, self.peer_did)

    def handshake_responder(self, r_init: bytes) -> Tuple[bytes, bytes]:
        r_resp, key = self.sm9.key_exchange_responder(self.my_did, self.peer_did, r_init)
        self.session_key = key
        return r_resp, key

    def handshake_finish(self, state, r_resp: bytes) -> bytes:
        key = self.sm9.key_exchange_initiator_finish(state, r_resp)
        self.session_key = key
        return key

    # ------------------------------------------------------------------
    # 帧封装
    # ------------------------------------------------------------------
    def frame_encrypt(self, payload: bytes, dst_vaddr: str, seq: int,
                      key: Optional[bytes] = None) -> bytes:
        """封装：明文 vaddr/seq 头 + SM4 密文 + HMAC-SM3。"""
        key = key if key is not None else self.session_key
        if key is None:
            raise ValueError("tunnel session key not established")
        vaddr = bytes(int(x) for x in dst_vaddr.split("."))
        if len(vaddr) != VADDR_LEN:
            raise ValueError("invalid vaddr")
        enc_key, mac_key = _derive_keys(key)
        seq_bytes = struct.pack(">I", seq)
        ciphertext = sm4_cbc_encrypt(payload, enc_key)
        mac = hmac_sm3(mac_key, vaddr + seq_bytes + ciphertext)
        return vaddr + seq_bytes + ciphertext + mac

    def frame_decrypt(self, frame: bytes, key: Optional[bytes] = None
                      ) -> Tuple[str, bytes, int]:
        """解封装：验 HMAC（compare_digest）→ 重放拒绝 → 解密 → 返回 (vaddr, payload, seq)。"""
        key = key if key is not None else self.session_key
        if key is None:
            raise ValueError("tunnel session key not established")
        if len(frame) < VADDR_LEN + SEQ_LEN + MAC_LEN:
            raise ValueError("frame too short")
        vaddr_bytes = frame[:VADDR_LEN]
        seq_bytes = frame[VADDR_LEN:VADDR_LEN + SEQ_LEN]
        ciphertext = frame[VADDR_LEN + SEQ_LEN:-MAC_LEN]
        mac = frame[-MAC_LEN:]
        enc_key, mac_key = _derive_keys(key)
        expected_mac = hmac_sm3(mac_key, vaddr_bytes + seq_bytes + ciphertext)
        # MAC 失败：不返回明文
        if not _hmac.compare_digest(mac, expected_mac):
            raise ValueError("integrity check failed")
        seq = struct.unpack(">I", seq_bytes)[0]
        if seq in self._received_seqs:
            raise ValueError("frame_replay")
        self._received_seqs.add(seq)
        payload = sm4_cbc_decrypt(ciphertext, enc_key)
        vaddr = ".".join(str(b) for b in vaddr_bytes)
        return vaddr, payload, seq

    def is_established(self) -> bool:
        return self.session_key is not None
