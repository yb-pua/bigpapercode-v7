"""
SM9 引擎：KGC 基于 DID 派生私钥、签名/验签，以及预留接口
（verify_chain / key_exchange_initiator / key_exchange_responder /
proxy_sign / proxy_verify）。

实现路径：gmalg 真实实现（首选）；gmalg 接口不可用 → 模拟实现
（SM3 系构造）并通过 is_real_gmalg() / impl 字段显式标注。
"""

import base64
import json
import threading
from typing import Dict, Optional, Tuple

from .common import hmac_sm3, rand_bytes, sm3

HID_SIGN = b"\x01"
HID_ENC = b"\x02"

try:
    from gmalg import SM9, SM9KGC, KEYXCHG_MODE

    GMALG_AVAILABLE = True
except ImportError:
    GMALG_AVAILABLE = False


def _b64(data: bytes) -> str:
    return base64.b64encode(data).decode("ascii")


class SM9Engine:
    """SM9 引擎：KGC（模拟 TEE 外部派生）＋ 本地签名验签。"""

    def __init__(self, master_key: Optional[bytes] = None):
        self.impl = "gmalg" if GMALG_AVAILABLE else "simulated"
        self._master_key = master_key or sm3(b"sm9_kgc_master")
        self._mpk_s = None
        self._mpk_e = None
        self._kgc = None
        self._user_sk_s: Dict[str, bytes] = {}
        self._user_sk_e: Dict[str, bytes] = {}
        self._verify_retries = 0
        self._verify_errors = 0
        self._lock = threading.RLock()
        if GMALG_AVAILABLE:
            self._init_gmalg()

    def verify_retry_count(self) -> int:
        """重验次数统计（gmalg 偶发失败兜底，README 记录可迭代）。"""
        return self._verify_retries

    def _init_gmalg(self):
        kgc = SM9KGC(hid_s=HID_SIGN, hid_e=HID_ENC)
        self._msk_s, self._mpk_s = kgc.generate_keypair_sign()
        self._msk_e, self._mpk_e = kgc.generate_keypair_encrypt()
        self._kgc = SM9KGC(hid_s=HID_SIGN, hid_e=HID_ENC,
                           msk_s=self._msk_s, mpk_s=self._mpk_s,
                           msk_e=self._msk_e, mpk_e=self._mpk_e)

    def is_real_gmalg(self) -> bool:
        return self.impl == "gmalg"

    # ------------------------------------------------------------------
    # KGC 派生
    # ------------------------------------------------------------------
    def derive_sk(self, did: str) -> Tuple[bytes, bytes]:
        """基于 DID 派生 SM9 用户私钥（签名私钥, 加密私钥）。线程安全。"""
        with self._lock:
            uid = did.encode("utf-8")
            if GMALG_AVAILABLE:
                sk_s = self._kgc.generate_sk_sign(uid)
                sk_e = self._kgc.generate_sk_encrypt(uid)
            else:
                sk_s = hmac_sm3(self._master_key, uid + b"sm9_sign")
                sk_e = hmac_sm3(self._master_key, uid + b"sm9_enc")
            self._user_sk_s[did] = sk_s
            self._user_sk_e[did] = sk_e
            return sk_s, sk_e

    def has_key(self, did: str) -> bool:
        return did in self._user_sk_s

    # ------------------------------------------------------------------
    # 签名 / 验签
    # ------------------------------------------------------------------
    def sign(self, did: str, message: bytes) -> bytes:
        with self._lock:
            if did not in self._user_sk_s:
                self.derive_sk(did)
            uid = did.encode("utf-8")
            if GMALG_AVAILABLE:
                # gmalg 的 sign 返回 (int_to_bytes(h), point_to_bytes_1(S))：
                # h 为变长（最高字节为 0 时省略前导零，概率 ~1/256），而 verify
                # 端按 signature[:32] 切分 h → h 短 1 字节会把 S 的 PC 字节吞掉，
                # 抛 InvalidPCError 被吞 → 偶发验签失败（~0.4%，与 1/256 吻合）。
                # 修复：h 左侧补零到固定 32 字节（bytes_to_int 逆操作精确无损）。
                sm9 = SM9(hid_s=HID_SIGN, mpk_s=self._mpk_s,
                          sk_s=self._user_sk_s[did], uid=uid)
                h, s = sm9.sign(message)
                if len(h) < 32:
                    h = b"\x00" * (32 - len(h)) + h
                return h + s
            # 模拟实现（标注 simulated）：HMAC-SM3 签名
            sig = hmac_sm3(self._user_sk_s[did], message)
            return sig

    def verify(self, did: str, message: bytes, signature: bytes) -> bool:
        with self._lock:
            uid = did.encode("utf-8")
            if GMALG_AVAILABLE:
                try:
                    if len(signature) in (96, 97):
                        h, s = signature[:32], signature[32:]
                        sm9 = SM9(hid_s=HID_SIGN, mpk_s=self._mpk_s, uid=uid)
                        ok = bool(sm9.verify(message, h, s))
                        if not ok:
                            # 工程兜底：同参数重验一次（gmalg 偶发失败；
                            # 伪造签名重验仍失败，不影响安全性）。
                            self._verify_retries += 1
                            sm9 = SM9(hid_s=HID_SIGN, mpk_s=self._mpk_s, uid=uid)
                            ok = bool(sm9.verify(message, h, s))
                        return ok
                except Exception:
                    # 瞬态异常兜底：重试一次
                    try:
                        self._verify_retries += 1
                        sm9 = SM9(hid_s=HID_SIGN, mpk_s=self._mpk_s, uid=uid)
                        return bool(sm9.verify(message, h, s))
                    except Exception:
                        self._verify_errors += 1
                        return False
                return False
            sk = hmac_sm3(self._master_key, uid + b"sm9_sign")
            return hmac_sm3(sk, message) == signature

    # ------------------------------------------------------------------
    # 预留接口（方向二/三使用，单测通过即可）
    # ------------------------------------------------------------------
    def verify_chain(self, entries: list) -> bool:
        """顺序验签链：entries = [(did, message, signature), ...]，
        要求相邻两条消息存在顺序绑定（后者消息以 前者消息的SM3哈希 结尾）。"""
        prev_hash = None
        for did, message, signature in entries:
            if prev_hash is not None:
                if not message.endswith(prev_hash):
                    return False
            if not self.verify(did, message, signature):
                return False
            prev_hash = sm3(message)
        return True

    def key_exchange_initiator(self, my_did: str, peer_did: str) -> Tuple[object, bytes]:
        """发起方第一步：返回 (session_state, R_init)。"""
        uid_peer = peer_did.encode("utf-8")
        if GMALG_AVAILABLE:
            if my_did not in self._user_sk_e:
                self.derive_sk(my_did)
            sm9 = SM9(hid_e=HID_ENC, mpk_e=self._mpk_e,
                      sk_e=self._user_sk_e[my_did], uid=my_did.encode("utf-8"))
            r, r_point = sm9.begin_key_exchange(uid_peer)
            return (sm9, r, r_point, uid_peer), r_point
        secret = hmac_sm3(self._master_key, my_did.encode("utf-8"))
        return ("simulated", secret), rand_bytes(32, "kx_r_init")

    def key_exchange_responder(self, my_did: str, peer_did: str,
                               r_init: bytes) -> Tuple[bytes, bytes]:
        """响应方：返回 (R_resp, session_key)。"""
        uid_peer = peer_did.encode("utf-8")
        if GMALG_AVAILABLE:
            if my_did not in self._user_sk_e:
                self.derive_sk(my_did)
            sm9 = SM9(hid_e=HID_ENC, mpk_e=self._mpk_e,
                      sk_e=self._user_sk_e[my_did], uid=my_did.encode("utf-8"))
            r_resp, r_point = sm9.begin_key_exchange(uid_peer)
            key = sm9.end_key_exchange(32, r_resp, r_point, uid_peer,
                                       r_init, KEYXCHG_MODE.RESPONDER)
            return r_point, key
        secret = hmac_sm3(self._master_key, my_did.encode("utf-8"))
        shared = hmac_sm3(secret, r_init)
        return shared, sm3(shared + b"kx_key")

    def key_exchange_initiator_finish(self, session_state: object,
                                      r_resp: bytes) -> bytes:
        """发起方第二步：用响应方的 R 计算会话密钥。"""
        if GMALG_AVAILABLE:
            sm9, r, r_point, uid_peer = session_state
            return sm9.end_key_exchange(32, r, r_point,
                                        uid_peer, r_resp, KEYXCHG_MODE.INITIATOR)
        _simulated, secret = session_state
        shared = hmac_sm3(secret, r_resp)
        return sm3(shared + b"kx_key")

    def _sig_len(self) -> int:
        return 97 if GMALG_AVAILABLE else 32

    def proxy_sign(self, delegatee_did: str, delegator_did: str,
                   message: bytes) -> bytes:
        """代理签名（模拟构造）：delegator 授权，delegatee 代签。
        结构 = delegator 授权声明签名 || delegatee 对 (消息||授权声明) 的签名。"""
        warrant = json.dumps({
            "delegator": delegator_did,
            "delegatee": delegatee_did,
            "purpose": "proxy",
        }, sort_keys=True).encode("utf-8")
        warrant_sig = self.sign(delegator_did, warrant)
        inner = message + warrant + warrant_sig
        return warrant + warrant_sig + self.sign(delegatee_did, inner)

    def proxy_verify(self, delegatee_did: str, message: bytes,
                     proxy_signature: bytes) -> bool:
        """代理验签：验 delegatee 签名 + 授权声明有效性。"""
        sig_len = self._sig_len()
        if len(proxy_signature) < sig_len * 2:
            return False
        warrant = proxy_signature[:-sig_len * 2]
        warrant_sig = proxy_signature[-sig_len * 2:-sig_len]
        inner_sig = proxy_signature[-sig_len:]
        try:
            w = json.loads(warrant.decode("utf-8"))
        except Exception:
            return False
        delegator_did = w.get("delegator")
        if not delegator_did or w.get("delegatee") != delegatee_did:
            return False
        if not self.verify(delegator_did, warrant, warrant_sig):
            return False
        inner = message + warrant + warrant_sig
        return self.verify(delegatee_did, inner, inner_sig)

    def _derive_self_enc_key(self):
        if GMALG_AVAILABLE:
            sk_e = self._kgc.generate_sk_encrypt(b"kgc_self")
            self._user_sk_e["kgc_self"] = sk_e