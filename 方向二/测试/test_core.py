"""
方向二 core 单测（验收对照《代码汇总版》§4.5）：

1. 票据：篡改/过期/伪造/重放全部失败；claims_checker 被调用；ticket_id 生成；
2. 代理伪造：授权书范围外签发凭证 100% 无效；
3. 隧道：两端协商密钥相等；中继 dump 仅见密文（明文泄露率=0）；
4. 整形：冗余率 ≤15%；整形后包长熵提升、KL 散度下降；
5. NAT：类型对直连判定与理论矩阵一致；兜底率按分布推导可复算；
6. 三重验证：6 类节点分类正确（合法通过、其余拒绝）；无绑定节点拒绝；
7. 超 30min ST 拒绝；重放 ST 第二次拒绝（单次缓存）；
8. 常量：30min / ticket_id / didsm9 / NetPerm / warrant。
"""

import time

import pytest

from core.authorization import (issue_auth, issue_session_credential,
                                proxy_delegate, proxy_verify,
                                verify_auth, verify_session_credential)
from core.binding_table import BindingTable
from core.common import rand_bytes, sm3
from core.device import Device
from core.discovery import DiscoveryService
from core.did import make_device_did
from core.kdc import KDC
from core.nat_layer import (PUNCH_MATRIX, NAT_TYPES, VirtualNAT,
                            derive_relay_needed, try_punch)
from core.relay import Relay
from core.shaping import (Shaper, kl_divergence, packet_stats,
                          redundancy_rate)
from core.sm9_engine import SM9Engine
from core.st_ticket import STService, TICKET_TTL, netperm_defaults
from core.tunnel import Tunnel

REALM_SERVICE = "relay@realm"


@pytest.fixture(scope="module")
def sm9():
    return SM9Engine()


@pytest.fixture(scope="module")
def netperm():
    p = netperm_defaults()
    p["services"] = ["file-sync", "rtc"]
    p["bandwidth_mbps"] = 10.0
    return p


def make_world(sm9, netperm, bind=True, ttl=1800.0):
    """构造 KDC + 中继 + 设备世界。"""
    kdc = KDC(sm9)
    kdc.register_user("didsm9:user1:aaa")
    kdc.register_user("didsm9:user2:bbb", authenticated=False)
    relay = Relay(sm9, kdc, relay_id="relay-1")
    relay.setup_proxy()
    dev = Device("dev-1", "didsm9:user1:aaa", sm9)
    if bind:
        assert dev.enroll(kdc)
    dev.obtain_authorization(kdc, netperm, ttl=ttl)
    return kdc, relay, dev


def do_admission(relay, dev):
    """完整两轮准入。"""
    r1 = relay.begin_admission(dev.admission_round1(), REALM_SERVICE)
    assert r1["ok"], r1
    r2 = dev.admission_round2(r1["challenge"])
    fin = relay.finish_admission(dev.admission_round1(), r1["challenge"],
                                 r2["sig"], r2["nonce"], r2["ts"], REALM_SERVICE)
    assert fin["ok"], fin
    return fin


# ----------------------------------------------------------------------
# 1. 票据
# ----------------------------------------------------------------------

class TestTicket:
    def test_issue_verify_ok(self, sm9, netperm):
        st = STService(sm9, make_device_did("kdc", "realm"))
        kdc_did = make_device_did("kdc", "realm")
        st = STService(sm9, kdc_did)
        t = st.issue_ticket("didsm9:dev-1@user1:aaa", REALM_SERVICE, netperm)
        assert len(t["ticket_id"]) == 32
        assert t["sname"] == REALM_SERVICE
        r = st.verify_ticket(t, REALM_SERVICE)
        assert r["ok"]
        assert r["claims"]["netperm"]["bandwidth_mbps"] == 10.0

    def test_tamper_rejected(self, sm9, netperm):
        kdc_did = make_device_did("kdc", "realm")
        st = STService(sm9, kdc_did)
        t = st.issue_ticket("didsm9:dev-1@user1:aaa", REALM_SERVICE, netperm)
        t["netperm"]["bandwidth_mbps"] = 100.0
        r = st.verify_ticket(t, REALM_SERVICE)
        assert not r["ok"]

    def test_expired_rejected(self, sm9, netperm):
        kdc_did = make_device_did("kdc", "realm")
        st = STService(sm9, kdc_did)
        t = st.issue_ticket("didsm9:dev-1@user1:aaa", REALM_SERVICE, netperm)
        r = st.verify_ticket(t, REALM_SERVICE, now=t["times"]["end"] + 1801.0)
        assert not r["ok"]

    def test_forged_rejected(self, sm9, netperm):
        kdc_did = make_device_did("kdc", "realm")
        evil = STService(sm9, make_device_did("evil", "attacker"))
        t = evil.issue_ticket("didsm9:dev-1@user1:aaa", REALM_SERVICE, netperm)
        good = STService(sm9, kdc_did)
        r = good.verify_ticket(t, REALM_SERVICE)
        assert not r["ok"]

    def test_replay_second_rejected(self, sm9, netperm):
        kdc_did = make_device_did("kdc", "realm")
        st = STService(sm9, kdc_did)
        t = st.issue_ticket("didsm9:dev-1@user1:aaa", REALM_SERVICE, netperm)
        cache = {}
        assert st.verify_ticket(t, REALM_SERVICE, replay_cache=cache)["ok"]
        r = st.verify_ticket(t, REALM_SERVICE, replay_cache=cache)
        assert not r["ok"] and r["error"] == "replay_detected"

    def test_claims_checker_called(self, sm9, netperm):
        kdc_did = make_device_did("kdc", "realm")
        st = STService(sm9, kdc_did)
        t = st.issue_ticket("didsm9:dev-1@user1:aaa", REALM_SERVICE, netperm)
        calls = []
        def checker(claims):
            calls.append(claims)
            return claims["netperm"]["bandwidth_mbps"] <= 10.0
        assert st.verify_ticket(t, REALM_SERVICE, claims_checker=checker)["ok"]
        assert len(calls) == 1
        def deny(claims):
            return False
        assert not st.verify_ticket(t, REALM_SERVICE, claims_checker=deny)["ok"]


# ----------------------------------------------------------------------
# 2. 授权 / 代理伪造
# ----------------------------------------------------------------------

class TestAuthorization:
    def test_auth_verify(self, sm9):
        kdc_did = make_device_did("kdc", "realm")
        sm9.derive_sk(kdc_did)
        a = issue_auth(sm9, kdc_did, "didsm9:dev-1@user1:aaa",
                       {"services": ["rtc"]}, exp=time.time() + 1800)
        assert verify_auth(sm9, a)
        a["policy"]["bandwidth_mbps"] = 999
        assert not verify_auth(sm9, a)

    def test_proxy_scope_bound(self, sm9):
        """授权书范围外签发凭证 100% 无效（B4-8）。"""
        kdc_did = make_device_did("kdc", "realm")
        relay_did = make_device_did("relay-1", "realm")
        sm9.derive_sk(kdc_did)
        sm9.derive_sk(relay_did)
        warrant = proxy_delegate(sm9, kdc_did, relay_did, scope=["session_credential"])
        # 合法：scope 内签发会话准入凭证
        cred = issue_session_credential(
            sm9, relay_did, warrant, "didsm9:dev-1@user1:aaa",
            {"services": ["rtc"]}, "relay@realm", exp=time.time() + 1800)
        assert verify_session_credential(sm9, cred)
        # 越界：中继用代理密钥签发"新授权"（scope 外）→ 拒绝
        payload = {"kind": "new_authorization", "did": "didsm9:evil:xx",
                   "policy": {"services": ["*"]}}
        import json
        msg = json.dumps(payload, sort_keys=True).encode()
        sig = sm9.sign(relay_did, msg)
        assert not proxy_verify(sm9, warrant, msg, sig, "authorization")
        # 越界：伪造新票据（scope=st_issue）→ 拒绝
        assert not proxy_verify(sm9, warrant, msg, sig, "st_issue")

    def test_warrant_tamper(self, sm9):
        kdc_did = make_device_did("kdc", "realm")
        relay_did = make_device_did("relay-1", "realm")
        sm9.derive_sk(kdc_did)
        sm9.derive_sk(relay_did)
        warrant = proxy_delegate(sm9, kdc_did, relay_did, scope=["session_credential"])
        warrant["scope"] = ["*", "authorization"]
        msg = b"anything"
        sig = sm9.sign(relay_did, msg)
        assert not proxy_verify(sm9, warrant, msg, sig, "session_credential")


# ----------------------------------------------------------------------
# 3. 三重验证 / 准入
# ----------------------------------------------------------------------

class TestAdmission:
    def test_legal_device_passes(self, sm9, netperm):
        kdc, relay, dev = make_world(sm9, netperm)
        fin = do_admission(relay, dev)
        assert fin["vaddr"].startswith("10.200.")
        assert fin["credential"]["did"] == dev.did
        assert relay.verify_credential(fin["credential"])

    def test_unbound_device_rejected(self, sm9, netperm):
        kdc, relay, dev = make_world(sm9, netperm, bind=False)
        r1 = relay.begin_admission(dev.admission_round1(), REALM_SERVICE)
        assert not r1["ok"] and r1["error"] == "binding_rejected"

    def test_unbound_user_rejected(self, sm9, netperm):
        kdc, relay, dev = make_world(sm9, netperm, bind=True)
        # 用户2 未认证：设备绑定到未认证用户 → 拒绝
        dev2 = Device("dev-2", "didsm9:user2:bbb", sm9)
        assert not dev2.enroll(kdc)
        dev2.obtain_authorization(kdc, netperm)
        r1 = relay.begin_admission(dev2.admission_round1(), REALM_SERVICE)
        assert not r1["ok"] and r1["error"] == "binding_rejected"

    def test_expired_st_rejected(self, sm9, netperm):
        kdc, relay, dev = make_world(sm9, netperm, ttl=10.0)
        # 推进时钟 31 分钟
        def later():
            return time.time() + 1860.0
        relay._now_fn = later
        r1 = relay.begin_admission(dev.admission_round1(), REALM_SERVICE)
        assert not r1["ok"]

    def test_forged_auth_rejected(self, sm9, netperm):
        kdc, relay, dev = make_world(sm9, netperm)
        evil = SM9Engine()
        evil_kdc = make_device_did("evil-kdc", "attacker")
        evil.derive_sk(evil_kdc)
        dev.auth = issue_auth(evil, evil_kdc, dev.did,
                              {"services": ["*"]}, exp=time.time() + 1800)
        r1 = relay.begin_admission(dev.admission_round1(), REALM_SERVICE)
        assert not r1["ok"] and r1["stage"] == "authorize"

    def test_did_spoofing_rejected(self, sm9, netperm):
        """合法票据 + 错误设备私钥：挑战应答失败（DID 冒用）。"""
        kdc, relay, dev = make_world(sm9, netperm)
        r1 = relay.begin_admission(dev.admission_round1(), REALM_SERVICE)
        # 冒用者用自己私钥签应答（无 dev.did 私钥）
        attacker = Device("dev-99", "didsm9:user1:aaa", sm9)
        nonce = rand_bytes(16, "attk")
        import json as _j
        msg = _j.dumps({"did": dev.did, "challenge": r1["challenge"].hex(),
                        "nonce": nonce.hex(), "ts": time.time()}, sort_keys=True).encode()
        sig = attacker.sm9.sign(attacker.did, msg)
        fin = relay.finish_admission(dev.admission_round1(), r1["challenge"],
                                     sig, nonce, time.time(), REALM_SERVICE)
        assert not fin["ok"] and fin["stage"] == "challenge"

    def test_replay_st_rejected_second_time(self, sm9, netperm):
        kdc, relay, dev = make_world(sm9, netperm)
        assert do_admission(relay, dev)["ok"]
        dev2 = Device("dev-2", "didsm9:user1:aaa", sm9)
        dev2.auth = dev.auth
        dev2.st = dev.st                      # 重放同一 ST
        r1 = relay.begin_admission(dev2.admission_round1(), REALM_SERVICE)
        assert not r1["ok"] and r1["error"] == "replay_detected"


# ----------------------------------------------------------------------
# 4. 隧道
# ----------------------------------------------------------------------

class TestTunnel:
    def test_session_keys_equal(self, sm9):
        kdc = KDC(sm9)
        did_a = make_device_did("dev-a", "u1")
        did_b = make_device_did("dev-b", "u1")
        sm9.derive_sk(did_a)
        sm9.derive_sk(did_b)
        ta = Tunnel(sm9, did_a, did_b)
        tb = Tunnel(sm9, did_b, did_a)
        state, r_init = ta.handshake_initiator()
        r_resp, key_b = tb.handshake_responder(r_init)
        key_a = ta.handshake_finish(state, r_resp)
        assert key_a == key_b
        assert len(key_a) == 32

    def test_frame_roundtrip_and_integrity(self, sm9, netperm):
        kdc, relay, dev = make_world(sm9, netperm)
        fin = do_admission(relay, dev)
        did_b = make_device_did("dev-b", "u1")
        sm9.derive_sk(did_b)
        ta = Tunnel(sm9, dev.did, did_b)
        tb = Tunnel(sm9, did_b, dev.did)
        state, r_init = ta.handshake_initiator()
        r_resp, key_b = tb.handshake_responder(r_init)
        key_a = ta.handshake_finish(state, r_resp)
        frame = ta.frame_encrypt(b"secret payload", fin["vaddr"], seq=1, key=key_a)
        # 中继仅见密文：dump 不含明文
        relay.forward(frame)
        assert all(b"secret payload" not in pkt for pkt in relay.dumped_packets)
        # 接收端解密
        vaddr, payload, seq = tb.frame_decrypt(frame, key=key_b)
        assert payload == b"secret payload" and seq == 1
        # 篡改帧 → 完整性失败
        tampered = frame[:-1] + bytes([frame[-1] ^ 0xFF])
        with pytest.raises(ValueError):
            tb.frame_decrypt(tampered, key=key_b)


# ----------------------------------------------------------------------
# 5. 整形
# ----------------------------------------------------------------------

class TestShaping:
    def test_redundancy_within_15pct(self):
        raw_lens = [512] * 200 + [1448] * 80 + [128] * 120
        shaper = Shaper(target_rate=1_000_000.0, mode="fixed")
        shaped = [shaper.shape_length(l) for l in raw_lens]
        red = redundancy_rate(sum(raw_lens), sum(shaped))
        assert red <= 0.15, red

    def test_entropy_up_kl_down(self):
        raw_lens = [512] * 400                      # 退化分布：单一包长
        shaper = Shaper(target_rate=1_000_000.0, mode="fixed")
        shaped = [shaper.shape_length(l) for l in raw_lens]
        e_raw = packet_stats(raw_lens)["entropy"]
        e_shape = packet_stats(shaped)["entropy"]
        kl_raw = kl_divergence(raw_lens)
        kl_shape = kl_divergence(shaped)
        assert e_shape >= e_raw
        assert kl_shape <= kl_raw


# ----------------------------------------------------------------------
# 6. NAT
# ----------------------------------------------------------------------

class TestNat:
    def test_matrix_consistent(self):
        assert len(PUNCH_MATRIX) == len(NAT_TYPES) ** 2
        for t in NAT_TYPES:
            assert try_punch(t, "full_cone")
            assert not try_punch("symmetric", "symmetric")

    def test_virtual_nat_punch(self):
        v = VirtualNAT("full_cone")
        assert v.punch("symmetric")
        assert VirtualNAT("symmetric").punch("restricted_cone") is False

    def test_derive_relay_needed(self):
        uniform = {t: 0.25 for t in NAT_TYPES}
        relay_p, direct_p = derive_relay_needed(uniform)
        assert 0.0 <= relay_p <= 1.0
        assert abs(relay_p + direct_p - 1.0) < 1e-9
        # full×sym / sym×full 双向可直连，仅 sym×sym 需中继 → 兜底率 0.25
        sym = {"full_cone": 0.5, "symmetric": 0.5, "restricted_cone": 0.0,
               "port_restricted": 0.0}
        relay_p2, _ = derive_relay_needed(sym)
        assert abs(relay_p2 - 0.25) < 1e-9


# ----------------------------------------------------------------------
# 7. 发现 / 拓扑
# ----------------------------------------------------------------------

class TestDiscovery:
    def test_register_find_topology(self):
        ds = DiscoveryService(relay_dids=["didsm9:relay-1:r"])
        ds.register_device("didsm9:dev-1@u1:a", "127.0.0.1:7001")
        ds.register_device("didsm9:dev-2@u1:b", "127.0.0.1:7002")
        assert ds.find_node("didsm9:dev-1@u1:a") == "127.0.0.1:7001"
        topo = ds.build_topology()
        assert len(topo) == 1
        assert set(topo["didsm9:relay-1:r"]) == {"didsm9:dev-1@u1:a",
                                                 "didsm9:dev-2@u1:b"}


# ----------------------------------------------------------------------
# 8. 绑定表
# ----------------------------------------------------------------------

class TestBinding:
    def test_bind_owner(self):
        bt = BindingTable()
        bt.bind("didsm9:u1:a", "didsm9:dev-1@u1:d")
        assert bt.owner_of("didsm9:dev-1@u1:d") == "didsm9:u1:a"
        assert bt.is_bound("didsm9:dev-1@u1:d")
        bt.unbind("didsm9:dev-1@u1:d")
        assert not bt.is_bound("didsm9:dev-1@u1:d")
