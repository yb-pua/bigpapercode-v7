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
from core.auth_context import UserAuthContextService, new_evidence_id
from core.binding_table import BindingTable
from core.common import rand_bytes, sm3
from core.crypto_roles import RestrictedSigner, VerifyOnlySM9
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
from core.st_ticket import (STService, TICKET_TTL, netperm_defaults,
                            st_fingerprint)
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
    """构造 KDC + 中继 + 设备世界（用户经 UserAuthContext 认证）。"""
    kdc = KDC(sm9)
    ctx1 = kdc.auth_context.issue("didsm9:user1:aaa", "src-1", "ev-1")
    assert kdc.register_user_context(ctx1)
    kdc.register_user("didsm9:user2:bbb", authenticated=False)
    relay = Relay(sm9, kdc, relay_id="relay-1")
    relay.setup_proxy()
    dev = Device("dev-1", "didsm9:user1:aaa", sm9)
    if bind:
        assert dev.enroll(kdc)
        dev.obtain_authorization(kdc, netperm, ttl=ttl)
    return kdc, relay, dev


def do_admission(relay, dev):
    """完整两轮 stateful 准入。"""
    r1 = relay.begin_admission(dev.admission_round1(), REALM_SERVICE)
    assert r1["ok"], r1
    r2 = dev.admission_round2(r1["challenge_id"], r1["challenge"],
                              r1["request_digest"])
    fin = relay.finish_admission(r1["challenge_id"], r1["challenge"],
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
            sm9, relay_did, warrant,
            device_did="didsm9:dev-1@user1:aaa",
            user_did="didsm9:user1:aaa",
            auth_id="auth-1",
            parent_auth_ticket_id="pat-1",
            parent_ticket_id="ticket-1",
            netperm={"services": ["rtc"]},
            sname="relay@realm",
            vaddr="10.200.0.1",
            st_fingerprint_hex=sm3(b"st").hex(),
            exp=time.time() + 1800)
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
        assert fin["credential"]["device_did"] == dev.did
        assert relay.verify_credential(fin["credential"])

    def test_unbound_device_rejected(self, sm9, netperm):
        """未绑定（未登记）设备不能获得 ST。"""
        kdc, relay, dev = make_world(sm9, netperm, bind=False)
        assert kdc.issue_device_access(dev.did, REALM_SERVICE, netperm) is None

    def test_unbound_user_rejected(self, sm9, netperm):
        """未认证用户不能绑定设备。"""
        kdc, relay, dev = make_world(sm9, netperm, bind=True)
        dev2 = Device("dev-2", "didsm9:user2:bbb", sm9)
        assert not dev2.enroll(kdc)
        assert kdc.issue_device_access(dev2.did, REALM_SERVICE, netperm) is None

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
        attacker = Device("dev-99", "didsm9:user1:aaa", sm9)
        nonce = rand_bytes(16, "attk")
        import json as _j
        msg = _j.dumps({"device_did": dev.did,
                        "challenge_id": r1["challenge_id"],
                        "challenge": r1["challenge"].hex(),
                        "request_digest": r1["request_digest"],
                        "nonce": nonce.hex(), "ts": time.time()},
                       sort_keys=True).encode()
        sig = attacker.sm9.sign(attacker.did, msg)
        fin = relay.finish_admission(r1["challenge_id"], r1["challenge"],
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

    def test_auth_st_device_did_mixmatch_rejected(self, sm9, netperm):
        """auth/ST/request 的 device DID 拼接不一致 → 拒绝。"""
        kdc, relay, dev = make_world(sm9, netperm)
        other = Device("dev-9", "didsm9:user1:aaa", sm9)
        assert other.enroll(kdc)
        other.obtain_authorization(kdc, netperm)
        dev.auth = other.auth                # auth.device_did = other.did != dev.did
        r1 = relay.begin_admission(dev.admission_round1(), REALM_SERVICE)
        assert not r1["ok"] and r1["error"] == "device_mismatch"

    def test_user_device_mismatch_rejected(self, sm9, netperm):
        """auth/ST 声称的 user_did 与设备绑定 owner 不一致 → 拒绝。"""
        kdc, relay, dev = make_world(sm9, netperm)
        exp = time.time() + 1800
        auth = kdc.issue_auth(dev.did, netperm, exp,
                              auth_id="aid-shared", parent_auth_ticket_id="pat-shared",
                              user_did="didsm9:user2:bbb")
        st = kdc.issue_ticket(dev.did, REALM_SERVICE, netperm,
                              auth_id="aid-shared", parent_auth_ticket_id="pat-shared",
                              user_did="didsm9:user2:bbb")
        dev.auth, dev.st = auth, st
        r1 = relay.begin_admission(dev.admission_round1(), REALM_SERVICE)
        assert not r1["ok"] and r1["error"] == "user_device_mismatch"

    def test_netperm_escalation_rejected(self, sm9, netperm):
        """ST.netperm 超出 auth.policy → 拒绝。"""
        kdc, relay, dev = make_world(sm9, netperm)
        narrow = dict(netperm); narrow["services"] = ["file-sync"]
        wide = dict(netperm); wide["services"] = ["file-sync", "rtc"]
        exp = time.time() + 1800
        auth = kdc.issue_auth(dev.did, narrow, exp,
                              auth_id="aid-1", parent_auth_ticket_id="pat-1",
                              user_did=dev.owner_user_did)
        st = kdc.issue_ticket(dev.did, REALM_SERVICE, wide,
                              auth_id="aid-1", parent_auth_ticket_id="pat-1",
                              user_did=dev.owner_user_did)
        dev.auth, dev.st = auth, st
        r1 = relay.begin_admission(dev.admission_round1(), REALM_SERVICE)
        assert not r1["ok"] and r1["error"] == "netperm_escalation"

    def test_caddr_mismatch_rejected(self, sm9, netperm):
        """请求 caddr 与 ST.caddr 不一致 → 拒绝。"""
        kdc, relay, dev = make_world(sm9, netperm)
        access = kdc.issue_device_access(dev.did, REALM_SERVICE, netperm,
                                         caddr="10.0.0.5")
        dev.auth, dev.st = access["auth"], access["st"]
        dev.caddr = "127.0.0.1"
        r1 = relay.begin_admission(dev.admission_round1(), REALM_SERVICE)
        assert not r1["ok"] and r1["error"] == "caddr_mismatch"

    def test_service_mismatch_rejected(self, sm9, netperm):
        kdc, relay, dev = make_world(sm9, netperm)
        r1 = relay.begin_admission(dev.admission_round1(), "other@realm")
        assert not r1["ok"] and r1["error"] == "service_mismatch"

    def test_finish_uses_verified_netperm(self, sm9, netperm):
        """finish 阶段只使用第一轮 verified claims，不能提权。"""
        kdc, relay, dev = make_world(sm9, netperm)
        r1 = relay.begin_admission(dev.admission_round1(), REALM_SERVICE)
        r2 = dev.admission_round2(r1["challenge_id"], r1["challenge"],
                                  r1["request_digest"])
        fin = relay.finish_admission(r1["challenge_id"], r1["challenge"],
                                     r2["sig"], r2["nonce"], r2["ts"],
                                     REALM_SERVICE)
        assert fin["ok"]
        assert fin["credential"]["netperm"]["services"] == netperm["services"]

    def test_challenge_single_use(self, sm9, netperm):
        kdc, relay, dev = make_world(sm9, netperm)
        r1 = relay.begin_admission(dev.admission_round1(), REALM_SERVICE)
        r2 = dev.admission_round2(r1["challenge_id"], r1["challenge"],
                                  r1["request_digest"])
        fin = relay.finish_admission(r1["challenge_id"], r1["challenge"],
                                     r2["sig"], r2["nonce"], r2["ts"],
                                     REALM_SERVICE)
        assert fin["ok"]
        fin2 = relay.finish_admission(r1["challenge_id"], r1["challenge"],
                                      r2["sig"], r2["nonce"], r2["ts"],
                                      REALM_SERVICE)
        assert not fin2["ok"] and fin2["error"] == "challenge_replay"

    def test_credential_binds_parent_ticket(self, sm9, netperm):
        kdc, relay, dev = make_world(sm9, netperm)
        fin = do_admission(relay, dev)
        cred = fin["credential"]
        assert cred["parent_ticket_id"] == dev.st["ticket_id"]
        assert cred["st_fingerprint"] == st_fingerprint(dev.st).hex()
        assert cred["device_did"] == dev.did
        assert cred["user_did"] == dev.owner_user_did

    def test_finish_service_swap_rejected(self, sm9, netperm):
        """finish 阶段换服务名（relay@realm → evil@realm）→ 拒绝。"""
        kdc, relay, dev = make_world(sm9, netperm)
        r1 = relay.begin_admission(dev.admission_round1(), REALM_SERVICE)
        assert r1["ok"]
        r2 = dev.admission_round2(r1["challenge_id"], r1["challenge"],
                                  r1["request_digest"])
        fin = relay.finish_admission(r1["challenge_id"], r1["challenge"],
                                     r2["sig"], r2["nonce"], r2["ts"],
                                     "evil@realm")
        assert not fin["ok"] and fin["error"] == "service_mismatch"


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

    def test_frame_replay_rejected(self, sm9):
        did_a = make_device_did("dev-a", "u1")
        did_b = make_device_did("dev-b", "u1")
        sm9.derive_sk(did_a)
        sm9.derive_sk(did_b)
        ta = Tunnel(sm9, did_a, did_b)
        tb = Tunnel(sm9, did_b, did_a)
        state, r_init = ta.handshake_initiator()
        r_resp, key_b = tb.handshake_responder(r_init)
        key_a = ta.handshake_finish(state, r_resp)
        frame = ta.frame_encrypt(b"hello", "10.200.0.1", seq=1, key=key_a)
        assert tb.frame_decrypt(frame, key=key_b)[1] == b"hello"
        with pytest.raises(ValueError) as e:
            tb.frame_decrypt(frame, key=key_b)
        assert "frame_replay" in str(e.value)

    def test_frame_wrong_key_rejected(self, sm9):
        did_a = make_device_did("dev-a", "u1")
        did_b = make_device_did("dev-b", "u1")
        sm9.derive_sk(did_a)
        sm9.derive_sk(did_b)
        ta = Tunnel(sm9, did_a, did_b)
        tb = Tunnel(sm9, did_b, did_a)
        state, r_init = ta.handshake_initiator()
        r_resp, key_b = tb.handshake_responder(r_init)
        key_a = ta.handshake_finish(state, r_resp)
        frame = ta.frame_encrypt(b"hello", "10.200.0.1", seq=1, key=key_a)
        wrong_key = sm3(b"wrong-session-key")
        with pytest.raises(ValueError):
            tb.frame_decrypt(frame, key=wrong_key)


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

    def test_bidirectional_punch(self):
        """直连判定必须双方同时成立（A→B 且 B→A），单向可行不算直连。"""
        assert try_punch("restricted_cone", "port_restricted") is True
        assert try_punch("port_restricted", "restricted_cone") is False
        both = (try_punch("restricted_cone", "port_restricted")
                and try_punch("port_restricted", "restricted_cone"))
        assert both is False


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


# ----------------------------------------------------------------------
# 9. UserAuthContext v1（方向一认证结果模拟交接）
# ----------------------------------------------------------------------

class TestUserAuthContext:
    def _svc(self, sm9):
        kdc_did = make_device_did("kdc", "realm")
        sm9.derive_sk(kdc_did)
        return UserAuthContextService(sm9, kdc_did)

    def test_issue_verify_ok(self, sm9):
        svc = self._svc(sm9)
        ctx = svc.issue("didsm9:user1:aaa", "src-1", "ev-1")
        assert svc.verify(ctx)["ok"]

    def test_tamper_rejected(self, sm9):
        svc = self._svc(sm9)
        ctx = svc.issue("didsm9:user1:aaa", "src-1", "ev-1")
        ctx["user_did"] = "didsm9:evil:xx"
        assert not svc.verify(ctx)["ok"]

    def test_expired_rejected(self, sm9):
        svc = self._svc(sm9)
        ctx = svc.issue("didsm9:user1:aaa", "src-1", "ev-1")
        assert not svc.verify(ctx, now=ctx["expires_at"] + 1.0)["ok"]

    def test_purpose_mismatch_rejected(self, sm9):
        svc = self._svc(sm9)
        ctx = svc.issue("didsm9:user1:aaa", "src-1", "ev-1",
                        purpose="other-purpose")
        r = svc.verify(ctx)
        assert not r["ok"] and r["error"] == "purpose_mismatch"

    def test_forged_issuer_rejected(self, sm9):
        """伪造 issuer（非可信 KDC）自签的认证上下文 → 拒绝。"""
        svc = self._svc(sm9)
        evil_did = "didsm9:evil-issuer:ff"
        sm9.derive_sk(evil_did)
        evil_svc = UserAuthContextService(sm9, evil_did)
        forged = evil_svc.issue("didsm9:user1:aaa", "src-1", "ev-1")
        r = svc.verify(forged)
        assert not r["ok"] and r["error"] == "untrusted_issuer"


# ----------------------------------------------------------------------
# 10. 最小角色隔离（接口级模拟，非硬件密钥隔离）
# ----------------------------------------------------------------------

class TestRoleIsolation:
    def test_relay_cannot_sign_as_kdc(self, sm9):
        kdc_did = make_device_did("kdc", "realm")
        relay_did = make_device_did("relay-1", "realm")
        sm9.derive_sk(kdc_did)
        sm9.derive_sk(relay_did)
        signer = RestrictedSigner(sm9, [relay_did])
        with pytest.raises(PermissionError):
            signer.sign(kdc_did, b"msg")

    def test_verify_only_has_no_sign(self, sm9):
        v = VerifyOnlySM9(sm9)
        assert not hasattr(v, "sign")


# ----------------------------------------------------------------------
# 11. 授权链 / 中继越权
# ----------------------------------------------------------------------

class TestAuthorizationChain:
    def test_relay_in_scope_netperm_escalation(self, sm9):
        """中继虽持 session_credential scope，也不能把低权限 ST 提升为高权限凭证。"""
        kdc_did = make_device_did("kdc", "realm")
        relay_did = make_device_did("relay-1", "realm")
        sm9.derive_sk(kdc_did)
        sm9.derive_sk(relay_did)
        warrant = proxy_delegate(sm9, kdc_did, relay_did,
                                 scope=["session_credential"])
        st = STService(sm9, kdc_did).issue_ticket(
            "didsm9:dev-1@user1:aaa", "relay@realm",
            {"services": ["file-sync"]},
            auth_id="aid-1", parent_auth_ticket_id="pat-1",
            user_did="didsm9:user1:aaa")
        cred = issue_session_credential(
            sm9, relay_did, warrant,
            device_did="didsm9:dev-1@user1:aaa",
            user_did="didsm9:user1:aaa",
            auth_id="aid-1",
            parent_auth_ticket_id="pat-1",
            parent_ticket_id=st["ticket_id"],
            netperm={"services": ["file-sync", "rtc"]},   # 越权
            sname="relay@realm", vaddr="10.200.0.1",
            st_fingerprint_hex=st_fingerprint(st).hex(),
            exp=st["times"]["end"])
        assert not verify_session_credential(sm9, cred, st=st)

    def test_self_signed_warrant_rejected(self, sm9):
        """中继自签 warrant（delegator 自声明）→ 指定信任锚后拒绝。"""
        kdc_did = make_device_did("kdc", "realm")
        relay_did = make_device_did("relay-1", "realm")
        sm9.derive_sk(kdc_did)
        sm9.derive_sk(relay_did)
        evil_warrant = proxy_delegate(sm9, relay_did, relay_did,
                                      scope=["session_credential"])
        cred = issue_session_credential(
            sm9, relay_did, evil_warrant,
            device_did="didsm9:dev-1@user1:aaa",
            user_did="didsm9:user1:aaa",
            auth_id="aid-1", parent_auth_ticket_id="pat-1",
            parent_ticket_id="ticket-1",
            netperm={"services": ["rtc"]}, sname="relay@realm",
            vaddr="10.200.0.1", st_fingerprint_hex=sm3(b"st").hex(),
            exp=time.time() + 1800)
        # 不指定信任锚时（旧行为）会被接受 —— 显式断言漏洞存在
        assert verify_session_credential(sm9, cred)
        # 指定可信 KDC 后必须拒绝
        assert not verify_session_credential(sm9, cred, trusted_kdc_did=kdc_did)
