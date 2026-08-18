"""
B4 攻击（D1/D2/D5）：八类攻击 + 代理伪造（warrant 越界）。

输出：
    expB4_attack_results.csv  (attack_type, attempts, blocked, block_rate, note)
    expB4_proxy_forge.csv     (test, forge_ok, note)

用例（《代码汇总版》§4.4 B4）：重放ST/伪造授权/伪造ST/篡改ST/DID冒用/
恶意中继窃听/过期续访/代理伪造。attempts ≥100。
"""

import json
import sys
import time
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from core.authorization import (issue_auth, issue_session_credential,
                                proxy_delegate, proxy_verify,
                                verify_session_credential)
from core.common import (SEED, csv_meta, get_rng, rand_bytes, write_csv)
from core.device import Device
from core.kdc import KDC
from core.relay import Relay
from core.sm9_engine import SM9Engine
from core.st_ticket import STService, netperm_defaults
from core.tunnel import Tunnel

N_ATTACK = 100                 # 每攻击用例次数
RESULTS = Path(__file__).resolve().parent.parent / "results"
_dev_counter = [0]


def next_dev_id():
    _dev_counter[0] += 1
    return f"dev-{_dev_counter[0]:05d}"


def build_world(sm9, netperm):
    kdc = KDC(sm9)
    kdc.register_user("didsm9:user1:aaa")
    kdc.register_user("didsm9:user2:bbb")
    relay = Relay(sm9, kdc, relay_id="relay-1")
    relay.setup_proxy()
    return kdc, relay


def legal_device(sm9, kdc, netperm, enroll=True):
    dev = Device(next_dev_id(), "didsm9:user1:aaa", sm9)
    if enroll:
        assert dev.enroll(kdc)
    dev.obtain_authorization(kdc, netperm)
    return dev


def run_admission(relay, dev, service="relay@realm"):
    r1 = relay.begin_admission(dev.admission_round1(), service)
    if not r1["ok"]:
        return False, r1
    r2 = dev.admission_round2(r1["challenge"])
    fin = relay.finish_admission(dev.admission_round1(), r1["challenge"],
                                 r2["sig"], r2["nonce"], r2["ts"], service)
    return fin["ok"], fin


def main():
    debug = "--debug" in sys.argv
    quick = "--quick" in sys.argv
    n_attack = 10 if quick else N_ATTACK
    sm9 = SM9Engine()
    netperm = netperm_defaults()
    netperm["services"] = ["file-sync", "rtc"]
    netperm["bandwidth_mbps"] = 10.0
    kdc, relay = build_world(sm9, netperm)

    rows = []

    def add(attack_type, blocked, note=""):
        rows.append({"attack_type": attack_type, "attempts": 1,
                     "blocked": 1 if blocked else 0,
                     "block_rate": 1.0 if blocked else 0.0, "note": note})

    # ------------------------------------------------------------------
    # B4-1 重放 ST：合法 ST 二次提交 → 拒绝
    # ------------------------------------------------------------------
    dev = legal_device(sm9, kdc, netperm)
    assert run_admission(relay, dev)[0]
    for i in range(n_attack):
        d2 = Device(f"replay-{i:03d}", "didsm9:user1:aaa", sm9)
        d2.auth, d2.st = dev.auth, dev.st
        ok, r = run_admission(relay, d2)
        add("replay_st", not ok)

    # ------------------------------------------------------------------
    # B4-2 伪造授权：无 KDC 主密钥构造授权 → 验签失败
    # ------------------------------------------------------------------
    evil = SM9Engine()
    evil_kdc = "didsm9:evil-kdc:ff"
    evil.derive_sk(evil_kdc)
    for i in range(n_attack):
        dev = legal_device(sm9, kdc, netperm)
        dev.auth = issue_auth(evil, evil_kdc, dev.did, {"services": ["*"]},
                              exp=time.time() + 1800)
        ok, r = run_admission(relay, dev)
        add("forged_auth", not ok)

    # ------------------------------------------------------------------
    # B4-3 DID 冒用：合法票据 + 错误设备私钥 → 挑战应答失败
    # ------------------------------------------------------------------
    for i in range(n_attack):
        dev = legal_device(sm9, kdc, netperm)
        attacker = Device(f"spoof-{i:03d}", "didsm9:user2:bbb", sm9)
        r1 = relay.begin_admission(dev.admission_round1(), "relay@realm")
        if not r1["ok"]:
            add("did_spoofing", True, "rejected at round1")
            continue
        nonce = rand_bytes(16, f"spoof_{i}")
        msg = json.dumps({"did": dev.did, "challenge": r1["challenge"].hex(),
                          "nonce": nonce.hex(), "ts": time.time()},
                         sort_keys=True).encode()
        sig = attacker.sm9.sign(attacker.did, msg)
        fin = relay.finish_admission(dev.admission_round1(), r1["challenge"],
                                     sig, nonce, time.time(), "relay@realm")
        add("did_spoofing", not fin["ok"])

    # ------------------------------------------------------------------
    # B4-4 恶意中继窃听：中继 dump 隧道载荷 → 仅密文
    # ------------------------------------------------------------------
    leak_ok = True
    frames_dumped = 0
    for i in range(30):
        dev = legal_device(sm9, kdc, netperm)
        ok, fin = run_admission(relay, dev)
        assert ok
        peer = Device(f"peer-{i:03d}", "didsm9:user1:aaa", sm9)
        ta = Tunnel(sm9, dev.did, peer.did)
        tb = Tunnel(sm9, peer.did, dev.did)
        state, r_init = ta.handshake_initiator()
        r_resp, key_b = tb.handshake_responder(r_init)
        key_a = ta.handshake_finish(state, r_resp)
        secret = b"classified-payload-" + str(i).encode()
        frame = ta.frame_encrypt(secret, fin["vaddr"], seq=i, key=key_a)
        relay.forward(frame)
        frames_dumped += 1
        if secret in relay.dumped_packets[-1]:
            leak_ok = False
    add("malicious_relay_plaintext", leak_ok, f"dumped={frames_dumped}")

    # ------------------------------------------------------------------
    # B4-5 伪造 ST：随机密钥签 ST → 验签失败
    # ------------------------------------------------------------------
    evil2 = SM9Engine()
    evil_kdc2 = "didsm9:evil2:ff"
    evil2.derive_sk(evil_kdc2)
    for i in range(n_attack):
        dev = legal_device(sm9, kdc, netperm)
        forged = dict(dev.st)
        forged["sig"] = evil2.sign(evil_kdc2,
                                   json.dumps({k: v for k, v in forged.items()
                                               if k != "sig"},
                                              sort_keys=True).encode()).hex()
        dev.st = forged
        ok, r = run_admission(relay, dev)
        add("forged_st", not ok)

    # ------------------------------------------------------------------
    # B4-6 篡改 ST：改 NetPerm/Principal 后重签（无密钥）→ 验签失败
    # ------------------------------------------------------------------
    for i in range(n_attack):
        dev = legal_device(sm9, kdc, netperm)
        dev.st["netperm"]["bandwidth_mbps"] = 999.0
        ok, r = run_admission(relay, dev)
        add("tampered_st", not ok)

    # ------------------------------------------------------------------
    # B4-7 过期续访：ST 过期后持续验证 → 拒绝
    # ------------------------------------------------------------------
    for i in range(n_attack):
        dev = legal_device(sm9, kdc, netperm, enroll=True)
        dev.st["times"]["end"] = time.time() - 1.0     # 已过期
        ok, r = run_admission(relay, dev)
        add("expired_st", not ok)

    # ------------------------------------------------------------------
    # B4-8 代理伪造（warrant 越界）：中继用代理密钥签授权书外凭证
    # ------------------------------------------------------------------
    forge_rows = []
    kdc_did = kdc.kdc_did
    relay_did = relay.relay_did
    warrant = kdc.warrants()[0]

    # 8a. 合法：scope 内签发会话准入凭证 → 验证通过
    dev = legal_device(sm9, kdc, netperm)
    cred = issue_session_credential(sm9, relay_did, warrant, dev.did,
                                    netperm, "relay@realm",
                                    exp=time.time() + 1800)
    forge_rows.append({"test": "session_credential_in_scope",
                       "forge_ok": verify_session_credential(sm9, cred),
                       "note": "期望: 验证通过(scope 内)"})

    # 8b. 越界：签发"新授权"（scope 外）→ 验证失败
    payload_new_auth = {"kind": "new_authorization", "did": dev.did,
                        "policy": {"services": ["*"]}}
    msg = json.dumps(payload_new_auth, sort_keys=True).encode()
    sig = sm9.sign(relay_did, msg)
    forge_rows.append({"test": "authorization_out_of_scope",
                       "forge_ok": proxy_verify(sm9, warrant, msg, sig,
                                                "authorization"),
                       "note": "期望: 验证失败(授权书外)"})

    # 8c. 越界：签发"新票据"（scope 外）→ 验证失败
    payload_new_st = {"kind": "st_issue", "principal": dev.did}
    msg = json.dumps(payload_new_st, sort_keys=True).encode()
    sig = sm9.sign(relay_did, msg)
    forge_rows.append({"test": "st_issue_out_of_scope",
                       "forge_ok": proxy_verify(sm9, warrant, msg, sig,
                                                "st_issue"),
                       "note": "期望: 验证失败(授权书外)"})

    # 8d. 篡改 warrant scope → 验证失败
    forged_warrant = dict(warrant)
    forged_warrant["scope"] = ["*", "authorization"]
    forge_rows.append({"test": "warrant_scope_tampered",
                       "forge_ok": proxy_verify(sm9, forged_warrant, msg,
                                                sig, "session_credential"),
                       "note": "期望: 验证失败(warrant 被篡改)"})

    # 8e. 伪造 warrant（无 KDC 私钥）→ 验证失败
    evil_warrant = proxy_delegate(evil2, evil_kdc2, relay_did,
                                  scope=["session_credential"])
    forge_rows.append({"test": "warrant_forged",
                       "forge_ok": proxy_verify(sm9, evil_warrant, msg, sig,
                                                "session_credential"),
                       "note": "期望: 验证失败(伪造 warrant)"})

    # ------------------------------------------------------------------
    # 汇总输出
    # ------------------------------------------------------------------
    summary = []
    by_type = {}
    for r in rows:
        by_type.setdefault(r["attack_type"], []).append(r)
    for atype, items in by_type.items():
        blocked = sum(1 for r in items if r["blocked"])
        summary.append({"attack_type": atype, "attempts": len(items),
                        "blocked": blocked,
                        "block_rate": blocked / len(items)})
    summary.append({"attack_type": "TOTAL", "attempts": sum(
        r["attempts"] for r in rows), "blocked": sum(
        r["blocked"] for r in rows), "block_rate": sum(
        r["blocked"] for r in rows) / max(1, sum(r["attempts"] for r in rows))})

    write_csv(RESULTS / "expB4_attack_results.csv", rows)
    write_csv(RESULTS / "expB4_proxy_forge.csv", forge_rows)
    write_csv(RESULTS / "expB4_summary.csv", summary)
    for f in ("expB4_attack_results.csv", "expB4_proxy_forge.csv",
              "expB4_summary.csv"):
        csv_meta(RESULTS / f, {"seed": SEED, "n_attack": N_ATTACK})

    for s in summary:
        print(f"  {s['attack_type']:<28} attempts={s['attempts']} "
              f"block_rate={s['block_rate']:.4f}")
    for fr in forge_rows:
        print(f"  forge[{fr['test']}] forge_ok={fr['forge_ok']} "
              f"({fr['note']})")


if __name__ == "__main__":
    main()