"""
B4 攻击实验：已有攻击 + 新增攻击，每类记录 expected/actual/reject_stage/error/pass。

新增攻击：
    auth_st_device_mix_match / netperm_escalation / finish_request_tamper /
    challenge_replay / relay_in_scope_netperm_escalation / tunnel_frame_replay

输出（独立 formal_v2_<run_id> 目录）：
    expB4_attack.csv    (attack_type, attempts, blocked, block_rate,
                         expected, actual, reject_stage, error, pass)
    manifest.json
"""

import json
import subprocess
import sys
import time
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent.parent))

from core.authorization import (issue_auth, issue_session_credential,
                                proxy_delegate, proxy_verify,
                                verify_session_credential)
from core.common import (SEED, csv_meta, rand_bytes, write_csv)
from core.device import Device
from core.kdc import KDC
from core.relay import Relay
from core.sm9_engine import SM9Engine
from core.st_ticket import STService, netperm_defaults, st_fingerprint
from core.tunnel import Tunnel

REALM_SERVICE = "relay@realm"
N_ATTACK = 100
RESULTS = Path(__file__).resolve().parent / "结果"
REPO_ROOT = Path(__file__).resolve().parent.parent.parent.parent

_dev_counter = [0]


def next_dev_id():
    _dev_counter[0] += 1
    return f"dev-{_dev_counter[0]:05d}"


def _pack(obj):
    return json.dumps(obj, sort_keys=True).encode("utf-8")


def _git_head():
    try:
        return subprocess.check_output(["git", "rev-parse", "HEAD"],
                                       cwd=str(REPO_ROOT),
                                       stderr=subprocess.DEVNULL).decode().strip()
    except Exception:
        return "unknown"


def _git_dirty():
    try:
        out = subprocess.check_output(["git", "status", "--porcelain"],
                                      cwd=str(REPO_ROOT),
                                      stderr=subprocess.DEVNULL).decode().strip()
        return bool(out)
    except Exception:
        return True


def build_world(sm9, netperm):
    kdc = KDC(sm9)
    ctx1 = kdc.auth_context.issue("didsm9:user1:aaa", "src-1", "ev-1")
    assert kdc.register_user_context(ctx1)
    kdc.register_user("didsm9:user2:bbb", authenticated=False)
    relay = Relay(sm9, kdc, relay_id="relay-1")
    relay.setup_proxy()
    return kdc, relay


def legal_device(sm9, kdc, netperm, enroll=True):
    dev = Device(next_dev_id(), "didsm9:user1:aaa", sm9)
    if enroll:
        assert dev.enroll(kdc)
        dev.obtain_authorization(kdc, netperm)
    return dev


def run_admission(relay, dev, service=REALM_SERVICE):
    """完整两轮准入，返回 (ok, fin_or_r1)。"""
    r1 = relay.begin_admission(dev.admission_round1(), service)
    if not r1["ok"]:
        return False, r1
    r2 = dev.admission_round2(r1["challenge_id"], r1["challenge"], r1["request_digest"])
    fin = relay.finish_admission(r1["challenge_id"], r1["challenge"], r2["sig"],
                                 r2["nonce"], r2["ts"], service)
    return fin["ok"], fin


def main():
    quick = "--quick" in sys.argv
    n_attack = 5 if quick else N_ATTACK
    run_id = time.strftime("%Y%m%d_%H%M%S") + f"_{time.time_ns() % 1000000000:09d}"
    out_dir = RESULTS / f"formal_v2_{run_id}"
    out_dir.mkdir(parents=True, exist_ok=False)

    sm9 = SM9Engine()
    netperm = netperm_defaults()
    netperm["services"] = ["file-sync", "rtc"]
    netperm["bandwidth_mbps"] = 10.0
    kdc, relay = build_world(sm9, netperm)

    rows = []

    def add(attack_type, expected_blocked, blocked_count, attempts,
            reject_stage="", error=""):
        rows.append({
            "attack_type": attack_type,
            "attempts": attempts,
            "blocked": blocked_count,
            "block_rate": blocked_count / attempts,
            "expected": "block" if expected_blocked else "pass",
            "actual": "block" if blocked_count == attempts else
                      ("pass" if blocked_count == 0 else "partial"),
            "reject_stage": reject_stage,
            "error": error,
            "pass": (blocked_count == attempts) == expected_blocked,
        })

    # 1) 重放 ST
    dev = legal_device(sm9, kdc, netperm)
    assert run_admission(relay, dev)[0]
    blocked = 0; stage = ""; err = ""
    for i in range(n_attack):
        d2 = Device(f"replay-{i:03d}", "didsm9:user1:aaa", sm9)
        d2.auth, d2.st = dev.auth, dev.st
        ok, r = run_admission(relay, d2)
        if not ok:
            blocked += 1; stage = r.get("stage", ""); err = r.get("error", "")
    add("replay_st", True, blocked, n_attack, stage, err)

    # 2) 伪造授权
    evil = SM9Engine(); evil_kdc = "didsm9:evil-kdc:ff"; evil.derive_sk(evil_kdc)
    blocked = 0; stage = ""; err = ""
    for i in range(n_attack):
        d = legal_device(sm9, kdc, netperm)
        d.auth = issue_auth(evil, evil_kdc, d.did, {"services": ["*"]},
                            exp=time.time() + 1800)
        ok, r = run_admission(relay, d)
        if not ok:
            blocked += 1; stage = r.get("stage", ""); err = r.get("error", "")
    add("forged_auth", True, blocked, n_attack, stage, err)

    # 3) 伪造 ST
    evil2 = SM9Engine(); evil_kdc2 = "didsm9:evil2:ff"; evil2.derive_sk(evil_kdc2)
    blocked = 0; stage = ""; err = ""
    for i in range(n_attack):
        d = legal_device(sm9, kdc, netperm)
        forged = dict(d.st)
        forged["sig"] = evil2.sign(evil_kdc2, _pack({k: v for k, v in forged.items()
                                                     if k != "sig"})).hex()
        d.st = forged
        ok, r = run_admission(relay, d)
        if not ok:
            blocked += 1; stage = r.get("stage", ""); err = r.get("error", "")
    add("forged_st", True, blocked, n_attack, stage, err)

    # 4) 篡改 ST
    blocked = 0; stage = ""; err = ""
    for i in range(n_attack):
        d = legal_device(sm9, kdc, netperm)
        d.st["netperm"]["bandwidth_mbps"] = 999.0
        ok, r = run_admission(relay, d)
        if not ok:
            blocked += 1; stage = r.get("stage", ""); err = r.get("error", "")
    add("tampered_st", True, blocked, n_attack, stage, err)

    # 5) DID 冒用（合法票据 + 错误设备私钥 → 挑战失败）
    blocked = 0; stage = ""; err = ""
    for i in range(n_attack):
        d = legal_device(sm9, kdc, netperm)
        r1 = relay.begin_admission(d.admission_round1(), REALM_SERVICE)
        if not r1["ok"]:
            blocked += 1; stage = r1.get("stage", ""); err = r1.get("error", "")
            continue
        attacker = Device(f"spoof-{i:03d}", "didsm9:user2:bbb", sm9)
        nonce = rand_bytes(16, f"spoof_{i}")
        msg = _pack({"device_did": d.did, "challenge_id": r1["challenge_id"],
                     "challenge": r1["challenge"].hex(),
                     "request_digest": r1["request_digest"],
                     "nonce": nonce.hex(), "ts": time.time()})
        sig = attacker.sm9.sign(attacker.did, msg)
        fin = relay.finish_admission(r1["challenge_id"], r1["challenge"], sig,
                                     nonce, time.time(), REALM_SERVICE)
        if not fin["ok"]:
            blocked += 1; stage = fin.get("stage", ""); err = fin.get("error", "")
    add("did_spoofing", True, blocked, n_attack, stage, err)

    # 6) 过期 ST
    blocked = 0; stage = ""; err = ""
    for i in range(n_attack):
        d = legal_device(sm9, kdc, netperm)
        d.st["times"]["end"] = time.time() - 1.0
        ok, r = run_admission(relay, d)
        if not ok:
            blocked += 1; stage = r.get("stage", ""); err = r.get("error", "")
    add("expired_st", True, blocked, n_attack, stage, err)

    # 7) auth/ST/request DID 拼接不一致
    blocked = 0; stage = ""; err = ""
    for i in range(n_attack):
        d = legal_device(sm9, kdc, netperm)
        other = legal_device(sm9, kdc, netperm)
        d.auth = other.auth
        ok, r = run_admission(relay, d)
        if not ok:
            blocked += 1; stage = r.get("stage", ""); err = r.get("error", "")
    add("auth_st_device_mix_match", True, blocked, n_attack, stage, err)

    # 8) netperm 越权（ST.netperm 超出 auth.policy）
    blocked = 0; stage = ""; err = ""
    for i in range(n_attack):
        d = legal_device(sm9, kdc, netperm)
        narrow = dict(netperm); narrow["services"] = ["file-sync"]
        wide = dict(netperm); wide["services"] = ["file-sync", "rtc"]
        exp = time.time() + 1800
        d.auth = kdc.issue_auth(d.did, narrow, exp, auth_id="aid-n",
                                parent_auth_ticket_id="pat-n", user_did=d.owner_user_did)
        d.st = kdc.issue_ticket(d.did, REALM_SERVICE, wide, auth_id="aid-n",
                                parent_auth_ticket_id="pat-n", user_did=d.owner_user_did)
        ok, r = run_admission(relay, d)
        if not ok:
            blocked += 1; stage = r.get("stage", ""); err = r.get("error", "")
    add("netperm_escalation", True, blocked, n_attack, stage, err)

    # 9) finish 阶段篡改请求（篡改 request_digest → challenge_failed）
    blocked = 0; stage = ""; err = ""
    for i in range(n_attack):
        d = legal_device(sm9, kdc, netperm)
        r1 = relay.begin_admission(d.admission_round1(), REALM_SERVICE)
        if not r1["ok"]:
            blocked += 1; stage = r1.get("stage", ""); err = r1.get("error", "")
            continue
        nonce = rand_bytes(16, f"tamper_{i}")
        msg = _pack({"device_did": d.did, "challenge_id": r1["challenge_id"],
                     "challenge": r1["challenge"].hex(),
                     "request_digest": "deadbeef",
                     "nonce": nonce.hex(), "ts": time.time()})
        sig = d.sm9.sign(d.did, msg)
        fin = relay.finish_admission(r1["challenge_id"], r1["challenge"], sig,
                                     nonce, time.time(), REALM_SERVICE)
        if not fin["ok"]:
            blocked += 1; stage = fin.get("stage", ""); err = fin.get("error", "")
    add("finish_request_tamper", True, blocked, n_attack, stage, err)

    # 10) challenge 重放
    blocked = 0; stage = ""; err = ""
    for i in range(n_attack):
        d = legal_device(sm9, kdc, netperm)
        r1 = relay.begin_admission(d.admission_round1(), REALM_SERVICE)
        if not r1["ok"]:
            blocked += 1; stage = r1.get("stage", ""); err = r1.get("error", "")
            continue
        r2 = d.admission_round2(r1["challenge_id"], r1["challenge"], r1["request_digest"])
        fin = relay.finish_admission(r1["challenge_id"], r1["challenge"], r2["sig"],
                                     r2["nonce"], r2["ts"], REALM_SERVICE)
        if not fin["ok"]:
            blocked += 1; stage = fin.get("stage", ""); err = fin.get("error", "")
            continue
        fin2 = relay.finish_admission(r1["challenge_id"], r1["challenge"], r2["sig"],
                                      r2["nonce"], r2["ts"], REALM_SERVICE)
        if not fin2["ok"]:
            blocked += 1; stage = fin2.get("stage", ""); err = fin2.get("error", "")
    add("challenge_replay", True, blocked, n_attack, stage, err)

    # 11) 恶意中继窃听（仅见密文）
    leak = 0
    for i in range(n_attack):
        d = legal_device(sm9, kdc, netperm)
        ok, fin = run_admission(relay, d)
        assert ok
        peer = Device(f"peer-{i:03d}", "didsm9:user1:aaa", sm9)
        ta = Tunnel(sm9, d.did, peer.did)
        tb = Tunnel(sm9, peer.did, d.did)
        state, r_init = ta.handshake_initiator()
        r_resp, key_b = tb.handshake_responder(r_init)
        key_a = ta.handshake_finish(state, r_resp)
        secret = b"classified-payload-" + str(i).encode()
        frame = ta.frame_encrypt(secret, fin["vaddr"], seq=i, key=key_a)
        relay.forward(frame)
        if any(secret in pkt for pkt in relay.dumped_packets[-1:]):
            leak += 1
    add("malicious_relay_plaintext", True, n_attack - leak, n_attack,
        "relay", "plaintext_leak" if leak else "")

    # 12) relay_in_scope_netperm_escalation（中继不能把低权限 ST 提升为高权限凭证）
    blocked = 0; err = ""
    kdc_did = kdc.kdc_did
    relay_did = relay.relay_did
    warrant = relay._warrant
    for i in range(n_attack):
        low_st = STService(sm9, kdc_did).issue_ticket(
            "didsm9:dev-1@user1:aaa", REALM_SERVICE, {"services": ["file-sync"]},
            auth_id="aid-r", parent_auth_ticket_id="pat-r", user_did="didsm9:user1:aaa")
        cred = issue_session_credential(
            sm9, relay_did, warrant,
            device_did="didsm9:dev-1@user1:aaa", user_did="didsm9:user1:aaa",
            auth_id="aid-r", parent_auth_ticket_id="pat-r",
            parent_ticket_id=low_st["ticket_id"],
            netperm={"services": ["file-sync", "rtc"]},   # 越权
            sname=REALM_SERVICE, vaddr="10.200.0.1",
            st_fingerprint_hex=st_fingerprint(low_st).hex(),
            exp=low_st["times"]["end"])
        if not verify_session_credential(sm9, cred, st=low_st):
            blocked += 1; err = "netperm_escalation"
    add("relay_in_scope_netperm_escalation", True, blocked, n_attack, "verify", err)

    # 13) tunnel_frame_replay（重复 seq → frame_replay）
    blocked = 0; err = ""
    did_a = "didsm9:dev-a:u1"; did_b = "didsm9:dev-b:u1"
    sm9.derive_sk(did_a); sm9.derive_sk(did_b)
    for i in range(n_attack):
        ta = Tunnel(sm9, did_a, did_b)
        tb = Tunnel(sm9, did_b, did_a)
        state, r_init = ta.handshake_initiator()
        r_resp, key_b = tb.handshake_responder(r_init)
        key_a = ta.handshake_finish(state, r_resp)
        frame = ta.frame_encrypt(b"hello", "10.200.0.1", seq=i, key=key_a)
        tb.frame_decrypt(frame, key=key_b)
        try:
            tb.frame_decrypt(frame, key=key_b)
        except ValueError as e:
            if "frame_replay" in str(e):
                blocked += 1; err = "frame_replay"
    add("tunnel_frame_replay", True, blocked, n_attack, "tunnel", err)

    # 14) 代理伪造（warrant 越界）
    blocked = 0; err = ""
    for i in range(n_attack):
        payload = {"kind": "new_authorization", "did": "didsm9:evil:xx",
                   "policy": {"services": ["*"]}}
        msg = _pack(payload)
        sig = sm9.sign(relay_did, msg)
        if not proxy_verify(sm9, warrant, msg, sig, "authorization"):
            blocked += 1; err = "authorization_out_of_scope"
    add("proxy_forge_out_of_scope", True, blocked, n_attack, "proxy", err)

    # 汇总
    write_csv(out_dir / "expB4_attack.csv", rows)
    manifest = {
        "git_commit": _git_head(),
        "dirty_worktree": _git_dirty(),
        "mode": "quick" if quick else "formal",
        "seed": SEED,
        "n_attack": n_attack,
        "simulated_components": ["SM9 engine (gmalg-or-simulated)",
                                 "malicious relay eavesdrop (loopback dump only)"],
    }
    (out_dir / "manifest.json").write_text(
        json.dumps(manifest, ensure_ascii=False, indent=2), encoding="utf-8")
    csv_meta(out_dir / "expB4_attack.csv", {"seed": SEED, "mode": manifest["mode"],
                                            "n_attack": n_attack})

    for r in rows:
        print(f"  {r['attack_type']:<34} blocked={r['block_rate']:.2%} "
              f"pass={r['pass']} stage={r['reject_stage']} err={r['error']}")


if __name__ == "__main__":
    main()
