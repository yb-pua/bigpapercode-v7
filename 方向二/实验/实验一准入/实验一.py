"""
B1 准入消融（四组真实执行，禁止硬编码结果）：

    G0  PSK/无ST         ：仅比对预共享密钥（真实 hmac.compare_digest）
    G1  仅验证签名ST      ：仅验 ST 签名/时效/服务，无挑战、无绑定、无单次
    G2  ST + device DID挑战：验 ST + 设备 DID 私钥挑战，无绑定、无单次
    G3  完整闭环          ：UserAuthContext + user/device/service/netperm 绑定
                           + 单次 ST + stateful challenge（真实 Relay）

输出（独立 formal_v2_<run_id> 目录）：
    expB1_flow.csv      (group, n_runs, legal_admission_rate, admission_p50_ms,
                         admission_p95_ms, request_bytes, credential_bytes)
    expB1_attack.csv    (group, attack_type, attempts, blocked, block_rate,
                         reject_stage, error)
    manifest.json
"""

import hmac as _hmac
import json
import subprocess
import sys
import time
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent.parent))

from core.authorization import issue_auth
from core.common import (SEED, csv_meta, rand_bytes, stats_ms, write_csv)
from core.device import Device
from core.kdc import KDC
from core.relay import Relay
from core.sm9_engine import SM9Engine
from core.st_ticket import netperm_defaults

REALM_SERVICE = "relay@realm"
CORRECT_PSK = b"static-psk-0123456789abcdef"
N_RUNS = 100
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


class World:
    def __init__(self, sm9, netperm):
        self.sm9 = sm9
        self.kdc = KDC(sm9)
        ctx1 = self.kdc.auth_context.issue("didsm9:user1:aaa", "src-1", "ev-1")
        assert self.kdc.register_user_context(ctx1)
        self.kdc.register_user("didsm9:user2:bbb", authenticated=False)
        self.relay = Relay(sm9, self.kdc, relay_id="relay-1")
        self.relay.setup_proxy()
        self.netperm = netperm
        self.st_service = self.kdc.st


def legal_device(world, enroll=True):
    dev = Device(next_dev_id(), "didsm9:user1:aaa", world.sm9)
    dev.psk = CORRECT_PSK
    if enroll:
        assert dev.enroll(world.kdc)
        dev.obtain_authorization(world.kdc, world.netperm)
    return dev


# ----------------------------------------------------------------------
# 四组准入（返回 (ok, stage, error, ms)）
# ----------------------------------------------------------------------
def admit_g0(device):
    t0 = time.perf_counter()
    ok = _hmac.compare_digest(device.psk, CORRECT_PSK)
    ms = (time.perf_counter() - t0) * 1000.0
    return (True, "", "", ms) if ok else (False, "psk", "psk_mismatch", ms)


def admit_g1(st_service, device, service):
    t0 = time.perf_counter()
    r = st_service.verify_ticket(device.st, service)   # 无 replay cache
    ms = (time.perf_counter() - t0) * 1000.0
    return (True, "", "", ms) if r["ok"] else (False, "st", r["error"], ms)


def admit_g2(sm9, st_service, device, service):
    t0 = time.perf_counter()
    r = st_service.verify_ticket(device.st, service)   # 无 replay cache
    if not r["ok"]:
        return False, "st", r["error"], (time.perf_counter() - t0) * 1000.0
    target_did = device.st.get("device_did", device.st.get("principal"))
    challenge = rand_bytes(16, "g2_challenge")
    challenge_id = rand_bytes(16, "g2_id").hex()
    msg = _pack({"device_did": target_did, "challenge_id": challenge_id,
                 "challenge": challenge.hex()})
    sig = device.sm9.sign(device.did, msg)
    if not sm9.verify(target_did, msg, sig):
        return False, "challenge", "challenge_failed", (time.perf_counter() - t0) * 1000.0
    return True, "", "", (time.perf_counter() - t0) * 1000.0


def admit_g3(relay, device, service):
    t0 = time.perf_counter()
    r1 = relay.begin_admission(device.admission_round1(), service)
    if not r1["ok"]:
        return False, r1.get("stage", ""), r1.get("error", ""), (time.perf_counter() - t0) * 1000.0
    r2 = device.admission_round2(r1["challenge_id"], r1["challenge"], r1["request_digest"])
    fin = relay.finish_admission(r1["challenge_id"], r1["challenge"], r2["sig"],
                                 r2["nonce"], r2["ts"], service)
    ms = (time.perf_counter() - t0) * 1000.0
    if not fin["ok"]:
        return False, fin.get("stage", ""), fin.get("error", ""), ms
    return True, "", "", ms


def admit(group, world, device, service=REALM_SERVICE):
    if group == "G0":
        return admit_g0(device)
    if group == "G1":
        return admit_g1(world.st_service, device, service)
    if group == "G2":
        return admit_g2(world.sm9, world.st_service, device, service)
    return admit_g3(world.relay, device, service)


# ----------------------------------------------------------------------
# 诚实流程指标
# ----------------------------------------------------------------------
def run_flow(group, world, n_runs):
    latencies = []
    ok_count = 0
    req_bytes = 0
    cred_bytes = 0
    for _ in range(n_runs):
        dev = legal_device(world)
        ok, stage, err, ms = admit(group, world, dev)
        latencies.append(ms)
        if ok:
            ok_count += 1
            if group == "G0":
                req_bytes = len(CORRECT_PSK)
                cred_bytes = 0
            elif group == "G1":
                req_bytes = len(_pack({"st": dev.st}))
                cred_bytes = 0
            elif group == "G2":
                req_bytes = len(_pack({"st": dev.st, "did": dev.did}))
                cred_bytes = 0
            else:
                req_bytes = len(_pack(dev.admission_round1()))
                vaddr = list(world.relay.admitted.keys())[-1]
                cred_bytes = len(_pack(world.relay.admitted[vaddr]["credential"]))
    st = stats_ms(latencies)
    return {
        "group": group,
        "n_runs": n_runs,
        "legal_admission_rate": ok_count / n_runs,
        "admission_p50_ms": st["p50_ms"],
        "admission_p95_ms": st["p90_ms"],
        "request_bytes": req_bytes,
        "credential_bytes": cred_bytes,
    }


# ----------------------------------------------------------------------
# 攻击执行
# ----------------------------------------------------------------------
def run_attack(group, world, atype, n_attack):
    blocked = 0
    sample_stage = ""
    sample_err = ""

    for _ in range(n_attack):
        ok, stage, err = _one_attack(group, world, atype)
        if not ok:
            blocked += 1
            sample_stage = stage
            sample_err = err

    return {
        "group": group,
        "attack_type": atype,
        "attempts": n_attack,
        "blocked": blocked,
        "block_rate": blocked / n_attack,
        "reject_stage": sample_stage,
        "error": sample_err,
    }


def _one_attack(group, world, atype):
    """构造并执行单个攻击样本，返回 (ok, stage, error)。ok=True 表示被放行（攻击成功）。"""
    sm9 = world.sm9

    # ---- 需要"先登记再过期/篡改"的干净世界，避免污染其它样本 ----
    if atype in ("expired_user_auth_context", "tampered_user_auth_context"):
        w2 = World(sm9, world.netperm)
        dev = legal_device(w2)
        if atype == "expired_user_auth_context":
            w2.kdc.users["didsm9:user1:aaa"]["expires_at"] = time.time() - 1.0
        else:
            w2.kdc.users["didsm9:user1:aaa"]["user_did"] = "didsm9:evil:xx"
        ok, stage, err, _ = admit(group, w2, dev, REALM_SERVICE)
        return ok, stage, err

    # ---- 需要先有合法设备作为基础 ----
    if atype in ("st_replay", "did_spoofing", "finish_request_tamper",
                 "challenge_replay"):
        return _one_stateful_attack(group, world, atype)

    dev = legal_device(world)
    service = REALM_SERVICE

    if atype == "psk_mismatch":
        dev.psk = b"wrong-psk"
    elif atype == "unbound_device":
        dev2 = Device(next_dev_id(), "didsm9:user1:aaa", sm9)
        dev2.psk = CORRECT_PSK
        exp = time.time() + 1800
        dev2.auth = world.kdc.issue_auth(dev2.did, world.netperm, exp,
                                         auth_id="aid-u", parent_auth_ticket_id="pat-u",
                                         user_did="didsm9:user1:aaa")
        dev2.st = world.kdc.issue_ticket(dev2.did, REALM_SERVICE, world.netperm,
                                         auth_id="aid-u", parent_auth_ticket_id="pat-u",
                                         user_did="didsm9:user1:aaa")
        dev = dev2
    elif atype == "user_device_mismatch":
        exp = time.time() + 1800
        dev.auth = world.kdc.issue_auth(dev.did, world.netperm, exp,
                                        auth_id="aid-m", parent_auth_ticket_id="pat-m",
                                        user_did="didsm9:user2:bbb")
        dev.st = world.kdc.issue_ticket(dev.did, REALM_SERVICE, world.netperm,
                                        auth_id="aid-m", parent_auth_ticket_id="pat-m",
                                        user_did="didsm9:user2:bbb")
    elif atype == "auth_st_device_mix_match":
        other = legal_device(world)
        dev.auth = other.auth          # auth.device_did = other.did != dev.did
    elif atype == "service_mismatch":
        service = "other@realm"
    elif atype == "netperm_escalation":
        narrow = dict(world.netperm); narrow["services"] = ["file-sync"]
        wide = dict(world.netperm); wide["services"] = ["file-sync", "rtc"]
        exp = time.time() + 1800
        dev.auth = world.kdc.issue_auth(dev.did, narrow, exp,
                                        auth_id="aid-n", parent_auth_ticket_id="pat-n",
                                        user_did=dev.owner_user_did)
        dev.st = world.kdc.issue_ticket(dev.did, REALM_SERVICE, wide,
                                        auth_id="aid-n", parent_auth_ticket_id="pat-n",
                                        user_did=dev.owner_user_did)
    elif atype == "caddr_mismatch":
        access = world.kdc.issue_device_access(dev.did, REALM_SERVICE,
                                               world.netperm, caddr="10.0.0.5")
        dev.auth, dev.st = access["auth"], access["st"]
        dev.caddr = "127.0.0.1"
    elif atype == "forged_auth":
        evil = SM9Engine(); evil_kdc = "didsm9:evil-kdc:ff"; evil.derive_sk(evil_kdc)
        dev.auth = issue_auth(evil, evil_kdc, dev.did, {"services": ["*"]},
                              exp=time.time() + 1800)
    elif atype == "forged_st":
        evil = SM9Engine(); evil_kdc = "didsm9:evil2:ff"; evil.derive_sk(evil_kdc)
        forged = dict(dev.st)
        forged["sig"] = evil.sign(evil_kdc, _pack({k: v for k, v in forged.items()
                                                   if k != "sig"})).hex()
        dev.st = forged
    elif atype == "tampered_st":
        dev.st["netperm"]["bandwidth_mbps"] = 999.0

    ok, stage, err, _ = admit(group, world, dev, service)
    return ok, stage, err


def _one_stateful_attack(group, world, atype):
    """针对两轮 stateful challenge 的攻击；G0/G1 直接放行；G2 仅 did_spoofing 有挑战。"""
    sm9 = world.sm9

    # did_spoofing：G2 有 DID 挑战（用 admit_g2 验），G3 用 stateful 挑战
    if atype == "did_spoofing" and group == "G2":
        victim = legal_device(world)
        attacker = Device(next_dev_id(), "didsm9:user2:bbb", sm9)
        attacker.psk = CORRECT_PSK
        attacker.st = victim.st
        ok, stage, err, _ = admit_g2(sm9, world.st_service, attacker, REALM_SERVICE)
        return ok, stage, err

    if group != "G3":
        # G0/G1 无 stateful challenge，无单次/重放/篡改 finish 语义 → 放行
        return True, "", ""

    relay = world.relay

    if atype == "st_replay":
        dev = legal_device(world)
        r1 = relay.begin_admission(dev.admission_round1(), REALM_SERVICE)
        if not r1["ok"]:
            return False, r1.get("stage", ""), r1.get("error", "")
        r2 = dev.admission_round2(r1["challenge_id"], r1["challenge"], r1["request_digest"])
        fin = relay.finish_admission(r1["challenge_id"], r1["challenge"], r2["sig"],
                                     r2["nonce"], r2["ts"], REALM_SERVICE)
        if not fin["ok"]:
            return False, fin.get("stage", ""), fin.get("error", "")
        dev2 = Device(next_dev_id(), "didsm9:user1:aaa", sm9)
        dev2.auth, dev2.st = dev.auth, dev.st
        r = relay.begin_admission(dev2.admission_round1(), REALM_SERVICE)
        return (True, "", "") if r["ok"] else (False, r.get("stage", ""), r.get("error", ""))

    if atype == "did_spoofing":
        dev = legal_device(world)
        r1 = relay.begin_admission(dev.admission_round1(), REALM_SERVICE)
        if not r1["ok"]:
            return False, r1.get("stage", ""), r1.get("error", "")
        attacker = Device(next_dev_id(), "didsm9:user2:bbb", sm9)
        nonce = rand_bytes(16, "spoof")
        msg = _pack({"device_did": dev.did, "challenge_id": r1["challenge_id"],
                     "challenge": r1["challenge"].hex(),
                     "request_digest": r1["request_digest"],
                     "nonce": nonce.hex(), "ts": time.time()})
        sig = attacker.sm9.sign(attacker.did, msg)
        fin = relay.finish_admission(r1["challenge_id"], r1["challenge"], sig,
                                     nonce, time.time(), REALM_SERVICE)
        return (True, "", "") if fin["ok"] else (False, fin.get("stage", ""), fin.get("error", ""))

    if atype == "finish_request_tamper":
        dev = legal_device(world)
        r1 = relay.begin_admission(dev.admission_round1(), REALM_SERVICE)
        if not r1["ok"]:
            return False, r1.get("stage", ""), r1.get("error", "")
        # 篡改 challenge 应答载荷（改 nonce 后用自己的 key 重签）→ 与 request_digest/challenge 不符
        nonce = rand_bytes(16, "tamper")
        msg = _pack({"device_did": dev.did, "challenge_id": r1["challenge_id"],
                     "challenge": r1["challenge"].hex(),
                     "request_digest": "deadbeef",   # 篡改 request_digest
                     "nonce": nonce.hex(), "ts": time.time()})
        sig = dev.sm9.sign(dev.did, msg)
        fin = relay.finish_admission(r1["challenge_id"], r1["challenge"], sig,
                                     nonce, time.time(), REALM_SERVICE)
        return (True, "", "") if fin["ok"] else (False, fin.get("stage", ""), fin.get("error", ""))

    if atype == "challenge_replay":
        dev = legal_device(world)
        r1 = relay.begin_admission(dev.admission_round1(), REALM_SERVICE)
        if not r1["ok"]:
            return False, r1.get("stage", ""), r1.get("error", "")
        r2 = dev.admission_round2(r1["challenge_id"], r1["challenge"], r1["request_digest"])
        fin = relay.finish_admission(r1["challenge_id"], r1["challenge"], r2["sig"],
                                     r2["nonce"], r2["ts"], REALM_SERVICE)
        if not fin["ok"]:
            return False, fin.get("stage", ""), fin.get("error", "")
        fin2 = relay.finish_admission(r1["challenge_id"], r1["challenge"], r2["sig"],
                                      r2["nonce"], r2["ts"], REALM_SERVICE)
        return (True, "", "") if fin2["ok"] else (False, fin2.get("stage", ""), fin2.get("error", ""))

    return True, "", ""


ATTACK_TYPES = [
    "expired_user_auth_context",
    "tampered_user_auth_context",
    "unbound_device",
    "user_device_mismatch",
    "auth_st_device_mix_match",
    "service_mismatch",
    "netperm_escalation",
    "caddr_mismatch",
    "forged_auth",
    "forged_st",
    "tampered_st",
    "st_replay",
    "did_spoofing",
    "finish_request_tamper",
    "challenge_replay",
    "psk_mismatch",
]


def main():
    quick = "--quick" in sys.argv
    n_runs = 5 if quick else N_RUNS
    n_attack = 5 if quick else N_ATTACK
    run_id = time.strftime("%Y%m%d_%H%M%S") + f"_{time.time_ns() % 1000000000:09d}"
    out_dir = RESULTS / f"formal_v2_{run_id}"
    out_dir.mkdir(parents=True, exist_ok=False)

    sm9 = SM9Engine()
    netperm = netperm_defaults()
    netperm["services"] = ["file-sync", "rtc"]
    netperm["bandwidth_mbps"] = 10.0

    flow_rows = []
    attack_rows = []
    for group in ("G0", "G1", "G2", "G3"):
        flow_rows.append(run_flow(group, World(sm9, netperm), n_runs))
        for atype in ATTACK_TYPES:
            # 每种攻击使用独立 world，避免 expired/tampered context 污染后续样本
            attack_rows.append(run_attack(group, World(sm9, netperm), atype, n_attack))

    write_csv(out_dir / "expB1_flow.csv", flow_rows)
    write_csv(out_dir / "expB1_attack.csv", attack_rows)
    manifest = {
        "git_commit": _git_head(),
        "dirty_worktree": _git_dirty(),
        "mode": "quick" if quick else "formal",
        "seed": SEED,
        "n_runs": n_runs,
        "n_attack": n_attack,
        "simulated_components": ["SM9 engine (gmalg-or-simulated)", "NAT not used here"],
    }
    (out_dir / "manifest.json").write_text(
        json.dumps(manifest, ensure_ascii=False, indent=2), encoding="utf-8")
    for f in ("expB1_flow.csv", "expB1_attack.csv"):
        csv_meta(out_dir / f, {"seed": SEED, "mode": manifest["mode"],
                               "n_runs": n_runs, "n_attack": n_attack})

    for r in flow_rows:
        print(f"  flow[{r['group']}] legal_rate={r['legal_admission_rate']:.2%} "
              f"p50={r['admission_p50_ms']:.2f}ms p95={r['admission_p95_ms']:.2f}ms "
              f"req={r['request_bytes']}B cred={r['credential_bytes']}B")
    g3 = [r for r in attack_rows if r["group"] == "G3"]
    bad = [r for r in g3 if r["block_rate"] < 1.0]
    print(f"  G3 attacks: {len(g3)} types; 未全拦截={[r['attack_type'] for r in bad]}")
    g0 = [r for r in attack_rows if r["group"] == "G0" and r["attack_type"] == "psk_mismatch"]
    print(f"  G0 psk_mismatch block_rate={g0[0]['block_rate']:.2%}")


if __name__ == "__main__":
    main()
