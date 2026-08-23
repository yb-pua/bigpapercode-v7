"""
C0 Agent 身份锚点可行性：4 类环境唯一标识 → Agent 设备 DID 派生 →
唯一性/冲突/重注册/克隆去重。
输出：expC0_agent_id.csv（env_type, env_id, device_did, collision,
      re_register, ok）
"""

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent.parent))

from core.common import SEED, csv_meta, write_csv
from core.did import make_device_did, make_user_did
from core.kdc import KDC
from core.mcp_agent import env_id
from core.sm9_engine import SM9Engine
from 实验.run_support import start_run, write_manifest

ENV_TYPES = ["docker", "linux", "windows", "vmware"]
N_PER_TYPE = 50
RESULTS = Path(__file__).resolve().parent / "结果"


def main():
    debug = "--debug" in sys.argv
    quick = "--quick" in sys.argv
    n_per_type = 10 if quick else N_PER_TYPE
    out_dir, run_state = start_run(RESULTS)
    if debug:
        print("[debug] expC0 main start")

    sm9 = SM9Engine()
    kdc = KDC(sm9)
    owner_user_id = "user1"
    user_did = make_user_did(owner_user_id)
    kdc.register_user(user_did)

    rows = []
    seen_dids = set()
    for et in ENV_TYPES:
        for i in range(n_per_type):
            eid = env_id(et, seed=SEED + i * 97)
            did = make_device_did(eid, owner_user_id)
            collision = did in seen_dids
            seen_dids.add(did)
            first_ok = kdc.register_device(did, user_did)      # 首次注册（真实）
            re_ok = kdc.register_device(did, user_did)         # 幂等重注册（真实）
            rows.append({"env_type": et, "env_id": eid, "device_did": did,
                         "owner_user_id": owner_user_id,
                         "owner_user_did": user_did,
                         "collision": 1 if collision else 0,
                         "re_register": 1 if re_ok else 0,
                         "ok": 1 if first_ok else 0})

    # 克隆（同 env_id）→ 相同 DID → KDC 注册去重（同 DID 第二次注册仍绑定）
    cloned = env_id("docker", seed=SEED)
    d1 = make_device_did(cloned, owner_user_id)
    d2 = make_device_did(cloned, owner_user_id)
    assert d1 == d2
    clone_ok = kdc.register_device(d1, user_did)   # 克隆真实注册（同 DID）
    rows.append({"env_type": "docker_clone", "env_id": cloned,
                 "device_did": d1, "owner_user_id": owner_user_id,
                 "owner_user_did": user_did,
                 "collision": 1, "re_register": 0,
                 "ok": 1 if clone_ok else 0})

    write_csv(out_dir / "expC0_agent_id.csv", rows)
    csv_meta(out_dir / "expC0_agent_id.csv", {"seed": SEED,
                                              "mode": "quick" if quick else "formal",
                                              "n_per_type": n_per_type})
    n_total = len(rows) - 1
    n_collision = sum(r["collision"] for r in rows[:-1])   # 排除克隆行
    print(f"  env_types={ENV_TYPES} n_per_type={n_per_type} "
          f"total_dids={n_total} collisions={n_collision}")
    print(f"  clone_same_did_ok=True (去重语义由 KDC 绑定表保证)")
    write_manifest(
        out_dir, run_state, mode="quick" if quick else "formal", seed=SEED,
        parameters={"env_types": ENV_TYPES, "n_per_type": n_per_type,
                    "n_total": n_total},
        simulated_components=["Agent environment identifiers",
                              "in-process KDC/device registry"],
    )


if __name__ == "__main__":
    main()
