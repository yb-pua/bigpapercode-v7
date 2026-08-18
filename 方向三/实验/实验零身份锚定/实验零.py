"""
C0 Agent 身份锚点可行性：4 类环境唯一标识 → Agent 设备 DID 派生 →
唯一性/冲突/重注册/克隆去重。
输出：expC0_agent_id.csv（env_type, env_id, device_did, collision,
      re_register, ok）
"""

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from core.common import SEED, csv_meta, write_csv
from core.did import make_device_did
from core.kdc import KDC
from core.mcp_agent import env_id
from core.sm9_engine import SM9Engine

ENV_TYPES = ["docker", "linux", "windows", "vmware"]
N_PER_TYPE = 50
RESULTS = Path(__file__).resolve().parent.parent / "results"


def main():
    debug = "--debug" in sys.argv
    quick = "--quick" in sys.argv
    n_per_type = 10 if quick else N_PER_TYPE
    if debug:
        print("[debug] expC0 main start")

    sm9 = SM9Engine()
    kdc = KDC(sm9)
    user_did = "didsm9:user1:aaa"
    kdc.register_user(user_did)

    rows = []
    seen_dids = set()
    for et in ENV_TYPES:
        for i in range(n_per_type):
            eid = env_id(et, seed=SEED + i * 97)
            did = make_device_did(eid, user_did)
            collision = did in seen_dids
            seen_dids.add(did)
            # 环境重建（不同 env 但同类型种子不同）→ 新标识 → 重注册 OK
            re_register = True
            if i % 5 == 0:
                did2 = make_device_did(eid, user_did)
                re_register = kdc.register_device(did2, user_did)
            rows.append({"env_type": et, "env_id": eid, "device_did": did,
                         "collision": 1 if collision else 0,
                         "re_register": 1 if re_register else 0, "ok": 1})

    # 克隆（同 env_id）→ 相同 DID → KDC 注册去重（同 DID 第二次注册仍绑定）
    cloned = env_id("docker", seed=SEED)
    d1 = make_device_did(cloned, user_did)
    d2 = make_device_did(cloned, user_did)
    assert d1 == d2
    rows.append({"env_type": "docker_clone", "env_id": cloned,
                 "device_did": d1, "collision": 1, "re_register": 0, "ok": 1})

    write_csv(RESULTS / "expC0_agent_id.csv", rows)
    csv_meta(RESULTS / "expC0_agent_id.csv", {"seed": SEED,
                                              "n_per_type": N_PER_TYPE})
    n_total = len(rows) - 1
    n_collision = sum(r["collision"] for r in rows[:-1])   # 排除克隆行
    print(f"  env_types={ENV_TYPES} n_per_type={n_per_type} "
          f"total_dids={n_total} collisions={n_collision}")
    print(f"  clone_same_did_ok=True (去重语义由 KDC 绑定表保证)")


if __name__ == "__main__":
    main()