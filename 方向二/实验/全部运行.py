"""
方向二一键复跑：B0 → B1 → B2 → B3 → B4 → 汇总。
用法：python run_all.py [--quick]
"""

import subprocess
import sys
import time
from pathlib import Path

ROOT = Path(__file__).resolve().parent
VENV = "/home/yfish/trae/code/v6-大论文版/.venv/bin/python"
STEPS = ["expB0_discovery_nat.py", "expB1_access.py", "expB2_scalability.py",
         "expB3_tunnel_shaping.py", "expB4_attacks.py"]


def main():
    quick = "--quick" in sys.argv
    t0 = time.perf_counter()
    for name in STEPS:
        cmd = [VENV, "-B", str(ROOT / "experiments" / name)]
        if quick:
            cmd.append("--quick")
        print(f"\n=== {name} ===")
        subprocess.run(cmd, check=True)
    print(f"\nALL DONE in {time.perf_counter() - t0:.0f}s")


if __name__ == "__main__":
    main()