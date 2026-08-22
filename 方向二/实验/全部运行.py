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
STEPS = ["实验零发现打洞/实验零.py", "实验一准入/实验一.py", "实验二扩展性/实验二.py",
         "实验三整形/实验三.py", "实验四攻击/实验四.py"]


def main():
    quick = "--quick" in sys.argv
    t0 = time.perf_counter()
    for name in STEPS:
        cmd = [VENV, "-B", str(ROOT / name)]
        if quick:
            cmd.append("--quick")
        print(f"\n=== {name} ===")
        subprocess.run(cmd, check=True)
    print(f"\nALL DONE in {time.perf_counter() - t0:.0f}s")


if __name__ == "__main__":
    main()