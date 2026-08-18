"""
方向三一键复跑：C0 → C1 → C3 → C2 → C4（《代码汇总版》§7.3 顺序）。
用法：python run_all.py [--quick] [--conc1000]
    --quick    各实验冒烟模式（缩短时长/样本）
    --conc1000 C2 追加 1000 并发档（D3 预留参数）
"""

import subprocess
import sys
import time
from pathlib import Path

ROOT = Path(__file__).resolve().parent
VENV = "/home/yfish/trae/code/v6-大论文版/.venv/bin/python"
STEPS = ["expC0_agent_id.py", "expC1_scenarios.py", "expC3_attacks.py",
         "expC2_performance.py", "expC4_security_matrix.py"]


def main():
    quick = "--quick" in sys.argv
    conc1000 = "--conc1000" in sys.argv
    t0 = time.perf_counter()
    for name in STEPS:
        cmd = [VENV, "-B", str(ROOT / "experiments" / name)]
        if quick:
            cmd.append("--quick")
        if conc1000 and name == "expC2_performance.py":
            cmd.append("--conc1000")
        print(f"\n=== {name} ===")
        subprocess.run(cmd, check=True)
    print(f"\nALL DONE in {time.perf_counter() - t0:.0f}s")


if __name__ == "__main__":
    main()