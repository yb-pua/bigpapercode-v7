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
STEPS = ["实验零身份锚定/实验零.py", "实验一场景审计/实验一.py", "实验三攻击消融/实验三.py",
         "实验二性能/实验二.py", "实验四安全矩阵/实验四.py"]


def main():
    quick = "--quick" in sys.argv
    conc1000 = "--conc1000" in sys.argv
    t0 = time.perf_counter()
    for name in STEPS:
        cmd = [VENV, "-B", str(ROOT / name)]
        if quick:
            cmd.append("--quick")
        if conc1000 and name == "实验二性能/实验二.py":
            cmd.append("--conc1000")
        print(f"\n=== {name} ===")
        subprocess.run(cmd, check=True)
    print(f"\nALL DONE in {time.perf_counter() - t0:.0f}s")


if __name__ == "__main__":
    main()