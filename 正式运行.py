#!/usr/bin/env python3
"""V7 三方向正式数据一键串行运行器（正式模式，不带 --quick）。

按论文 §7 顺序执行 15 个实验，逐个记录返回码与耗时，失败不中断后续实验。
日志实时打印，由外层重定向到文件。
"""
import subprocess
import time
from pathlib import Path

ROOT = Path(__file__).resolve().parent
VENV = "/home/yfish/trae/code/v6-大论文版/.venv/bin/python"

# (标签, 实验脚本绝对路径) —— 沿用 v6 的官方执行顺序
STEPS = [
    ("方向一/A1", ROOT / "方向一/实验/实验一密钥恢复/实验一.py"),
    ("方向一/A2", ROOT / "方向一/实验/实验二噪声鲁棒/实验二.py"),
    ("方向一/A3", ROOT / "方向一/实验/实验三端到端/实验三.py"),
    ("方向一/A4", ROOT / "方向一/实验/实验四性能对比/实验四.py"),
    ("方向一/A5", ROOT / "方向一/实验/实验五攻击隐私/实验五.py"),
    ("方向二/B0", ROOT / "方向二/实验/实验零发现打洞/实验零.py"),
    ("方向二/B1", ROOT / "方向二/实验/实验一准入/实验一.py"),
    ("方向二/B2", ROOT / "方向二/实验/实验二扩展性/实验二.py"),
    ("方向二/B3", ROOT / "方向二/实验/实验三整形/实验三.py"),
    ("方向二/B4", ROOT / "方向二/实验/实验四攻击/实验四.py"),
    ("方向三/C0", ROOT / "方向三/实验/实验零身份锚定/实验零.py"),
    ("方向三/C1", ROOT / "方向三/实验/实验一场景审计/实验一.py"),
    ("方向三/C3", ROOT / "方向三/实验/实验三攻击消融/实验三.py"),
    ("方向三/C2", ROOT / "方向三/实验/实验二性能/实验二.py"),
    ("方向三/C4", ROOT / "方向三/实验/实验四安全矩阵/实验四.py"),
]


def main():
    t0 = time.perf_counter()
    results = []
    for tag, script in STEPS:
        if not script.exists():
            print(f"[SKIP] {tag}: 脚本不存在 {script}", flush=True)
            results.append((tag, -1, 0.0, "missing"))
            continue
        st = time.perf_counter()
        print(f"\n===== {tag} 开始: {script.name} =====", flush=True)
        rc = subprocess.call([VENV, "-B", str(script)], cwd=str(script.parent))
        dt = time.perf_counter() - st
        status = "OK" if rc == 0 else f"FAIL(rc={rc})"
        print(f"===== {tag} 结束: {status} 耗时 {dt:.0f}s =====", flush=True)
        results.append((tag, rc, dt, status))

    print("\n\n########## 汇总 ##########", flush=True)
    for tag, rc, dt, status in results:
        print(f"{tag}: {status} {dt:.0f}s", flush=True)
    print(f"总耗时 {time.perf_counter() - t0:.0f}s", flush=True)


if __name__ == "__main__":
    main()
