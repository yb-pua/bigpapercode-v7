"""论文图表生成（300dpi PNG）：从最新 formal_v2 输出目录读取。

图1 阈值扫描（synthetic_rs_threshold_scan）：RS 纠错 θ 扫描（KRR vs θ）
图2 噪声鲁棒：五类噪声 KRR 对比（分档）
图3 熔断状态机时间线（两场景：l1_success / l2_downgrade）
"""

import sys
from pathlib import Path

import numpy as np

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

import matplotlib
matplotlib.use("Agg")
import matplotlib.pyplot as plt

from core.common import read_csv
from data_config import FIGURES_DIR

ROOT = Path(__file__).resolve().parent
DPI = 300


def latest_run_dir(exp_name: str) -> Path:
    """返回 实验<name>/结果/ 下最新的 formal_v2_<run_id> 目录。"""
    result_dir = ROOT / exp_name / "结果"
    runs = sorted(d for d in result_dir.iterdir()
                  if d.is_dir() and d.name.startswith("formal_v2_"))
    if not runs:
        raise SystemExit(f"未找到 formal_v2 输出目录: {result_dir}")
    return runs[-1]


def fig1():
    a1 = latest_run_dir("实验一密钥恢复")
    rows = [r for r in read_csv(a1 / "attempts.csv")
            if r.get("experiment") == "synthetic_rs_threshold_scan"]
    thetas = sorted({int(r["theta_requested"]) for r in rows})
    krr = [np.mean([int(r["ok"]) for r in rows
                    if int(r["theta_requested"]) == t]) for t in thetas]
    plt.figure(figsize=(6, 4))
    plt.plot(thetas, krr, "o-", color="#1f77b4", label="KRR (RS 纠正)")
    plt.axvline(32, color="red", linestyle="--", alpha=0.7,
                label="RS(255,191,t=32) 容量")
    plt.xlabel(r"$\theta$（注入错误符号数）")
    plt.ylabel("密钥恢复率 KRR")
    plt.ylim(-0.05, 1.05)
    plt.legend()
    plt.grid(alpha=0.3)
    plt.tight_layout()
    plt.savefig(FIGURES_DIR / "expA1_threshold_scan.png", dpi=DPI)
    plt.close()


def fig2():
    a2 = latest_run_dir("实验二噪声鲁棒")
    rows = read_csv(a2 / "attempts.csv")
    types = sorted({r["noise_type"] for r in rows})
    intensities = {t: sorted({float(r["intensity"]) for r in rows
                              if r["noise_type"] == t}) for t in types}
    plt.figure(figsize=(9, 5))
    markers = ["o", "s", "^", "D", "v"]
    for t, m in zip(types, markers):
        xs = intensities[t]
        ys = [np.mean([int(r["ok"]) for r in rows
                       if r["noise_type"] == t and float(r["intensity"]) == x])
              for x in xs]
        plt.plot(xs, ys, marker=m, label=t, linewidth=1.5)
    plt.xlabel("扰动强度")
    plt.ylabel("密钥恢复率 KRR")
    plt.ylim(-0.05, 1.05)
    plt.legend()
    plt.grid(alpha=0.3)
    plt.tight_layout()
    plt.savefig(FIGURES_DIR / "expA2_noise_krr.png", dpi=DPI)
    plt.close()


def fig3():
    a3 = latest_run_dir("实验三端到端")
    rows = read_csv(a3 / "circuit.csv")
    states = {"closed": 0, "blocked": 1}
    scenarios = sorted({r["scenario"] for r in rows})
    plt.figure(figsize=(8, 3.5 * len(scenarios)))
    for si, sc in enumerate(scenarios, 1):
        sub = [r for r in rows if r["scenario"] == sc]
        seq = [int(r["seq"]) for r in sub]
        st = [states.get(r["state"], 0) for r in sub]
        plt.subplot(len(scenarios), 1, si)
        plt.step(seq, st, where="post", color="#2ca02c")
        plt.yticks([0, 1], ["closed", "blocked"])
        plt.title(sc)
        plt.xlabel("事件序列")
        plt.ylabel("熔断状态")
        plt.grid(alpha=0.3)
    plt.tight_layout()
    plt.savefig(FIGURES_DIR / "expA3_circuit.png", dpi=DPI)
    plt.close()


def main():
    debug = "--debug" in sys.argv
    FIGURES_DIR.mkdir(parents=True, exist_ok=True)
    fig1()
    fig2()
    fig3()
    print("figures ->", FIGURES_DIR)


if __name__ == "__main__":
    main()
