"""论文图表生成（300dpi PNG）：从 results/ CSV 读取，可独立重跑。

图1 expA1_threshold_scan.pdf/png   —— RS 纠错 θ 扫描（KRR vs θ）
图2 expA2_summary.pdf/png          —— 五类噪声 KRR 对比（分档）
图3 expA3_circuit.pdf/png          —— 熔断状态机时间线
"""

import sys
from pathlib import Path

import numpy as np

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

import matplotlib
matplotlib.use("Agg")
import matplotlib.pyplot as plt

from core.common import read_csv
from data_config import FIGURES_DIR, RESULTS_DIR

DPI = 300


def fig1():
    rows = read_csv(RESULTS_DIR / "expA1_threshold_scan.csv")
    thetas = sorted({int(r["theta"]) for r in rows})
    krr = [np.mean([int(r["ok"]) for r in rows if int(r["theta"]) == t])
           for t in thetas]
    plt.figure(figsize=(6, 4))
    plt.plot(thetas, krr, "o-", color="#1f77b4", label="KRR (RS 纠正)")
    plt.axvline(32, color="red", linestyle="--", alpha=0.7, label="RS(255,191,t=32) 容量")
    plt.xlabel(r"$\theta$（注入错误字节数）")
    plt.ylabel("密钥恢复率 KRR")
    plt.ylim(-0.05, 1.05)
    plt.legend()
    plt.grid(alpha=0.3)
    plt.tight_layout()
    plt.savefig(FIGURES_DIR / "expA1_threshold_scan.png", dpi=DPI)
    plt.close()


def fig2():
    rows = read_csv(RESULTS_DIR / "expA2_noise_krr.csv")
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
    rows = read_csv(RESULTS_DIR / "expA3_circuit.csv")
    states = {"closed": 0, "blocked": 1}
    seq = [int(r["seq"]) for r in rows]
    st = [states.get(r["state"], 0) for r in rows]
    plt.figure(figsize=(8, 3.5))
    plt.step(seq, st, where="post", color="#2ca02c")
    plt.yticks([0, 1], ["closed", "blocked"])
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