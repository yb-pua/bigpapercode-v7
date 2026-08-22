"""一键复现：A1 → A2 → A3 → A4 → A5（缓存缺失时先构建特征缓存）。

用法：
    python experiments/run_all.py            # 全量（含缓存构建，约 1-2 小时）
    python experiments/run_all.py --skip-cache
    python experiments/run_all.py --quick    # 冒烟（每实验小样本）
"""

import argparse
import subprocess
import sys
import time
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from core.face_embedder import EmbeddingCache, FaceEmbedder
from data_config import FORMAL_V2_CACHE_DIR, INSIGHTFACE_ROOT

STEPS = [
    ("A1", "实验一密钥恢复/实验一.py"),
    ("A2", "实验二噪声鲁棒/实验二.py"),
    ("A3", "实验三端到端/实验三.py"),
    ("A4", "实验四性能对比/实验四.py"),
    ("A5", "实验五攻击隐私/实验五.py"),
]


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--skip-cache", action="store_true")
    ap.add_argument("--quick", action="store_true")
    args = ap.parse_args()
    root = Path(__file__).resolve().parent

    if not args.skip_cache:
        embedder = FaceEmbedder(backend="insightface", model_root=INSIGHTFACE_ROOT)
        cache = EmbeddingCache(str(FORMAL_V2_CACHE_DIR), embedder)
        if not cache.has_cache():
            print("[run_all] 构建正式 V2 全量缓存 ...")
            subprocess.check_call([
                sys.executable, str(root / "建缓存.py"), "--full-lfw",
            ])
        else:
            print("[run_all] 正式 V2 缓存已存在，跳过")

    results = {}
    for name, script in STEPS:
        t0 = time.time()
        print(f"\n=== {name}: {script} ===")
        rc = subprocess.call([sys.executable, str(root / script)] +
                              (["--quick"] if args.quick else []))
        results[name] = (rc, time.time() - t0)
        if rc != 0:
            print(f"[run_all] {name} FAILED (rc={rc})")
            sys.exit(1)

    print("\n=== run_all 完成 ===")
    for name, (rc, dt) in results.items():
        print(f"{name}: rc={rc} {dt:.0f}s")


if __name__ == "__main__":
    main()