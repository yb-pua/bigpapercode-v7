"""方向三实验的独立运行目录与 manifest 工具。"""

import json
import platform
import subprocess
import sys
import time
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent


def _git(args):
    try:
        return subprocess.check_output(
            ["git", *args], cwd=REPO_ROOT, text=True,
            stderr=subprocess.DEVNULL).strip()
    except Exception:
        return "unknown"


def start_run(results_dir: Path):
    """创建独立 formal_v2 目录；先捕获工作树状态，避免新结果自身导致 dirty。"""
    state = {
        "git_commit": _git(["rev-parse", "HEAD"]),
        "dirty_worktree": bool(_git(["status", "--porcelain"]) not in
                               ("", "unknown")),
        "timestamp": time.strftime("%Y-%m-%dT%H:%M:%S%z"),
        "python": sys.version.split()[0],
        "platform": platform.platform(),
    }
    run_id = time.strftime("%Y%m%d_%H%M%S") + \
        f"_{time.time_ns() % 1000000000:09d}"
    out_dir = results_dir / f"formal_v2_{run_id}"
    out_dir.mkdir(parents=True, exist_ok=False)
    return out_dir, state


def write_manifest(out_dir: Path, state: dict, *, mode: str, seed: int,
                   parameters: dict, simulated_components: list,
                   measurement_mode: str = "functional_simulation"):
    manifest = dict(state)
    manifest.update({
        "mode": mode,
        "seed": seed,
        "measurement_mode": measurement_mode,
        "parameters": parameters,
        "simulated_components": simulated_components,
    })
    (out_dir / "manifest.json").write_text(
        json.dumps(manifest, ensure_ascii=False, indent=2), encoding="utf-8")
    return manifest
