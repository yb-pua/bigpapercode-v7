"""
全局数据与运行配置（本工程唯一配置入口）。

本机环境（2026-08 实测）：
    LFW:     /home/yfish/trae/code/dataset/lfw/LFW - People (Face Recognition)_datasets/lfw_funneled
    InsightFace 模型: /home/yfish/trae/code/dataset/insightface (buffalo_l)
    统计：5749 人 / ≥2:1680 / ≥5:423 / ≥8:217 / ≥10:158
"""

import os
from pathlib import Path

from core.common import SEED

PROJECT_ROOT = Path(__file__).resolve().parent

LFW_DIR = os.environ.get(
    "LFW_DIR",
    "/home/yfish/trae/code/dataset/lfw/LFW - People (Face Recognition)_datasets/lfw_funneled",
)
INSIGHTFACE_ROOT = os.environ.get(
    "INSIGHTFACE_ROOT",
    "/home/yfish/trae/code/dataset/insightface",
)

CACHE_DIR = PROJECT_ROOT / "cache"
FORMAL_V2_CACHE_DIR = PROJECT_ROOT / "cache_formal_v2"   # 正式 V2 缓存（独立，禁止覆盖旧 cache/）
RESULTS_DIR = PROJECT_ROOT / "results"
FIGURES_DIR = RESULTS_DIR / "figures"

TEE_AUDIT_PATH = RESULTS_DIR / "kdc_tee_audit.jsonl"
AUDIT_PATH = RESULTS_DIR / "auth_audit.jsonl"

# 数据规约
VOTE_COHORT_MIN_IMAGES = 5          # 投票主档：≥5 张（423 人）
VOTE_PROBE_MIN_IMAGES = 6           # 正式划分：≥6 张（前5登记 + 第6独立 probe）
VOTE_ENROLL_IMAGES = 5              # 投票登记张数
ENROLL_IMAGES = 5                   # 登记张数（与 VOTE_ENROLL_IMAGES 语义一致）
CROSS_CONDITION_MIN_IMAGES = 2      # 跨条件双样本：≥2 张（1680 人）
IMPOSTOR_PAIRS = 5000               # 异人配对 ≥5000

# 特征后端
PRIMARY_BACKEND = "insightface"     # buffalo_l 512 维
ABLATION_BACKEND = "dlib"           # dlib 128 维（消融对照，本机不可用则标注）

# 专利常量（验收可查）
STABLE_THRESHOLD = 0.8              # 稳定性阈值
RS_N, RS_K, RS_T = 255, 191, 32     # RS(255,191,t=32)
TIMESTAMP_WINDOW = 30 * 60          # 30 分钟
BREAKER_THRESHOLD = 3               # 连续失败 3 次熔断
DID_PREFIX = "didsm9:"


def ensure_dirs():
    CACHE_DIR.mkdir(parents=True, exist_ok=True)
    RESULTS_DIR.mkdir(parents=True, exist_ok=True)
    FIGURES_DIR.mkdir(parents=True, exist_ok=True)