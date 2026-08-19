# V7 实验环境静态预检（V7_PRECHECK）

- 检查时间：2026-08-19
- 环境：Python 3.14.6，venv 位于 `/home/yfish/trae/code/v6-大论文版/.venv`
- 范围：方向一 / 方向二 / 方向三（代码 + 实验入口 + 配置）

## 一、12 项静态检查结果

| # | 检查项 | 结果 | 说明 |
|---|---|---|---|
| 1 | Python 版本 | ✅ | 3.14.6 |
| 2 | requirements | ✅ | 三方向均有 requirements.txt |
| 3 | import 路径 | ❌ | 见问题 P0（sys.path 少一级，core 找不到） |
| 4 | 相对路径 | ❌ | 输出目录 results 未适配新「结果/」目录 |
| 5 | 数据集路径 | ✅ | LFW / InsightFace 绝对路径指向 `/dataset/`，仍有效 |
| 6 | 输出目录 | ❌ | `data_config.py` RESULTS_DIR = `方向一/results`，非每实验「结果/」 |
| 7 | CSV 输出文件名 | ✅ | 文件名本身正确（expA1_*.csv 等），仅目录不对 |
| 8 | seed | ✅ | SEED=20260817，三方向 core/common.py 一致 |
| 9 | 旧目录引用 | ✅ | 未发现 exp1/exp2/exp3 目录名硬引用 |
| 10 | v6 残留路径 | ⚠️ | 方向二/三 `全部运行.py` 的 VENV 仍指向 v6 venv |
| 11 | 硬编码结果 | ✅ | 未发现明显硬编码实验结果 |
| 12 | 临时文件依赖 | ⚠️ | 方向一 A1/A2 依赖特征缓存 cache/（未迁移，需 fallback 或重建） |

## 二、问题清单

### P0（阻断运行）— import 路径断链

- **文件**：三方向所有实验脚本（实验X.py、exp_common.py）
- **函数/位置**：文件头部 `sys.path.insert(0, str(Path(__file__).resolve().parent.parent))`
- **根因**：V7 把实验脚本下沉到 `方向X/实验/实验Y/`，`parent.parent` 只到 `方向X/实验/`，而 `core` 在 `方向X/core/`，需要 `parent.parent.parent`
- **影响**：`from core.xxx import ...` 全部失败，三方向实验入口均无法启动
- **最小修复**：把实验脚本的 sys.path 上移到 `parent.parent.parent`（或同时加入 core 所在目录）

### P1（输出目录未适配）

- **文件**：`方向一/data_config.py`（RESULTS_DIR/CACHE_DIR/FIGURES_DIR/TEE_AUDIT_PATH/AUDIT_PATH）
- **根因**：仍写 `PROJECT_ROOT / "results"`，与 V7 约定的每实验「结果/」目录不符
- **影响**：CSV 会写到 `方向一/results/` 而非 `方向一/实验/实验X/结果/`
- **最小修复**：结果目录改为指向每实验「结果/」目录（或由实验脚本传入）

### P1（v6 venv 路径残留）

- **文件**：`方向二/实验/全部运行.py`、`方向三/实验/全部运行.py`
- **根因**：`VENV = "/home/yfish/trae/code/v6-大论文版/.venv/bin/python"`
- **影响**：run_all 仍可运行（venv 仍存在），但属 v6 残留，迁移后需更新
- **最小修复**：VENV 指向当前可用 venv（或改为环境变量）

### P1（方向一特征缓存缺失）

- **文件**：方向一 A1/A2 依赖 `cache/embs_insightface.npy`
- **根因**：cache 为 npy 大文件，按 .gitignore 未迁移
- **影响**：A1/A2 无缓存时需 fallback 或重建
- **最小修复**：smoke test 用 fallback（合成嵌入）或跳过需缓存的部分

## 三、结论

- 三方向**核心代码（core/）完整**，seed 一致，数据集路径有效。
- 主要破坏点集中在**实验入口的路径适配**（import 路径 + 输出目录 + venv 路径），均属「允许修复范围」（import/path、输出目录、参数读取）。
- **未发现**核心算法、SM9/Fuzzy/DID/ST/MCP 协议被破坏的迹象。

下一步：按「允许修复范围」修复 import 路径与输出目录，再做三方向最小 smoke test。
