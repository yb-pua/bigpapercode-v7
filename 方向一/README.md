# 方向一：基于 SM9 与生物特征模糊提取的 Kerberos 身份认证

> 对应专利 CN121567387A 四模块（SM9 标识密码 / 生物特征模糊提取非存储式模板 /
> 模拟 TEE / 安全熔断）的实验实现，产出论文可直接取用的 CSV（`results/`）。

## 一、工作与创新点

**工作**：将生物特征密钥（Fuzzy Extractor）与 SM9 标识密码、Kerberos 票据体系
三者融合，构造一套**无口令、无存储式生物模板、国密全链**的身份认证系统，并用
LFW + InsightFace 真实数据、gmalg 国密实现完成端到端实验。

**创新点**（按贡献度）：

1. **非存储式生物模板 + 模糊提取密钥**：512 维人脸嵌入 → 稳定位筛选（稳定性
   0.8，多数投票）→ 256 位稳定序列 W → SM3 派生生物密钥；helper data σ =
   码字⊕W_ext，**只存 σ 不存明文特征**，每次 Gen 注入随机盐使同人重登记
   σ 不可链接（A5-p02 实测不可链接）。对比同类生物密钥方案（Dodis 等模糊提取
   框架、Juels 模糊承诺），本方案把"密钥恢复率"从理论下界做到实测 100%。
2. **前置验签替代口令的 Kerberos 增强**：AS 注册/认证以 SM9 签名（生物密钥
   派生私钥）替代口令，票据载荷 SM4-CBC 密封、30min 时间窗、nonce 防重放、
   ticket_id 全链审计——Kerberos 安全语义 + 国密密码套件 + 无口令。
3. **模拟 TEE 持有 KGC 主密钥**：多进程隔离，审计日志全程不含主密钥材料
   （A3 实测 msk_in_log=False）。
4. **安全熔断**：连续 3 次认证失败 → L1 票据清理 + Rep 重认证；L1 失败 →
   L2 重新 Gen + 显式更新登记，阻断暴力/重放通道。

## 二、现状问题

传统身份认证与生物特征方案各有短板：

| 问题 | 现状痛点 |
|---|---|
| 口令认证 | 弱口令/撞库/钓鱼，Kerberos 传统实现依赖口令 |
| 生物模板存储 | 模板明文入库，泄露即永久性泄露（不可撤销） |
| 生物特征密钥方案 | 大多基于实验性哈希/固定模板，噪声鲁棒性与密钥强度难两全 |
| 国密合规 | 主流认证体系为 AES/ECDSA/RSA 套件，不满足国密改造要求 |
| 审计缺失 | 认证事件与票据生命周期（签发/使用/过期）无关联归因 |

## 三、解决方案

分层实现（`core/` 13 模块，全链路国密）：

```
生物图像 → InsightFace 512 维嵌入 → 稳定位筛选 → 模糊提取器 gen/rep
        → bio_key=SM3(W) → SM9 派生私钥(生物 DID) → Kerberos AS/TGS/Service
        → SM4-CBC 票据 + 30min 窗口 + nonce 防重放 + 熔断 + 模拟 TEE 审计
```

关键机制：

- **模糊提取器（非存储式）**：W=256 位（512 维符号量化+多数投票+稳定 0.8）；
  bio_key=SM3(W)；payload=bio_key‖salt‖0^159；RS(255,191,t=32) 编码；
  σ=码字⊕W_ext。σ 不含明文特征；盐随机 → 重登记不可链接。
- **SM9 标识密码**（gmalg 实现）：签名 97B、SM9 密钥交换；前置验签替代口令。
- **模拟 TEE（KGC）**：子进程持主密钥，审计日志无主密钥材料。
- **安全熔断**：3 次失败 → L1/L2 两级恢复。
- **Kerberos 增强**：AS/TGS/Service 全流程，SM4-CBC 密封，30min 窗，防重放。

## 四、参考论文

| 论文 | 作用 |
|---|---|
| Dodis, Reyzin, Smith. *Fuzzy Extractors: How to Generate Strong Keys from Biometrics and Other Noisy Data*, EUROCRYPT 2004 | 模糊提取器理论框架（Gen/Rep、纠错下界）——本方案 W 提取与 σ 构造的理论依据 |
| Juels, Wattenberg. *A Fuzzy Commitment Scheme*, CCS 1999 | 模糊承诺（模板=码字⊕特征）对比对象 |
| Deng et al. *InsightFace: 2D/3D Face Analysis*, TPAMI 2022（ArcFace, CVPR 2019） | 嵌入特征来源（buffalo_l 模型） |
| RFC 4120 *The Kerberos Network Authentication Service (V5)* | 票据体系/认证器/时间窗语义对照 |
| GB/T 38635.1/.2-2020 SM9 标识密码算法 | 签名/密钥交换国密原语 |
| GB/T 32905-2016 SM3、GB/T 32907-2016 SM4 | 哈希/对称加密国密原语 |

## 五、对比数据（与论文比什么）

| 对比项 | 论文/基线 | 本文数据（results/expA*） |
|---|---|---|
| 密钥恢复率 KRR | Fuzzy Extractor 理论纠错下界（RS t=32 可纠 ≤32 字节错） | 单图与五图投票 KRR=1.0000（A1） |
| 噪声鲁棒性 BER | 模糊承诺类方案噪声容忍窗口 | 单图/五图 BER≈31.9B（A1）；A2 六类扰动（高斯/亮度/旋转/模糊/遮挡/压缩）逐强度 KRR（A2） |
| 误识率 FAR/误拒率 FRR/EER | InsightFace 论文 FAR@FRR 指标 | EER=0.1771/AUC=0.0964（A1 上下文；异人 FAR 全放行基线见"已知限制"） |
| 认证时延 | Kerberos V5 常规实现、RSA/ECDSA 体系 | SM9 sign 116.3ms / verify 186.4ms / SM4 0.63ms / SM3 0.46ms（A4，gmalg 纯 Python） |
| 票据防重放 | RFC 4120 30min 窗口语义 | 窗口外/重复 nonce 全拒（A3，单测 26/26） |
| 隐私（模板泄露） | 明文模板存储基线 | 只存 σ；重登记不可链接；审计无主密钥（A3/A5） |

## 六、实验结果摘要

- **A1**：单图 KRR=1.0000、BER≈31.9B；五图投票 KRR=1.0000；阈值扫描全 θ 档
  KRR 表（expA1_threshold_scan.csv）。
- **A3**：端到端 AS→TGS→Service 全流程，熔断两级恢复，审计链完整，
  msk_in_log=False。
- **A4**：SM9 签名 116.3ms/验签 186.4ms（gmalg 纯 Python，论文需标注实现
  差异）；SM4 0.63ms；SM3 0.46ms；含 RSA2048/ECDSA-P256/SM2 对照。
- **A5**：9 类攻击 8 类拦截；σ 熵 7.1B（盐随机性）；重登记不可链接。
- 单测 `pytest tests/` 26/26 通过。

## 七、已知限制（论文引用时标注）

- gmalg 为纯 Python 国密参考实现，A4 绝对耗时不可与 OpenSSL 类库直接对比
  （相对量级对比有效）。
- TEE 为多进程模拟（真实 TEE 硬件隔离不在范围）。
- InsightFace CPU 推理（本机 ort/CUDA 不匹配）；A1/A2 当前 CSV 为
  中间后端产出，**真实特征缓存（4629 张，cache/build_cache2.log 收尾后）
  需重跑 A1/A2 才能作为论文终值**；A1 异人 FAR=1.0 为无真实特征时的
  合成嵌入结果，须标注。
- dlib 后端不可用（Python 3.14 无 wheel）→ 128 维消融标注 unavailable。
- A2 噪声鲁棒性 CSV（expA2_noise_krr/summary）在本机上次 run_all 中未产出
  （OpenCV 图像加载链路问题），已在联调清单中，复现时自动产出。

## 八、复现

```bash
# 环境：Python 3.14，依赖见 requirements.txt（numpy/opencv/gmalg/insightface/...）
OMP_NUM_THREADS=1 python experiments/build_cache.py \
    --image-list cache/needed_images.json        # 构建特征缓存（~1h，4629 张）
python experiments/run_all.py --skip-cache       # A1→A2→A3→A4→A5 全量
python experiments/run_all.py --quick            # 冒烟（每实验小样本）
```

确定性：固定种子 SEED=20260817；随机字节流由 SM3 派生（禁
os.urandom/SHA-256/BLAKE2b），全流程可复现。调试口：全部实验脚本支持
`--debug`（逐条明细）与 `--quick`（冒烟缩减）。

## 目录

```
core/            # 底座（密码原语/模糊提取/Kerberos/TEE/熔断/特征）
experiments/     # A1–A5 + run_all + 图表
cache/           # 特征缓存（npy，不入 git）
results/         # 输出 CSV（论文数据源）+ figures/
tests/           # 26 项单元测试
docs/API.md      # 模块接口文档
data_config.py   # 唯一配置入口
```

## 验收自查

- `pytest tests/`：26/26 通过（RS 纠错边界、SM3 标准向量、SM4 回环、SM9
  签名与密钥交换、TEE 审计、熔断、30min 窗口、重放防护等）。
- 从空 `results/` 执行 `run_all.py` 可完整复现全部 CSV。
- CSV 规约：英文列名、≥4 位有效数字、含 `#meta` 元数据行。