# 方向二：基于 SM9 的国密 P2P VPN（组网准入 + 流量整形 + 攻击面）

> 对应《代码汇总版》方向二：SM9 标识密码 + 短时票据（ST）+ 代理授权 +
> 虚拟 NAT 打洞 + 隧道整形，构建国密 P2P VPN 的可复现实证（B0–B4），
> 产出论文 CSV（`results/`）。

## 一、工作与创新点

**工作**：用 SM9 标识密码与 Kerberos 风格短时票据重写 P2P VPN 的准入、
授权、中继三大环节，实现"设备 DID 锚定 + 按需签发 ST + 代理授权 +
SM4 隧道 + 流量整形"，并以 OpenVPN 为基线完成对比实验。

**创新点**：

1. **ST 票据组网准入**：设备注册 KDC 后按服务签发短时 ST（SM9 签名+SM4 密封，
   30min 窗口，单次使用防重放），中继凭 ST 验收设备，取代 OpenVPN 的
   长时证书/口令体系——恶意设备/中继无法伪造或复用准入凭据（B1/B4 实测
   601 次攻击 100% 拦截）。
2. **代理授权 + 会话语柄**：中继凭 KDC 签发的代理授权书（scope 限定）代理
   设备通信，会话凭据限定转发范围——中继被攻陷也无法越权转发（B4
   代理伪造 5 项用例全部符合预期）。
3. **虚拟 NAT 四类映射打洞**：full_cone/restricted/port_restricted/symmetric
   四类 NAT 两两组合打洞判定 + 中继兜底比例推导（B0）。
4. **流量整形抗流量分析**：令牌桶 + 长度整形（固定/随机/请求模式三档），
   分布熵 H、KL 散度、冗余率量化整形收益（B3：period 流 H 0→3.28，
   request 流 H 1.0→3.56，KL 34.99/33.75）。
5. **国密全链**：SM9 签名/密钥交换 + SM3 哈希 + SM4 隧道加密，
   与 TLS1.3/AES-256-GCM 基线同环境对照（B3 帧统计、B2 握手时延）。

## 二、现状问题

| 问题 | 现状痛点 |
|---|---|
| 商用 VPN 密码套件 | OpenVPN/WireGuard 默认非国密（TLS/AES/ChaCha20），不满足国密改造要求 |
| 设备准入凭据 | 长时证书/共享口令，泄露面大、吊销滞后；无单次使用防重放 |
| 中继信任 | 中继全权转发，被攻陷即可窃听/越权（无代理授权约束） |
| NAT 穿透 | STUN/TURN 兜底高时延，混合 NAT 组合穿透成功率与中继比例无量化依据 |
| 流量分析 | 明文长度特征暴露协议类型/行为模式（OpenVPN/TLS 有固定记录层形态） |

## 三、解决方案

```
设备(DID=SM9 标识) → KDC 注册 → 按服务签发 ST(30min,单次) → 中继凭 ST 准入
→ 代理授权书(scope) → 虚拟 NAT 四类打洞/中继兜底 → SM9 密钥交换 → SM4 隧道
→ Shaper 整形(固定/随机/请求) → 数据面模拟(真实 SM4 加密+转发路径)
```

核心模块（`core/` 15 个）：

- `sm9_engine.py`：SM9 签名/验签/密钥交换/代理签名（含 h 补零修复，1500 次
  自验签 0 失败）；
- `st_ticket.py`：ST 签发/验证/防重放缓存（单次使用 + 30min 窗口 + 重放指纹）；
- `authorization.py`：代理授权书签发/验证/会话凭据；
- `relay.py`：准入两轮挑战-应答（begin/finish admission）、虚拟地址分配、转发；
- `nat_layer.py`：四类虚拟 NAT 打洞判定 + 中继兜底比例推导；
- `shaping.py`：令牌桶 + 长度整形 + 熵/KL/冗余率指标；
- `tunnel.py`：SM9 密钥交换建隧 + SM4-CBC 帧加解密（序号防重放）。

## 四、参考论文

| 论文/标准 | 作用 |
|---|---|
| RFC 4120 *Kerberos Network Authentication Service (V5)* | ST 票据/单次使用/时间窗语义来源 |
| RFC 5389 STUN / RFC 5766 TURN / RFC 3489 | NAT 打洞四类映射与中继兜底对照 |
| OpenVPN 官方架构（TLS 控制面 + tun 数据面） | 基线实现与对比对象 |
| WireGuard / Noise Protocol Framework | 现代 VPN 性能与安全语义对照 |
| Boneh, Lynn, Shacham *Short Signatures from the Weil Pairing*, ASIACRYPT 2001 | SM9 双线性对签名族理论背景 |
| GB/T 38635 SM9、GB/T 32905 SM3、GB/T 32907 SM4 | 国密原语 |
| 流量整形/抗流量分析（Tor 论文流控、VNP 填充类文献） | 整形收益度量（熵/KL/冗余率）对比基准 |

## 五、对比数据（与论文/基线比什么）

| 对比项 | 基线 | 本文数据（results/expB*） |
|---|---|---|
| 准入时延 | OpenVPN TLS 控制面握手（本机实测 p50=104.2ms，n=10） | 本文准入（verify_auth+verify_st+挑战应答）p50=670–677ms（N=10–200 平稳） |
| 扩展性 | 准入时延随规模增长曲线（OpenVPN 无此机制） | N=10/50/100/200 准入 p50≈670–677ms、零丢包、吞吐 0.69→9.79Mbps |
| 故障转移 | OpenVPN 网关故障无快速恢复机制 | relay 被杀 → 50 会话中断、恢复 16.07s（会话重建+重新准入） |
| NAT 穿透 | STUN/TURN 文献穿透率/中继时延 | 四类 NAT 两两组合打洞判定表 + 中继兜底比例（B0） |
| 抗攻击 | Kerberos/RFC 4120 重放窗口语义 | 8 类攻击 601 次 100% 拦截；代理伪造 5 用例全符合预期（B4） |
| 流量特征 | TLS1.3 记录层形态（AES-256-GCM 真实加密） | period 流 H 0→3.28、request 流 H 1.0→3.56、KL 34.99/33.75、冗余率 91.8%/183.9%（B3） |

## 六、实验结果摘要

- **B0**：发现服务 + 四类 NAT 打洞/中继判定表（expB1_discovery/nat.csv）。
- **B1**：7 类用例 ×100 次判定全部正确（legal 不误拦，expired/replay/
  forged_auth/tampered_st/did_spoofing/unbound 全拦，block_rate=1.0000）；
  时延分解 verify_auth/verify_st/challenge 三段。
- **B2**：N=10/50/100/200 准入 p50≈670–677ms 零丢包；OpenVPN 控制面握手
  p50=104.2ms（基线对照）；故障注入恢复 16.07s。
- **B3**：三型业务流（period/burst/request）× 三方案（sm9_raw/sm9_shaped/
  tls_baseline）10min/段：熵增益、KL、冗余率表；整形后帧数一致
  （不漏帧，仅延迟/填充）。
- **B4**：601 次攻击（replay_st/forged_auth/did_spoofing/malicious_relay/
  forged_st/tampered_st/expired_st）100% 拦截；代理伪造 5 项用例符合预期。
- 单测 `pytest tests/` 25/25 通过。

## 七、已知限制（论文引用时标注）

- 数据面为**本机内存模拟**（真实 SM4 加密 + 转发路径，标注 "simulated"）；
  OpenVPN 数据面同步标注 simulated（D1-A 拍板），仅控制面握手为实测。
- 吞吐受 GIL 限制（1.5–9.8Mbps 为趋势性对比，不反映真实网络吞吐上限）。
- gmalg 纯 Python 实现，时延绝对值为参考（相对量级对比有效）。
- 虚拟 NAT 为程序模拟四类映射（真实公网打洞需公网环境）。
- 整形 burst 档 1448B 已达最大长度档，无填充空间（如实记录）。

## 八、复现

```bash
python run_all.py            # B0→B1→B2→B3→B4 全量（B2 含 OpenVPN 基线）
python run_all.py --quick    # 冒烟
python experiments/expB2_scalability.py   # 单实验可独立运行
```

调试口：全部实验脚本支持 `--debug`（逐条明细）；`--quick` 冒烟缩减
（B0 6/6、B1 10 次、B2 规模[10]+握手 3+故障 10、B3 短段、B4 10 次）。
环境：Python 3.14 + venv（gmalg 1.1.2、cryptography 50.0.0、OpenSSL 3.5.7、
OpenVPN 2.7.6、numpy）。

## 目录

```
core/            # 15 模块（SM9/ST/代理授权/中继/隧道/NAT/整形/发现/绑定表）
experiments/     # B0–B4 + run_all
results/         # 全部 CSV（论文数据源）
tests/           # 25 项单元测试
docs/API.md      # 模块接口文档
```

## 验收自查

- `pytest tests/`：25/25 通过。
- 从空 `results/` 执行 `run_all.py` 可完整复现全部 CSV。
- CSV 规约：英文列名、≥4 位有效数字、含 `#meta` 元数据行。