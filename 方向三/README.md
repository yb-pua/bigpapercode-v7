# 方向三：SM9 + 双 DID 的 MCP 安全访问控制（C0–C4）

> 对应《代码汇总版》方向三：AI Agent 环境标识锚定双 DID（用户生物 DID +
> 设备 DID），双 ST 票据 + 双签名链 + MCP 四步验证，OAuth 2.1 与无管控
> 基线同环境对照（C0–C4），产出论文 CSV（`results/`）。

## 一、工作与创新点

**工作**：面向 MCP（Model Context Protocol）服务调用，用 SM9 标识密码构造
"双 DID + 双 ST + 双签名链"的调用级访问控制：Agent 运行环境标识（4 类
环境类型）锚定设备 DID，用户在 KDC 以生物 DID 注册，一次 MCP 调用携带
ST_net（组网）+ ST_data（数据权限）双票据与"先设备后用户"的双签名链，
服务端四步验证；并复刻 OAuth 2.1 授权态缓存缺陷与无管控基线做同环境对照。

**创新点**（按贡献度）：

1. **环境标识锚定双 DID**：Agent 运行环境（docker/k8s/desktop/server 四类）
   唯一标识派生设备 DID，KDC 绑定表将用户生物 DID 与设备 DID 绑定，
   DID 冲突/克隆可检测（C0：200 DID 零冲突，克隆同标识→同 DID 被识别）。
2. **双 ST 分离组网与数据权限**：ST_net 管组网、ST_data 带 claims
   （tools+actions），30min 窗口 + 单次使用防重放——权限粒度到
   tool+action 级，OAuth server 级 scope 无法比拟（C3：越权 100% 拦截 vs
   OAuth 0%）。
3. **双签名链每请求认证**：σ_agent=Sign(设备sk, SM3(Cmd‖ts‖req_id))，
   σ_user=Sign(生物sk, SM3(Cmd‖σ_agent‖ctx))，服务端按
   "用户→设备"链验——调用者混淆/伪造/重放全部失效（C3 六类攻击
   100% 拦截，OAuth/无管控全部放行）。
4. **四步验证**：①双 ST 验签+防重放 ②双签名链 ③签名者 DID==票据
   Principal ④ClaimsChecker tool+action 匹配；消融实验证明
   ②④ 层为必要（去掉任一层正常调用 100% 失败，C3 消融）。
5. **审计全链归因**：ticket_id 从 KDC 签发 → 网关 → MCP 调用贯通
   （C1 审计链 complete_rate=1.0）。
6. **同环境缺陷复刻**：OAuth 2.1 基线复现"授权态缓存复用"缺陷
   （token 与调用者不绑定 → 调用者混淆可打穿），为对比提供真实缺陷
   而非理论假设。

## 二、现状问题

| 问题 | 现状痛点 |
|---|---|
| MCP 无调用级认证 | MCP 规范依赖传输层（OAuth 2.1）授权，scope 为服务级，无法约束"哪个 Agent 以谁的身份调用哪个工具" |
| Agent 身份伪造 | LLM 生态下 Agent 运行环境多样（docker/k8s/桌面/服务器），无统一环境标识锚定，DID 冒用/克隆无法检测 |
| 权限粒度粗 | OAuth scope 服务级：持 token 即可调全部工具（越权/调用者混淆缺陷） |
| 一次性授权态复用 | 授权码换 token 后授权态被缓存，调用时不再校验绑定（复刻缺陷见 C3-6） |
| 审计不可归因 | OAuth 仅授权时审计，调用事件无身份关联键 |
| 国密合规 | MCP 生态默认 TLS/AES，无国密改造路径 |

## 三、解决方案

```
Agent 环境标识(env_type+seed → env_id) → 设备 DID ←绑定→ 用户生物 DID
→ KDC 双 ST：ST_net(组网 NetPerm) + ST_data(claims={tools,actions})
→ 双签名链：σ_agent=Sign(设备sk,SM3(Cmd‖ts‖req_id))
            σ_user=Sign(生物sk,SM3(Cmd‖σ_agent‖ctx))
→ MCP JSON-RPC tools/call + 头 X-ST-Ticket / X-ST-Ticket-Net
→ 服务端四步验证：①双ST(验签+单次防重放) ②签名链 ③DID一致性 ④权限匹配
→ 网关：ST_net 跨域准入，载荷不解密；审计 ticket_id 全链贯通
```

基线：`OAuthBaseline`（授权码+PKCE+授权态缓存复用缺陷，server 级 scope）、
`NoAuthBaseline`（裸调用，无任何安全功能）。

## 四、参考论文

| 论文/标准 | 作用 |
|---|---|
| Anthropic. *Model Context Protocol*（2024–2025） | MCP 协议形态（JSON-RPC tools/call、认证走 OAuth） |
| draft-ietf-oauth-v2-1（OAuth 2.1） | 基线协议：授权码+PKCE、scope 粒度、token 生命周期 |
| RFC 4120 *Kerberos Network Authentication Service (V5)* | 票据体系/认证器/时间窗语义（ST_net/ST_data 双票） |
| GB/T 38635 SM9、GB/T 32905 SM3、GB/T 32907 SM4 | 国密原语（双签名链、票据密封） |
| Boneh, Lynn, Shacham *Short Signatures from the Weil Pairing*, ASIACRYPT 2001 | SM9 双线性对签名族理论背景 |
| 方向一专利 CN121567387A 生物密钥模块 | 用户生物 DID 与生物密钥派生来源 |

## 五、对比数据（与论文/基线比什么）

| 对比项 | 基线/论文 | 本文数据（results/expC*） |
|---|---|---|
| 调用级安全矩阵（7 维） | 标准 Kerberos / 国密 Kerberos / OAuth 2.1 | expC4_security_matrix.csv：本文 7 维全 1；OAuth 抗重放/粒度/绑定/审计=0 |
| 攻击拦截率 | OAuth 2.1 / 无管控 | 六类攻击（tampered/priv_esc/replay/forged_st/did_spoof/confusion）本文 100% 拦截，OAuth/noauth 0%（C3 attack_matrix） |
| 权限粒度 | OAuth server 级 scope | claims tool+action 级（越权指令本文全拦、OAuth 全放行） |
| 性能开销 | OAuth 直连（纯查表） | 本文每调用含双 ST+双签名链（报文 ~2.3KB），p50/p90/p99/QPS 对比（C2） |
| 审计归因 | OAuth 授权时审计 | ticket_id 全链贯通率 1.0（C1 audit） |
| 身份冲突 | 无锚定基线 | 200 DID 零冲突、克隆识别（C0） |
| 层必要性 | 完整方案 | 消融：去用户签名层/去 ST_data → 正常调用 100% 失败（C3 ablation） |

## 六、实验结果摘要

- **C0**：4 类环境标识 200 个设备 DID 零冲突；克隆同标识 → 同 DID（KDC
  绑定表去重识别）。
- **C1**：三场景（A 数据查询 / B 协作链 / C 网关跨域）全部通过；审计链
  ticket_id 贯通率 1.0，缺失率 0.6%（拒绝类无票，如实标注）。
- **C2**：并发 100/500 本文 vs OAuth：时延分位、QPS、报文字节（数值待
  联调回填，见已知限制）。
- **C3**：500 条指令流（60/16/16/8）本文正常 100% 通过、篡改/越权/重放
  100% 拦截；六类攻击矩阵本文全 1.00、OAuth/noauth 全 0.00（OAuth
  混淆缺陷如实复现）；消融 full 正常 0% 拦+攻击 100% 拦，去任一必要层
  正常调用 100% 失败。
- **C4**：7 维 × 4 方案安全矩阵（判定依据见 CSV basis 列）。
- 单测 `pytest tests/` 21/21 通过。

## 七、已知限制（论文引用时标注）

- MCP 为 JSON-RPC 2.0 `tools/call` 轻量模拟（无真实 MCP SDK），头部注入
  + 服务端中间件按 §5.2 B/C 方案实现。
- OAuth 基线为自实现（同环境对照）；`cache_auth_state=True` 复刻"一次性
  授权后授权态缓存复用"缺陷（C3-6 打穿）。
- 环境标识为程序模拟生成（标注"环境标识模拟"）。
- 并发测量为多线程回环（GIL 受限），C2 数值为趋势性对比；并发下 sign 与
  报文 ts 已统一（避免跨秒链验失败）。
- ST 单次使用 → 每请求必须重新签发双 ST（~150ms×2，C1/C3 已按此构造）。
- SM9 签名 h 补零修复（同方向二），1500 次自验签 0 失败。

## 八、复现

```bash
python run_all.py             # C0→C1→C3→C2→C4 全量
python run_all.py --quick     # 冒烟
python run_all.py --conc1000  # C2 追加 1000 并发档（D3 预留参数）
```

调试口：全部实验脚本支持 `--debug`（逐条明细）；`--quick` 冒烟缩减
（C0 10/类、C1 6/3、C2 并发[10,50]+50 请求、C3 50 指令）。环境：
Python 3.14 + venv（gmalg 1.1.2、numpy）。

## 目录

```
core/            # 16 模块（复用方向二 9 个 + MCP/双ST/签名链/基线 7 个）
experiments/     # C0–C4 + run_all
results/         # 全部 CSV（论文数据源）
tests/           # 21 项单元测试
docs/API.md      # 模块接口文档
```

## 安全属性与实现对应

- 抗重放：ST 单次使用缓存（ticket_id）+ 请求 nonce（req_id）
- 抗伪造：SM9 双签名链（设备先、用户后）+ 双 ST 验签
- 越权防护：claims_checker tool+action 级匹配（第④步）
- DID 冒用：签名者 DID == 票据 Principal（第③步）
- 调用者混淆：每请求双签名链认证器
- 审计归因：ticket_id 全链（KDC 签发→网关→MCP 调用→审计记录）
- 国产合规：SM9/SM3/SM4 全链（gmalg），哈希禁 SHA-256

## 验收自查

- `pytest tests/`：21/21 通过。
- 从空 `results/` 执行 `run_all.py` 可完整复现全部 CSV。
- CSV 规约：英文列名、≥4 位有效数字、含 `#meta` 元数据行。