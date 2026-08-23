"""
C4 安全属性对比矩阵：7 维 × 4 方案（标准 Kerberos / 国密 Kerberos /
OAuth 2.1 直连 / 本文 SM9+双DID+签名链）。
输出：expC4_security_matrix.csv（dimension, scheme, value, basis）

value 语义：1=支持/具备，0=不支持；basis 为判定依据（代码逻辑或
本方向实验证据，全部可复现）。
调试口：--debug 打印矩阵；--quick 同全量（矩阵为静态判定）。
"""

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent.parent))

from core.common import SEED, csv_meta, write_csv
from 实验.run_support import start_run, write_manifest

RESULTS = Path(__file__).resolve().parent / "结果"

DIMENSIONS = ["anti_replay", "anti_forgery", "perm_granularity",
              "caller_binding", "audit_attribution", "revocation",
              "national_crypto"]
SCHEMES = ["kerberos_std", "kerberos_sm", "oauth21", "ours"]


def build_matrix() -> list:
    """7 维 × 4 方案判定。basis 注明代码依据或实验证据 CSV。"""
    M = []
    # 1 抗重放
    M += [
        ("anti_replay", "kerberos_std", 1, "认证器时间戳+replay 窗口（RFC 4120）"),
        ("anti_replay", "kerberos_sm", 1, "同标准，时间戳窗口 30min（st_ticket.MAX_SKEW）"),
        ("anti_replay", "oauth21", 0, "token 复用无 nonce/单次约束（expC3_attack_matrix: replay 0.00）"),
        ("anti_replay", "ours", 1, "ST 单次使用缓存+请求 nonce（expC3_attack_matrix: replay 1.00）"),
    ]
    # 2 抗伪造
    M += [
        ("anti_forgery", "kerberos_std", 1, "KDC 对称密钥签发的票据（Kerberos 协议）"),
        ("anti_forgery", "kerberos_sm", 1, "SM9 签名链（sm9_engine.sign）"),
        ("anti_forgery", "oauth21", 1, "192bit 随机 token 难伪造，但无调用级绑定"),
        ("anti_forgery", "ours", 1, "SM9 双签名链+双 ST（expC3_attack_matrix: forged_st/did_spoof 1.00）"),
    ]
    # 3 权限粒度（tool 级）
    M += [
        ("perm_granularity", "kerberos_std", 0, "服务级授权（SName 粒度）"),
        ("perm_granularity", "kerberos_sm", 0, "服务级授权"),
        ("perm_granularity", "oauth21", 0, "scope 为 server 级（expC3_attack_matrix: priv_esc 0.00）"),
        ("perm_granularity", "ours", 1, "claims={tools,actions} tool+action 级（claims_checker.match）"),
    ]
    # 4 调用级绑定（防调用者混淆）
    M += [
        ("caller_binding", "kerberos_std", 0, "仅认证器绑定客户端地址"),
        ("caller_binding", "kerberos_sm", 0, "仅认证器绑定客户端地址"),
        ("caller_binding", "oauth21", 0, "本实验 bearer-token/授权态缓存基线与调用者不绑定（C3）"),
        ("caller_binding", "ours", 1, "每请求双签名链认证器（expC3_attack_matrix: confusion 1.00）"),
    ]
    # 5 审计归因
    M += [
        ("audit_attribution", "kerberos_std", 0, "KDC 有授权日志，调用级无关联键"),
        ("audit_attribution", "kerberos_sm", 0, "KDC 有授权日志，调用级无关联键"),
        ("audit_attribution", "oauth21", 0, "授权时审计，调用不可归因"),
        ("audit_attribution", "ours", 1, "ticket_id 全链贯通（expC1_audit: chain_complete_rate=1.0）"),
    ]
    # 6 撤销/生命周期
    M += [
        ("revocation", "kerberos_std", 1, "KDC 可吊销/短时票据"),
        ("revocation", "kerberos_sm", 1, "KDC 可吊销/短时票据"),
        ("revocation", "oauth21", 1, "token 撤销端点（oauth_baseline.revoke）"),
        ("revocation", "ours", 1, "ST 30min 短周期+单次使用；本实验未实现在线 CRL"),
    ]
    # 7 国产合规
    M += [
        ("national_crypto", "kerberos_std", 0, "默认 AES/非国密"),
        ("national_crypto", "kerberos_sm", 1, "SM9/SM3/SM4 全链"),
        ("national_crypto", "oauth21", 0, "TLS 默认套件非国密"),
        ("national_crypto", "ours", 1, "MCP 认证层 SM9/SM3；数据通道继承方向二 SM4"),
    ]
    rows = []
    for dim, scheme, value, basis in M:
        rows.append({"dimension": dim, "scheme": scheme, "value": value,
                     "basis": basis})
    return rows


def main():
    debug = "--debug" in sys.argv
    quick = "--quick" in sys.argv
    out_dir, run_state = start_run(RESULTS)
    rows = build_matrix()
    write_csv(out_dir / "expC4_security_matrix.csv", rows)
    csv_meta(out_dir / "expC4_security_matrix.csv", {
        "seed": SEED, "mode": "quick" if quick else "formal",
        "dimensions": 7, "schemes": 4})
    if debug:
        for r in rows:
            print(f"  {r['dimension']:<20} {r['scheme']:<14} "
                  f"value={r['value']}  {r['basis']}")
    else:
        print(f"  expC4_security_matrix.csv written: "
              f"{len(rows)} rows ({len(DIMENSIONS)} dims x "
              f"{len(SCHEMES)} schemes)")
    write_manifest(
        out_dir, run_state, mode="quick" if quick else "formal", seed=SEED,
        parameters={"dimensions": 7, "schemes": 4},
        simulated_components=["Evidence-derived static security matrix",
                              "OAuth bearer-token baseline"],
        measurement_mode="evidence_matrix",
    )


if __name__ == "__main__":
    main()
