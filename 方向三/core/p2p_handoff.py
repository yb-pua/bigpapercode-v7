"""方向二→方向三的会话凭证模拟交接器。

本模块只用于小论文实验：按方向二 Session Credential 的字段和
信任链构造一份可验证的上游凭证，不重新执行 NAT 打洞、P2P 准入
或真实网络通信。论文和 manifest 中必须标注 simulated。
"""

from typing import Optional

from .authorization import (WARRANT_SCOPE_SESSION_CREDENTIAL,
                            issue_session_credential)
from .common import rand_bytes, sm3
from .did import make_device_did


def issue_simulated_p2p_session(kdc, agent_did: str, user_did: str,
                                netperm: Optional[dict] = None,
                                ttl: float = 1800.0,
                                label: str = "mcp-handoff") -> dict:
    """构造可由方向三 KDC 验证的方向二会话凭证（模拟交接）。"""
    relay_did = make_device_did("relay-handoff", "realm")
    kdc.sm9.derive_sk(relay_did)
    now = kdc.st.now()
    warrant = kdc.delegate_proxy(
        relay_did,
        scope=[WARRANT_SCOPE_SESSION_CREDENTIAL],
        exp=now + ttl,
    )
    parent_ticket_id = rand_bytes(
        16, f"{label}:{agent_did}:parent_ticket").hex()
    auth_id = rand_bytes(16, f"{label}:{agent_did}:auth").hex()
    parent_auth_ticket_id = rand_bytes(
        16, f"{label}:{user_did}:parent_auth").hex()
    vaddr_tail = int.from_bytes(sm3(agent_did.encode())[:2], "big")
    vaddr = f"10.200.{vaddr_tail // 256}.{vaddr_tail % 256}"
    return issue_session_credential(
        kdc.sm9, relay_did, warrant,
        device_did=agent_did,
        user_did=user_did,
        auth_id=auth_id,
        parent_auth_ticket_id=parent_auth_ticket_id,
        parent_ticket_id=parent_ticket_id,
        netperm=netperm or {"services": ["mcp-gateway"]},
        sname="relay@realm",
        vaddr=vaddr,
        st_fingerprint_hex=sm3(parent_ticket_id.encode()).hex(),
        exp=now + ttl,
        now_fn=kdc.st.now,
    )
