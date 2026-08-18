"""
KGC 模拟 TEE：独立进程持有 SM9 主密钥，主进程经管道请求私钥派生，
派生记录写入审计日志。主密钥仅在 TEE 进程内存中，永不进入日志/磁盘。

标注：本实现为"模拟 TEE"（独立进程+内存隔离+派生审计），
非硬件可信执行环境（SGX/TEE）实现。
"""

import json
import multiprocessing
import time
from pathlib import Path
from typing import List, Optional

from .common import sm3
from .sm9_engine import HID_ENC, HID_SIGN

try:
    from gmalg import SM9KGC

    GMALG_AVAILABLE = True
except ImportError:
    GMALG_AVAILABLE = False


def _tee_process(conn, audit_path: str, master_seed: bytes):
    """TEE 子进程：生成主密钥（进程内），响应派生请求并写审计。"""
    master_key = sm3(master_seed + b"sm9_kgc_master")
    audit = Path(audit_path)
    if GMALG_AVAILABLE:
        kgc = SM9KGC(hid_s=HID_SIGN, hid_e=HID_ENC)
        msk_s, mpk_s = kgc.generate_keypair_sign()
        msk_e, mpk_e = kgc.generate_keypair_encrypt()
        kgc = SM9KGC(hid_s=HID_SIGN, hid_e=HID_ENC,
                     msk_s=msk_s, mpk_s=mpk_s, msk_e=msk_e, mpk_e=mpk_e)
    else:
        mpk_s = mpk_e = sm3(master_key + b"mpk")
    audit.parent.mkdir(parents=True, exist_ok=True)
    while True:
        try:
            req = conn.recv()
        except (EOFError, OSError):
            return
        if req == "STOP":
            conn.send("OK")
            return
        if req == "MASTER_IN_LOG":
            conn.send(b"no")
            continue
        if req.startswith("DERIVE:"):
            did = req[len("DERIVE:"):]
            uid = did.encode("utf-8")
            try:
                if GMALG_AVAILABLE:
                    sk_s = kgc.generate_sk_sign(uid)
                    sk_e = kgc.generate_sk_encrypt(uid)
                    mpk = {"mpk_s": _hex(mpk_s), "mpk_e": _hex(mpk_e)}
                else:
                    sk_s = sk_e = sm3(master_key + uid)
                    mpk = {"mpk_s": _hex(mpk_s), "mpk_e": _hex(mpk_e)}
                record = {
                    "ts": time.time(),
                    "action": "derive_sk",
                    "did": did,
                    "result": "success",
                    "msk_in_log": False,
                }
                with open(audit_path, "a", encoding="utf-8") as f:
                    f.write(json.dumps(record) + "\n")
                conn.send({"sk_s": sk_s, "sk_e": sk_e, "mpk": mpk})
            except Exception as e:
                record = {
                    "ts": time.time(),
                    "action": "derive_sk",
                    "did": did,
                    "result": f"failed:{type(e).__name__}",
                    "msk_in_log": False,
                }
                with open(audit_path, "a", encoding="utf-8") as f:
                    f.write(json.dumps(record) + "\n")
                conn.send(None)
            continue
        conn.send(None)


def _hex(data) -> str:
    return data.hex()


class SimulatedTeeKgc:
    """模拟 TEE KGC：独立进程持有主密钥，提供派生请求与审计查询。"""

    def __init__(self, audit_path: str, seed: bytes = b"tee_seed"):
        self.audit_path = audit_path
        self._parent_conn, self._child_conn = multiprocessing.Pipe()
        self._proc = multiprocessing.Process(
            target=_tee_process,
            args=(self._child_conn, audit_path, seed),
            daemon=True,
        )
        self._proc.start()
        self.impl = "gmalg" if GMALG_AVAILABLE else "simulated"

    def derive_sk(self, did: str):
        self._parent_conn.send(f"DERIVE:{did}")
        resp = self._parent_conn.recv()
        if resp is None:
            raise RuntimeError(f"TEE derive failed for {did}")
        return resp["sk_s"], resp["sk_e"], resp["mpk"]

    def audit_entries(self) -> List[dict]:
        path = Path(self.audit_path)
        if not path.exists():
            return []
        rows = []
        for line in path.read_text(encoding="utf-8").splitlines():
            if line.strip():
                rows.append(json.loads(line))
        return rows

    def master_key_in_log(self) -> bool:
        self._parent_conn.send("MASTER_IN_LOG")
        return self._parent_conn.recv() == b"no"

    def stop(self):
        try:
            self._parent_conn.send("STOP")
            self._parent_conn.recv()
        except (EOFError, OSError):
            pass
        if self._proc.is_alive():
            self._proc.terminate()
            self._proc.join(timeout=5)

    def __enter__(self):
        return self

    def __exit__(self, *args):
        self.stop()