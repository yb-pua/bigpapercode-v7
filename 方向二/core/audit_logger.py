"""审计日志：ts, ticket_id, action, result, principal（追加式 JSONL）。"""

import json
import threading
import time
from pathlib import Path
from typing import Optional


class AuditLogger:
    def __init__(self, path: str):
        self.path = Path(path)
        self.path.parent.mkdir(parents=True, exist_ok=True)
        self._lock = threading.Lock()

    def log(self, action: str, result: str, principal: str,
            ticket_id: Optional[str] = None, ts: Optional[float] = None,
            extra: Optional[dict] = None) -> None:
        record = {
            "ts": ts if ts is not None else time.time(),
            "ticket_id": ticket_id,
            "action": action,
            "result": result,
            "principal": principal,
        }
        if extra:
            record.update(extra)
        with self._lock:
            with open(self.path, "a", encoding="utf-8") as f:
                f.write(json.dumps(record) + "\n")

    def entries(self) -> list:
        if not self.path.exists():
            return []
        rows = []
        with self._lock:
            for line in self.path.read_text(encoding="utf-8").splitlines():
                if line.strip():
                    rows.append(json.loads(line))
        return rows

    def clear(self) -> None:
        with self._lock:
            self.path.write_text("", encoding="utf-8")