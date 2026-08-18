"""
安全熔断：连续失败 3 次 → is_blocked → 删除会话票据 → L1 恢复
（Rep 重认证，bio_key/DID 不变）；L1 失败才 L2 重注册（重新 Gen +
显式更新登记）。

与专利技术细节一致：
    record_failure()：失败计数 +1，达到阈值即熔断
    record_success()：清零
    is_blocked()：当前熔断状态
    recover_l1()：尝试重认证（Rep 复现 bio_key 不变），成功则解除熔断
    recover_l2()：重新 Gen 生成新 σ + 显式更新登记记录
"""

from typing import Callable, Dict, List, Optional


class CircuitBreaker:
    FAIL_THRESHOLD = 3

    def __init__(self, principal: str,
                 threshold: int = FAIL_THRESHOLD,
                 ticket_cleanup: Optional[Callable[[str], None]] = None,
                 l1_attempt: Optional[Callable[[], bool]] = None,
                 l2_attempt: Optional[Callable[[], bool]] = None):
        """参数：
            ticket_cleanup(principal)：熔断时删除该主体全部会话票据的回调
            l1_attempt()：L1 恢复尝试（Rep 重认证），返回是否成功
            l2_attempt()：L2 恢复尝试（重新 Gen + 显式更新登记），返回是否成功
        """
        self.principal = principal
        self.threshold = threshold
        self._consecutive_failures = 0
        self._blocked = False
        self._blocked_at = None
        self._ticket_cleanup = ticket_cleanup
        self._l1_attempt = l1_attempt
        self._l2_attempt = l2_attempt
        self._events: List[Dict] = []

    # ------------------------------------------------------------------
    def record_failure(self, reason: str = "") -> bool:
        """记录一次失败；达到阈值返回 True（本次触发熔断）。"""
        self._consecutive_failures += 1
        self._events.append({"action": "failure", "count": self._consecutive_failures,
                             "reason": reason})
        if self._consecutive_failures >= self.threshold and not self._blocked:
            self._blocked = True
            self._blocked_at = self._consecutive_failures
            if self._ticket_cleanup is not None:
                self._ticket_cleanup(self.principal)
            self._events.append({"action": "blocked", "count": self._consecutive_failures})
            return True
        return False

    def record_success(self) -> None:
        self._consecutive_failures = 0
        self._events.append({"action": "success", "count": 0})

    def is_blocked(self) -> bool:
        return self._blocked

    def failure_count(self) -> int:
        return self._consecutive_failures

    # ------------------------------------------------------------------
    def recover_l1(self) -> bool:
        """L1 恢复：Rep 重认证（bio_key/DID 不变）。"""
        if self._l1_attempt is None:
            return False
        ok = bool(self._l1_attempt())
        self._events.append({"action": "l1_recover", "result": "success" if ok else "failed"})
        if ok:
            self._blocked = False
            self._consecutive_failures = 0
        return ok

    def recover_l2(self) -> bool:
        """L2 恢复：重新 Gen + 显式更新登记。"""
        if self._l2_attempt is None:
            return False
        ok = bool(self._l2_attempt())
        self._events.append({"action": "l2_recover", "result": "success" if ok else "failed"})
        if ok:
            self._blocked = False
            self._consecutive_failures = 0
        return ok

    def events(self) -> List[Dict]:
        return list(self._events)

    def reset(self) -> None:
        self._consecutive_failures = 0
        self._blocked = False
        self._blocked_at = None
        self._events = []