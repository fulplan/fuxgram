"""Beaconing timer with jitter and exponential back-off on failure."""
from __future__ import annotations
import random
import time


class Beacon:
    """Manage sleep intervals between C2 check-ins.

    Normal cadence: sleep * (1 ± jitter%).
    After 3 consecutive failures: exponential back-off, capped at max_sleep.
    """

    def __init__(
        self,
        sleep: int = 10,
        jitter: int = 20,
        max_sleep: int = 3600,
    ) -> None:
        self.sleep     = sleep
        self.jitter    = jitter      # percent
        self.max_sleep = max_sleep
        self._failures = 0
        self._last_ok  = time.time()

    # ── public API ────────────────────────────────────────────────────────

    def next_sleep(self) -> float:
        """Return seconds to sleep before the next beacon."""
        base = self._backoff_base()
        if self.jitter > 0:
            delta = base * (self.jitter / 100.0)
            base  = base + random.uniform(-delta, delta)
        return max(1.0, base)

    def mark_success(self) -> None:
        self._failures = 0
        self._last_ok  = time.time()

    def mark_failure(self) -> None:
        self._failures += 1

    @property
    def consecutive_failures(self) -> int:
        return self._failures

    @property
    def seconds_since_ok(self) -> float:
        return time.time() - self._last_ok

    # ── internals ─────────────────────────────────────────────────────────

    def _backoff_base(self) -> float:
        if self._failures < 3:
            return float(self.sleep)
        exp = min(self._failures - 2, 8)     # cap exponent
        back = self.sleep * (2 ** exp)
        return min(float(back), float(self.max_sleep))
