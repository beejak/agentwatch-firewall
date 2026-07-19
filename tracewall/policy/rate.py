"""
Sliding-window rate budgets for policy ``rate_exceeds``.

Keyed counters live on the PolicyEngine (or a shared tracker). Thread-safe.
"""
from __future__ import annotations

import time
from threading import Lock


class RateBudget:
    """Return True when a key would exceed ``max_n`` hits inside ``window_s``."""

    def __init__(self) -> None:
        self._hits: dict[str, list[float]] = {}
        self._lock = Lock()

    def exceeds(self, key: str, window_s: float, max_n: int, *, now: float | None = None) -> bool:
        """
        Count this attempt. If the window already has ``max_n`` hits, return True
        (over limit — do not append). Otherwise append and return False.
        """
        if max_n <= 0:
            return True
        window_s = float(window_s)
        now = time.time() if now is None else float(now)
        with self._lock:
            hits = self._hits.setdefault(key, [])
            cutoff = now - window_s
            hits[:] = [t for t in hits if t >= cutoff]
            if len(hits) >= int(max_n):
                return True
            hits.append(now)
            return False

    def reset(self, key: str | None = None) -> None:
        with self._lock:
            if key is None:
                self._hits.clear()
            else:
                self._hits.pop(key, None)
