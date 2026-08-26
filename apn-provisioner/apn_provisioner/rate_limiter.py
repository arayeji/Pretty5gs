"""Rate limiting, de-duplication and circuit breaker (spec 5.1, 5.2).

An attach storm must never become an SMS storm. Layers, checked in order:
  1. in-flight / recent de-dup   -> never queue duplicates for one IMSI
  2. circuit breaker             -> if global sends exceed N/min, stop and log
                                    loudly; resume only once the rate falls
  3. global sends-per-second cap
  4. per-subscriber sends-per-day cap
"""
from __future__ import annotations

from collections import defaultdict, deque


class RateLimiter:
    def __init__(self, *, dedup_window_sec: float, global_max_per_sec: float,
                 max_sends_per_sub_per_day: int, breaker_per_min: int,
                 breaker_resume_per_min: int):
        self.dedup_window = dedup_window_sec
        self.global_max_per_sec = global_max_per_sec
        self.max_sub_day = max_sends_per_sub_per_day
        self.breaker_per_min = breaker_per_min
        self.breaker_resume = breaker_resume_per_min

        self._inflight: dict[str, float] = {}
        self._last_send: dict[str, float] = {}
        self._sub_day: dict[str, deque] = defaultdict(deque)
        self._global_min: deque = deque()
        self._global_sec: deque = deque()
        self.breaker_open = False

    def _global_count(self, now: float) -> int:
        while self._global_min and now - self._global_min[0] > 60.0:
            self._global_min.popleft()
        return len(self._global_min)

    def check(self, imsi: str, now: float) -> tuple[bool, str]:
        # de-dup: in-flight or sent within the window
        inflight_ts = self._inflight.get(imsi)
        if inflight_ts is not None and now - inflight_ts < self.dedup_window:
            return False, "in_flight"
        last = self._last_send.get(imsi)
        if last is not None and now - last < self.dedup_window:
            return False, "duplicate_recent"

        # circuit breaker
        gmin = self._global_count(now)
        if self.breaker_open:
            if gmin <= self.breaker_resume:
                self.breaker_open = False
            else:
                return False, "circuit_open"
        elif gmin >= self.breaker_per_min:
            self.breaker_open = True
            return False, "circuit_open"

        # global per second
        while self._global_sec and now - self._global_sec[0] > 1.0:
            self._global_sec.popleft()
        if len(self._global_sec) >= self.global_max_per_sec:
            return False, "rate_global_sec"

        # per subscriber per day
        dq = self._sub_day[imsi]
        while dq and now - dq[0] > 86400.0:
            dq.popleft()
        if len(dq) >= self.max_sub_day:
            return False, "rate_sub_day"

        return True, "ok"

    def start_send(self, imsi: str, now: float) -> None:
        self._inflight[imsi] = now

    def finish_send(self, imsi: str, now: float, success: bool) -> None:
        self._inflight.pop(imsi, None)
        if success:
            self._last_send[imsi] = now
            self._sub_day[imsi].append(now)
            self._global_min.append(now)
            self._global_sec.append(now)
