"""Thread-safe token buckets for rate limiting.

Two independent limits are used:

* per-client-IP, on the investigation endpoint, so one caller cannot monopolise
  the tool;
* per-upstream-host, shared across every investigation, so the process as a whole
  stays within the free public endpoints' own rate limits.

Buckets are keyed by a value derived from the request (client address, upstream
host). The key is never logged. The bucket map is bounded by evicting the least
recently used key, so an attacker cannot exhaust memory by cycling keys.

The standard library only; no dependency is added.
"""

from __future__ import annotations

import threading
import time
from collections import OrderedDict
from dataclasses import dataclass


@dataclass
class _Bucket:
    tokens: float
    updated_at: float


class TokenBucketLimiter:
    """A bounded collection of per-key token buckets.

    ``rate_per_minute`` is the sustained refill rate; ``burst`` is the bucket
    capacity. A key is allowed while it has at least one token; every allowed
    call consumes one. Refill is continuous, so a caller cannot bank an unbounded
    allowance by waiting.
    """

    def __init__(
        self,
        rate_per_minute: float,
        burst: int,
        *,
        max_keys: int = 4096,
        clock: "callable[[], float] | None" = None,
    ) -> None:
        if rate_per_minute <= 0:
            raise ValueError("rate_per_minute must be positive")
        if burst <= 0:
            raise ValueError("burst must be positive")
        self.rate_per_second = rate_per_minute / 60.0
        self.burst = float(burst)
        self.max_keys = max_keys
        self._clock = clock if clock is not None else time.monotonic
        self._lock = threading.Lock()
        self._buckets: "OrderedDict[str, _Bucket]" = OrderedDict()

    def allow(self, key: str) -> bool:
        """Consume one token for ``key``; return whether the call is allowed."""
        now = self._clock()
        with self._lock:
            bucket = self._buckets.get(key)
            if bucket is None:
                bucket = _Bucket(tokens=self.burst, updated_at=now)
                self._buckets[key] = bucket
                if len(self._buckets) > self.max_keys:
                    # Evict the least recently used key. A caller cycling keys
                    # cannot grow the map without bound.
                    self._buckets.popitem(last=False)
            else:
                elapsed = max(0.0, now - bucket.updated_at)
                bucket.tokens = min(self.burst, bucket.tokens + elapsed * self.rate_per_second)
                bucket.updated_at = now
                self._buckets.move_to_end(key)

            if bucket.tokens < 1.0:
                return False
            bucket.tokens -= 1.0
            return True

    def retry_after_seconds(self, key: str) -> int:
        """Whole seconds until ``key`` would next be allowed (>= 1)."""
        now = self._clock()
        with self._lock:
            bucket = self._buckets.get(key)
            if bucket is None:
                return 0
            elapsed = max(0.0, now - bucket.updated_at)
            tokens = min(self.burst, bucket.tokens + elapsed * self.rate_per_second)
            if tokens >= 1.0:
                return 0
            deficit = 1.0 - tokens
            return max(1, int(deficit / self.rate_per_second) + 1)
