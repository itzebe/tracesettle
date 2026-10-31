"""Bounded TTL cache for read-only upstream responses.

Only responses that are (a) read-only, (b) identical for identical request
parameters, and (c) *successful* are cacheable. Failures, timeouts, and
incomplete results are never stored, so a transient upstream error can never be
replayed as if it were fresh evidence.

Two properties matter for correctness:

* **Determinism is preserved.** A cached entry is byte-for-byte the value the
  adapter would have parsed from a live response, so reconciliation produces the
  same result whether the data came from the network or the cache.
* **Single-flight.** Concurrent callers asking for the same key wait for one
  in-flight fetch instead of each issuing their own, which prevents a burst of
  identical requests from amplifying load on a free public endpoint.

The standard library only; no dependency is added.
"""

from __future__ import annotations

import threading
import time
from collections import OrderedDict
from dataclasses import dataclass
from typing import Any, Callable


@dataclass
class _Entry:
    value: Any
    expires_at: float


class TtlCache:
    """A bounded, thread-safe TTL cache with optional single-flight."""

    def __init__(
        self,
        ttl_seconds: float,
        *,
        max_entries: int = 512,
        clock: "Callable[[], float] | None" = None,
    ) -> None:
        self.ttl_seconds = ttl_seconds
        self.max_entries = max_entries
        self._clock = clock if clock is not None else time.monotonic
        self._lock = threading.Lock()
        self._entries: "OrderedDict[str, _Entry]" = OrderedDict()
        # One in-flight marker per key; used only to coalesce concurrent misses.
        self._inflight: dict[str, threading.Event] = {}

    def get(self, key: str) -> Any | None:
        """Return the cached value, or ``None`` on a miss or expiry."""
        now = self._clock()
        with self._lock:
            entry = self._entries.get(key)
            if entry is None:
                return None
            if entry.expires_at <= now:
                self._entries.pop(key, None)
                return None
            self._entries.move_to_end(key)
            return entry.value

    def put(self, key: str, value: Any) -> None:
        now = self._clock()
        with self._lock:
            self._entries[key] = _Entry(value=value, expires_at=now + self.ttl_seconds)
            self._entries.move_to_end(key)
            while len(self._entries) > self.max_entries:
                self._entries.popitem(last=False)

    def get_or_load(
        self,
        key: str,
        loader: Callable[[], Any],
        *,
        cache_if: "Callable[[Any], bool] | None" = None,
    ) -> Any:
        """Return a cached value, or compute it once and cache a *successful* result.

        ``loader`` produces the value. It is stored only when ``cache_if`` returns
        true (default: any non-``None`` value). Concurrent callers for the same key
        share a single load, so a burst of identical requests is coalesced into one.
        """
        if cache_if is None:
            def cache_if(value: Any) -> bool:  # noqa: E731 - trivial default
                return value is not None

        cached = self.get(key)
        if cached is not None:
            return cached

        # Coalesce concurrent misses for the same key onto one loader call.
        with self._lock:
            event = self._inflight.get(key)
            if event is None:
                event = threading.Event()
                self._inflight[key] = event
                leader = True
            else:
                leader = False

        if not leader:
            event.wait(timeout=self.ttl_seconds)
            cached = self.get(key)
            if cached is not None:
                return cached
            # The leader did not cache (a failure); fall through and load ourselves.
            return self._load_and_store(key, loader, cache_if)

        try:
            return self._load_and_store(key, loader, cache_if)
        finally:
            with self._lock:
                self._inflight.pop(key, None)
            event.set()

    def _load_and_store(
        self, key: str, loader: Callable[[], Any], cache_if: Callable[[Any], bool]
    ) -> Any:
        value = loader()
        if cache_if(value):
            self.put(key, value)
        return value

    def clear(self) -> None:
        with self._lock:
            self._entries.clear()

    def __len__(self) -> int:
        with self._lock:
            return len(self._entries)
