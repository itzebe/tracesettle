"""Unit tests for the bounded TTL cache and its single-flight behaviour."""

from __future__ import annotations

import threading
import time

from tracesettle.cache import TtlCache


def test_cache_hit_within_ttl():
    clock = [0.0]
    cache = TtlCache(ttl_seconds=30, clock=lambda: clock[0])
    loads: list[int] = []
    value = cache.get_or_load("k", lambda: (loads.append(1), "v1")[1])
    again = cache.get_or_load("k", lambda: (loads.append(1), "v2")[1])
    assert value == "v1" and again == "v1"
    assert len(loads) == 1


def test_cache_expires_after_ttl():
    clock = [0.0]
    cache = TtlCache(ttl_seconds=30, clock=lambda: clock[0])
    cache.put("k", "v1")
    assert cache.get("k") == "v1"
    clock[0] = 30.0001
    assert cache.get("k") is None


def test_failed_result_is_not_cached():
    """``cache_if`` rejects non-successful results, so an error is never replayed."""
    cache = TtlCache(ttl_seconds=30, clock=lambda: 0.0)
    loads: list[int] = []

    def loader():
        loads.append(1)
        return None  # represents a failure

    cache.get_or_load("k", loader, cache_if=lambda v: v is not None)
    cache.get_or_load("k", loader, cache_if=lambda v: v is not None)
    assert len(loads) == 2
    assert cache.get("k") is None


def test_cache_is_bounded_by_max_entries():
    cache = TtlCache(ttl_seconds=30, max_entries=3, clock=lambda: 0.0)
    for i in range(10):
        cache.put(f"k{i}", i)
    assert len(cache) == 3
    # The most recent keys survived; the oldest were evicted.
    assert cache.get("k9") == 9
    assert cache.get("k0") is None


def test_cache_isolation_by_key():
    cache = TtlCache(ttl_seconds=30, clock=lambda: 0.0)
    cache.put("a", "va")
    cache.put("b", "vb")
    assert cache.get("a") == "va"
    assert cache.get("b") == "vb"
    assert cache.get("c") is None


def test_single_flight_coalesces_concurrent_loads():
    """N concurrent misses for one key trigger exactly one loader call."""
    cache = TtlCache(ttl_seconds=30, clock=lambda: 0.0)
    calls: list[int] = []
    start = threading.Event()

    def loader():
        calls.append(1)
        start.wait(timeout=2)  # hold the leader until all waiters are parked
        return "value"

    results: list[str] = []
    threads = [
        threading.Thread(target=lambda: results.append(cache.get_or_load("k", loader)))
        for _ in range(8)
    ]
    for t in threads:
        t.start()
    time.sleep(0.2)  # let waiters block on the in-flight event
    start.set()
    for t in threads:
        t.join(timeout=5)

    assert calls == [1]
    assert results == ["value"] * 8


def test_single_flight_failure_lets_a_waiter_retry():
    """When the leader fails to cache, a waiter performs its own load."""
    cache = TtlCache(ttl_seconds=1, clock=lambda: 0.0)
    calls: list[str] = []
    release = threading.Event()

    def leader_loader():
        calls.append("leader")
        release.wait(timeout=2)
        return None  # failure: nothing cached

    def waiter_loader():
        calls.append("waiter")
        return "value"

    results: list[str] = []

    def leader():
        results.append(cache.get_or_load("k", leader_loader, cache_if=lambda v: v is not None))

    def waiter():
        results.append(cache.get_or_load("k", waiter_loader, cache_if=lambda v: v is not None))

    lt = threading.Thread(target=leader)
    wt = threading.Thread(target=waiter)
    lt.start()
    time.sleep(0.1)
    wt.start()
    time.sleep(0.2)
    release.set()
    lt.join(timeout=5)
    wt.join(timeout=5)

    assert calls[0] == "leader"
    assert "waiter" in calls
    assert "value" in results


def test_clear_empties_the_cache():
    cache = TtlCache(ttl_seconds=30, clock=lambda: 0.0)
    cache.put("k", "v")
    cache.clear()
    assert cache.get("k") is None
    assert len(cache) == 0
