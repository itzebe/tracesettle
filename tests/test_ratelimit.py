"""Unit tests for the token-bucket rate limiter."""

from __future__ import annotations

import pytest

from tracesettle.ratelimit import TokenBucketLimiter


def test_burst_allows_up_to_capacity_then_denies():
    clock = [0.0]
    limiter = TokenBucketLimiter(rate_per_minute=60, burst=3, clock=lambda: clock[0])
    assert [limiter.allow("ip") for _ in range(5)] == [True, True, True, False, False]


def test_tokens_refill_over_time():
    clock = [0.0]
    limiter = TokenBucketLimiter(rate_per_minute=60, burst=2, clock=lambda: clock[0])
    assert limiter.allow("ip") and limiter.allow("ip")
    assert not limiter.allow("ip")
    clock[0] = 1.0  # one second at 60/min refills one token
    assert limiter.allow("ip")
    assert not limiter.allow("ip")


def test_buckets_are_isolated_per_key():
    limiter = TokenBucketLimiter(rate_per_minute=60, burst=1, clock=lambda: 0.0)
    assert limiter.allow("a")
    assert not limiter.allow("a")
    assert limiter.allow("b")  # a different key has its own bucket


def test_key_map_is_bounded():
    limiter = TokenBucketLimiter(rate_per_minute=60, burst=1, max_keys=4, clock=lambda: 0.0)
    for i in range(50):
        limiter.allow(f"key-{i}")
    assert len(limiter._buckets) <= 4


def test_retry_after_is_reported_when_limited():
    clock = [0.0]
    limiter = TokenBucketLimiter(rate_per_minute=60, burst=1, clock=lambda: clock[0])
    limiter.allow("ip")
    assert limiter.retry_after_seconds("ip") >= 1
    clock[0] = 5.0
    assert limiter.retry_after_seconds("ip") == 0


def test_unknown_key_has_no_retry_delay():
    limiter = TokenBucketLimiter(rate_per_minute=60, burst=1, clock=lambda: 0.0)
    assert limiter.retry_after_seconds("never-seen") == 0


@pytest.mark.parametrize("rate,burst", [(0, 1), (-1, 1), (60, 0), (60, -3)])
def test_invalid_configuration_is_rejected(rate, burst):
    with pytest.raises(ValueError):
        TokenBucketLimiter(rate_per_minute=rate, burst=burst)
