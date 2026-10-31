"""HttpClient caching and per-host rate-limit tests (no real network)."""

from __future__ import annotations

from tracesettle.cache import TtlCache
from tracesettle.httpclient import HttpClient
from tracesettle.model import SourceStatus
from tracesettle.ratelimit import TokenBucketLimiter

from conftest import FakeOpener


def _client(opener: FakeOpener, **kwargs) -> HttpClient:
    return HttpClient(
        opener=opener,
        max_attempts=1,
        timeout=1.0,
        backoff_base=0.0,
        sleeper=lambda _: None,
        **kwargs,
    )


def test_cacheable_get_is_served_from_cache():
    opener = FakeOpener().json("GET", "/v0/status", {"status": "SUCCESS"})
    cache = TtlCache(ttl_seconds=30, clock=lambda: 0.0)
    client = _client(opener, cache=cache)

    first = client.get_json("https://1click.chaindefuser.com/v0/status?depositAddress=0xabc")
    second = client.get_json("https://1click.chaindefuser.com/v0/status?depositAddress=0xabc")

    assert first.data == {"status": "SUCCESS"}
    assert second.data == {"status": "SUCCESS"}
    # Only one network call was made; the second came from the cache.
    assert len(opener.calls) == 1


def test_cache_key_distinguishes_deposit_addresses():
    opener = FakeOpener()
    opener.json("GET", "depositAddress=0xaaa", {"addr": "aaa"})
    opener.json("GET", "depositAddress=0xbbb", {"addr": "bbb"})
    cache = TtlCache(ttl_seconds=30, clock=lambda: 0.0)
    client = _client(opener, cache=cache)

    a = client.get_json("https://1click.chaindefuser.com/v0/status?depositAddress=0xaaa")
    b = client.get_json("https://1click.chaindefuser.com/v0/status?depositAddress=0xbbb")
    assert a.data == {"addr": "aaa"}
    assert b.data == {"addr": "bbb"}
    assert len(opener.calls) == 2


def test_failed_response_is_not_cached():
    """A timeout must not be cached, so a later attempt can still succeed."""
    opener = FakeOpener()
    opener.timeout("GET", "/v0/status", once=True)
    opener.json("GET", "/v0/status", {"status": "SUCCESS"})
    cache = TtlCache(ttl_seconds=30, clock=lambda: 0.0)
    client = _client(opener, cache=cache)

    first = client.get_json("https://1click.chaindefuser.com/v0/status?depositAddress=0xabc")
    assert first.status is SourceStatus.TIMEOUT
    second = client.get_json("https://1click.chaindefuser.com/v0/status?depositAddress=0xabc")
    assert second.status is SourceStatus.OK
    assert second.data == {"status": "SUCCESS"}


def test_not_found_is_not_cached_as_success():
    opener = FakeOpener().http_error("GET", "/v0/status", 404, b"{}")
    cache = TtlCache(ttl_seconds=30, clock=lambda: 0.0)
    client = _client(opener, cache=cache)
    result = client.get_json("https://1click.chaindefuser.com/v0/status?depositAddress=0xabc")
    assert result.status is SourceStatus.NOT_FOUND
    assert len(cache) == 0


def test_post_is_never_cached():
    opener = FakeOpener().json("POST", "fastnear", {"result": "x"})
    cache = TtlCache(ttl_seconds=30, clock=lambda: 0.0)
    client = _client(opener, cache=cache)
    client.post_json("https://free.rpc.fastnear.com", {"method": "tx"})
    client.post_json("https://free.rpc.fastnear.com", {"method": "tx"})
    assert len(opener.calls) == 2
    assert len(cache) == 0


def test_non_cacheable_get_path_is_not_cached():
    """A path outside the cacheable set is always fetched."""
    opener = FakeOpener().json("GET", "/some/other", {"ok": True})
    cache = TtlCache(ttl_seconds=30, clock=lambda: 0.0)
    client = _client(opener, cache=cache)
    client.get_json("https://example.com/some/other")
    client.get_json("https://example.com/some/other")
    assert len(opener.calls) == 2


def test_cached_result_is_identical_to_live_result():
    """Caching must not change the parsed value, so reconciliation is unaffected."""
    opener = FakeOpener().json("GET", "/v0/status", {"swapDetails": {"intentHashes": ["h1"]}})
    cache = TtlCache(ttl_seconds=30, clock=lambda: 0.0)
    live_client = _client(opener)
    cached_client = _client(opener, cache=cache)

    live = live_client.get_json("https://1click.chaindefuser.com/v0/status?depositAddress=0xabc")
    cached_client.get_json("https://1click.chaindefuser.com/v0/status?depositAddress=0xabc")
    from_cache = cached_client.get_json("https://1click.chaindefuser.com/v0/status?depositAddress=0xabc")
    assert live.data == from_cache.data


def test_host_limiter_returns_rate_limited_without_a_network_call():
    opener = FakeOpener().json("POST", "fastnear", {"result": "x"})
    limiter = TokenBucketLimiter(rate_per_minute=60, burst=1, clock=lambda: 0.0)
    client = _client(opener, host_limiter=limiter)

    first = client.post_json("https://free.rpc.fastnear.com", {"method": "tx"})
    second = client.post_json("https://free.rpc.fastnear.com", {"method": "tx"})
    assert first.status is SourceStatus.OK
    assert second.status is SourceStatus.RATE_LIMITED
    assert second.message == "local host rate limit reached"
    # The second call never reached the network.
    assert len(opener.calls) == 1


def test_host_limiter_is_per_host():
    opener = FakeOpener()
    opener.json("POST", "fastnear", {"result": "near"})
    opener.json("POST", "publicnode", {"result": "evm"})
    limiter = TokenBucketLimiter(rate_per_minute=60, burst=1, clock=lambda: 0.0)
    client = _client(opener, host_limiter=limiter)

    near = client.post_json("https://free.rpc.fastnear.com", {"method": "tx"})
    evm = client.post_json("https://ethereum-rpc.publicnode.com", {"method": "eth"})
    assert near.status is SourceStatus.OK
    assert evm.status is SourceStatus.OK
