"""Regression tests for the NEAR JSON-RPC client's failure classification.

Two defects motivated this file, both found while checking the public
demonstration's live settlement read against the real free testnet nodes:

* A pruned transaction is returned inside an HTTP 200 as a JSON-RPC error whose
  outer ``name`` is the generic ``HANDLER_ERROR``; the real meaning lives in the
  ``cause``, the ``data`` string and the cause's ``info`` values. Reading only
  the outer name classified a definitive miss as ``MALFORMED``.
* Even once classified correctly, ``_call`` returned the JSON-RPC ``NOT_FOUND``
  immediately, so the fallback endpoints were never tried and a pruned
  transaction could never be found on an archive node.

Both are exercised here against a stub transport, so no network is required.
"""

from __future__ import annotations

from typing import Any

from tracesettle.httpclient import FetchResult
from tracesettle.model import SourceStatus
from tracesettle.near.networks import NetworkConfig, NearNetwork
from tracesettle.near.rpc import NearRpc

#: The exact envelope the free testnet node returns for a pruned transaction.
PRUNED_TX_ERROR: dict[str, Any] = {
    "name": "HANDLER_ERROR",
    "cause": {
        "info": {"requested_transaction_hash": "3wQ7UDmQzCTtqyxnBMaQ35SfxioQJUp3rnLyEPX6nuQd"},
        "name": "UNKNOWN_TRANSACTION",
    },
    "code": -32000,
    "message": "Server error",
    "data": "Transaction 3wQ7UDmQzCTtqyxnBMaQ35SfxioQJUp3rnLyEPX6nuQd doesn't exist",
}


class _StubClient:
    """A transport stub that answers each URL from a fixed script."""

    def __init__(self, responses: dict[str, FetchResult]) -> None:
        self.responses = responses
        self.calls: list[str] = []

    def post_json(self, url: str, payload: dict[str, Any]) -> FetchResult:
        self.calls.append(url)
        return self.responses.get(url, FetchResult(SourceStatus.NETWORK_ERROR, None, message="no stub"))


def _config(*urls: str) -> NetworkConfig:
    return NetworkConfig(
        network=NearNetwork.TESTNET,
        rpc_url=urls[0],
        rpc_fallbacks=tuple(urls[1:]),
    )


def _ok(body: dict[str, Any]) -> FetchResult:
    return FetchResult(SourceStatus.OK, 200, data=body)


def _rpc_error(error: dict[str, Any]) -> FetchResult:
    return FetchResult(SourceStatus.OK, 200, data={"jsonrpc": "2.0", "id": "tracesettle", "error": error})


def test_pruned_transaction_is_classified_not_found() -> None:
    """The generic outer name must not hide a definitive ``UNKNOWN_TRANSACTION``."""
    result = NearRpc._classify_rpc_error(PRUNED_TX_ERROR, "https://rpc.testnet.near.org")
    assert result.status is SourceStatus.NOT_FOUND


def test_an_unknown_transaction_message_alone_is_not_found() -> None:
    result = NearRpc._classify_rpc_error({"message": "Transaction abc doesn't exist"}, "u")
    assert result.status is SourceStatus.NOT_FOUND


def test_an_outage_error_is_not_mistaken_for_a_miss() -> None:
    """A server error must stay an outage, so the fan-out stops."""
    result = NearRpc._classify_rpc_error({"name": "HANDLER_ERROR", "message": "Server error"}, "u")
    assert result.status is SourceStatus.MALFORMED


def test_a_rate_limit_error_is_classified_rate_limited() -> None:
    result = NearRpc._classify_rpc_error({"message": "rate limit exceeded"}, "u")
    assert result.status is SourceStatus.RATE_LIMITED


def test_a_pruned_transaction_fans_out_to_the_archive() -> None:
    """The core regression: a NOT_FOUND inside HTTP 200 must try the next node."""
    free, archive = "https://free", "https://archive"
    client = _StubClient(
        {
            free: _rpc_error(PRUNED_TX_ERROR),
            archive: _ok({"jsonrpc": "2.0", "id": "tracesettle", "result": {"final_execution_status": "FINAL"}}),
        }
    )
    rpc = NearRpc(_config(free, archive), client=client)  # type: ignore[arg-type]
    result = rpc.tx_status("hash", "signer.testnet")
    assert result.ok
    assert result.endpoint == archive
    assert client.calls == [free, archive]


def test_an_outage_does_not_fan_out() -> None:
    """An outage on the first node must stop, not multiply load."""
    free, archive = "https://free", "https://archive"
    client = _StubClient({free: _rpc_error({"name": "HANDLER_ERROR", "message": "Server error"})})
    rpc = NearRpc(_config(free, archive), client=client)  # type: ignore[arg-type]
    result = rpc.tx_status("hash", "signer.testnet")
    assert not result.ok
    assert result.status is SourceStatus.MALFORMED
    assert client.calls == [free]


def test_a_miss_on_every_node_stays_not_found() -> None:
    free, archive = "https://free", "https://archive"
    client = _StubClient({free: _rpc_error(PRUNED_TX_ERROR), archive: _rpc_error(PRUNED_TX_ERROR)})
    rpc = NearRpc(_config(free, archive), client=client)  # type: ignore[arg-type]
    result = rpc.tx_status("hash", "signer.testnet")
    assert result.status is SourceStatus.NOT_FOUND
    assert client.calls == [free, archive]


def test_the_testnet_configuration_includes_an_archive_fallback() -> None:
    """The shipped config must be able to answer a pruned recent transaction."""
    from tracesettle.near.networks import NETWORKS

    config = NETWORKS[NearNetwork.TESTNET]
    assert "https://archival-rpc.testnet.near.org" in config.rpc_fallbacks


def test_archive_first_config_puts_the_archive_first() -> None:
    """A historical read should reach the node that holds the record first."""
    from tracesettle.near.networks import archive_first_config

    config = archive_first_config(NearNetwork.TESTNET)
    assert "archival" in config.rpc_url
    # Every original endpoint is still reachable.
    assert set(config.rpc_fallbacks) | {config.rpc_url} == {
        "https://rpc.testnet.near.org",
        "https://rpc.testnet.fastnear.com",
        "https://archival-rpc.testnet.near.org",
    }


def test_max_endpoints_bounds_the_fan_out() -> None:
    """A bounded client must not try more endpoints than it was given."""
    free, fast, archive = "https://free", "https://fast", "https://archive"
    client = _StubClient({u: _rpc_error(PRUNED_TX_ERROR) for u in (free, fast, archive)})
    rpc = NearRpc(_config(free, fast, archive), client=client, max_endpoints=2)  # type: ignore[arg-type]
    result = rpc.tx_status("hash", "signer.testnet")
    assert result.status is SourceStatus.NOT_FOUND
    assert client.calls == [free, fast]

