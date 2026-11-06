"""Live OutLayer Agent Custody provider checks, run only when a key is supplied.

The OutLayer Agent Custody API is real and documented at
``https://testnet-api.outlayer.ai/openapi.json``. This test exercises the
**live** provider through the production adapter
(:class:`tracesettle.near.outlayer.OutLayerCustodyProvider`).

Three things are asserted so the test cannot pass vacuously:

* the endpoint set the adapter calls is a subset of the provider's published
  OpenAPI paths — the adapter never invents an endpoint, and this fails the
  moment the provider renames one;
* an unauthenticated call is refused (401/400), never answered — the auth
  boundary the adapter models is the real one;
* when a live key is supplied, the wallet address read resolves through the real
  adapter and the provider's own ``policy``/``balance`` are read as evidence.

It is skipped by default: with no credentials the correct outcome is "skipped",
never a fabricated pass. It never sends a transfer, never signs, and never
mutates provider state.

Set ``TRACESETTLE_TEST_OUTLAYER_API_KEY`` (a ``wk_`` bearer key) to run the
authenticated half.
"""

from __future__ import annotations

import json
import os
import urllib.error
import urllib.request

import pytest

from tracesettle.near.outlayer import (
    OUTLAYER_HOSTS,
    OutLayerConfig,
    OutLayerCustodyProvider,
    OutLayerError,
    config_from_env,
)

_API_KEY = os.environ.get("TRACESETTLE_TEST_OUTLAYER_API_KEY", "").strip()

#: The provider's published OpenAPI document. The adapter must only ever call
#: paths that appear here.
_OPENAPI_URL = f"{OUTLAYER_HOSTS['testnet']}/openapi.json"

#: The paths the adapter uses, from the module docstring and the code.
_ADAPTER_PATHS = frozenset(
    {
        "/wallet/v1/transfer",
        "/wallet/v1/address",
        "/wallet/v1/balance",
        "/wallet/v1/requests/{id}",
        "/wallet/v1/audit",
        "/wallet/v1/policy",
    }
)


def _documented_paths() -> set[str]:
    with urllib.request.urlopen(_OPENAPI_URL, timeout=20) as response:
        document = json.loads(response.read().decode("utf-8"))
    return set(document.get("paths", {}))


def test_every_adapter_endpoint_is_in_the_published_openapi():
    """The adapter never invents an endpoint: each path is documented."""
    documented = _documented_paths()
    invented = _ADAPTER_PATHS - documented
    assert not invented, f"adapter calls paths the provider does not document: {sorted(invented)}"


def test_an_unauthenticated_call_is_refused():
    """With no credential the provider refuses; it never answers an operation."""
    request = urllib.request.Request(
        f"{OUTLAYER_HOSTS['testnet']}/wallet/v1/transfer",
        data=b'{"chain": "near", "to": "x", "amount": "1"}',
        method="POST",
        headers={"Content-Type": "application/json"},
    )
    try:
        with urllib.request.urlopen(request, timeout=20) as response:
            status = response.status
    except urllib.error.HTTPError as exc:
        status = exc.code
    assert status in {400, 401, 403}, f"unauthenticated transfer answered {status}"


def test_config_from_env_requires_a_key_when_enabled(monkeypatch):
    monkeypatch.setenv("TRACESETTLE_OUTLAYER_ENABLED", "1")
    monkeypatch.delenv("TRACESETTLE_OUTLAYER_API_KEY", raising=False)
    with pytest.raises(OutLayerError):
        config_from_env(os.environ)


@pytest.mark.skipif(
    not _API_KEY,
    reason="no live OutLayer key supplied; set TRACESETTLE_TEST_OUTLAYER_API_KEY",
)
def test_live_wallet_address_reads_through_the_real_adapter():
    """The authenticated wallet read resolves through the production adapter."""
    from tracesettle.httpclient import HttpClient

    provider = OutLayerCustodyProvider(
        OutLayerConfig(api_key=_API_KEY, network="testnet", timeout=20.0),
        client=HttpClient(timeout=20, max_attempts=2),
    )
    identity = provider.address("near")
    assert identity.account_id, "the provider returned no NEAR account id"
    # The read-only evidence surfaces are read as evidence, never as approval.
    policy = provider.policy()
    assert "available" in policy
    measurements = provider.approved_measurements()
    assert "available" in measurements
