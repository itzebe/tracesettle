"""The public, keyless demonstration surface.

The production deployment sets ``TRACESETTLE_API_KEY``, which gates every guard
route and the investigation endpoint. The landing page nevertheless advertises a
demonstration, so without an opt-in public surface a first-time visitor meets
``{"error": "unauthorized"}`` on every button — the website promises something it
cannot deliver.

These tests pin the fix and, just as importantly, pin its **limits**:

* with the flag off (the default) nothing changes — every demo route stays
  key-gated, exactly as before;
* with the flag on, only the exact allowlist is served keyless, and every
  state-changing or sensitive route keeps the API-key requirement;
* the ``/demo`` page is only served when the flag is on, so the landing page and
  the page it links to never disagree.

The demonstration tests run the real code paths; the only substitution is the
outbound HTTP transport (``FakeOpener``), which is a transport boundary, not a
logic mock. The settlement-check test substitutes the RPC transport for the same
reason and asserts the real verification logic over a real capture.
"""

from __future__ import annotations

import json
import threading
import urllib.error
import urllib.request
from contextlib import contextmanager

import pytest

from tracesettle import config
from tracesettle.guard.api import GuardAPI
from tracesettle.near.settlement_check import (
    REFERENCE_RECEIVER,
    REFERENCE_SIGNER,
    REFERENCE_TX_HASH,
    SettlementCheck,
    verify_reference_settlement,
)
from tracesettle.ui import PUBLIC_DEMO_ROUTES, InvestigationServer

from guard_helpers import make_authority, make_service

#: The public allowlist, written out here so a change to the shipped set is a
#: test failure, not a silent widening of the surface.
EXPECTED_PUBLIC_ROUTES = {
    "/api/guard/scenarios",
    "/api/guard/near/agent-demo",
    "/api/guard/near/policy-scope",
    "/api/guard/near/behaviours",
    "/api/guard/near/prompt-injection",
    "/api/guard/near/settlement-check",
}

#: Routes that must **never** be served without the API key, even with the public
#: demonstration enabled. This is the security-critical half of the test.
MUST_STAY_GATED = [
    "/api/guard/policy",
    "/api/guard/metrics",
    "/api/guard/incidents",
    "/api/guard/audit",
    "/api/guard/invariants",
    "/api/guard/safeguards",
    "/api/guard/investigations",
    "/api/guard/near/execution",
    "/api/guard/near/wallet",
    "/api/guard/near/tee",
    "/api/guard/near/enclave",
    "/api/guard/near/access-keys",
    "/api/guard/near/lifecycle",
    "/api/guard/near/settlement-demo",
]


@contextmanager
def running_server(*, api_key: str | None = None, public_demo: bool = False, **kwargs):
    original_key = config.API_KEY
    original_demo = config.PUBLIC_DEMO_ENABLED
    config.API_KEY = api_key
    config.PUBLIC_DEMO_ENABLED = public_demo
    server = InvestigationServer(
        ("127.0.0.1", 0),
        timeout_seconds=2.0,
        max_attempts=1,
        guard_service=make_service(authority=make_authority()),
        **kwargs,
    )
    host, port = server.server_address[:2]
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        yield f"http://{host}:{port}"
    finally:
        server.shutdown()
        server.server_close()
        thread.join(timeout=5)
        config.API_KEY = original_key
        config.PUBLIC_DEMO_ENABLED = original_demo


def _get(url: str, key: str | None = None):
    req = urllib.request.Request(url, method="GET")
    if key is not None:
        req.add_header("X-API-Key", key)
    try:
        with urllib.request.urlopen(req, timeout=5) as resp:
            body = resp.read().decode("utf-8", "replace")
            try:
                parsed = json.loads(body)
            except json.JSONDecodeError:
                parsed = body
            return resp.status, parsed, dict(resp.headers)
    except urllib.error.HTTPError as exc:
        body = exc.read().decode("utf-8", "replace")
        try:
            parsed = json.loads(body)
        except json.JSONDecodeError:
            parsed = body
        return exc.code, parsed, dict(exc.headers)


# --- the allowlist itself --------------------------------------------------


def test_public_allowlist_is_exactly_the_expected_set():
    """A widening of the public surface must be a deliberate, reviewed change."""
    assert set(PUBLIC_DEMO_ROUTES) == EXPECTED_PUBLIC_ROUTES


def test_public_allowlist_contains_only_read_only_routes():
    """No route that evaluates, signs, broadcasts or mutates may be keyless."""
    # The exact gated route names, so an allowlist entry cannot shadow one of
    # them by sharing a substring (e.g. ``policy-scope`` is a shipped fixture
    # analysis, whereas ``/api/guard/policy`` is the operator's live policy).
    gated = set(MUST_STAY_GATED) | {
        "/api/guard/evaluate",
        "/api/guard/sign",
        "/api/guard/near/agent-evaluate",
        "/api/guard/near/execution/prepare",
        "/api/guard/near/execution/submit",
        "/api/guard/near/wallet/prepare",
        "/api/guard/near/wallet/verify",
        "/api/guard/near/lifecycle",
        "/api/guard/near/lifecycle/tokens",
        "/api/guard/near/lifecycle/list",
    }
    for path in PUBLIC_DEMO_ROUTES:
        assert path.startswith("/api/guard/")
        assert path not in gated, f"{path} must not be keyless"


# --- default posture: the flag off changes nothing -------------------------


def test_flag_off_leaves_every_demo_route_gated():
    with running_server(api_key="s3cret", public_demo=False) as base:
        for path in sorted(EXPECTED_PUBLIC_ROUTES):
            status, _, _ = _get(base + path)
            assert status == 401, f"{path} must stay gated when the flag is off"


def test_flag_off_does_not_serve_the_demo_page():
    with running_server(api_key="s3cret", public_demo=False) as base:
        status, _, _ = _get(base + "/demo")
    assert status == 404


def test_flag_off_landing_page_links_to_the_console_not_the_demo():
    with running_server(public_demo=False) as base:
        _, body, _ = _get(base + "/")
    assert "console#lab" in body
    assert 'href="demo"' not in body


# --- enabled: the demonstration is reachable without a key -----------------


def test_flag_on_serves_every_allowlisted_route_without_a_key():
    with running_server(api_key="s3cret", public_demo=True) as base:
        for path in sorted(EXPECTED_PUBLIC_ROUTES):
            status, payload, _ = _get(base + path)
            assert status == 200, f"{path} should be keyless when the demo is enabled"
            assert isinstance(payload, dict)


def test_flag_on_serves_the_demo_page():
    with running_server(api_key="s3cret", public_demo=True) as base:
        status, body, headers = _get(base + "/demo")
    assert status == 200
    assert "text/html" in headers.get("Content-Type", "")
    assert "six-scene" in body.lower()
    # Same-origin only: no third-party origin is named in the page. The inline
    # favicon is a data: URI, whose SVG namespace is the only http:// in the page,
    # so remove it before checking for a real network origin.
    without_icon = body.split('rel="icon"', 1)[-1].split(">", 1)[-1]
    assert "http://" not in without_icon and "https://" not in without_icon


def test_flag_on_landing_page_links_to_the_demo():
    with running_server(public_demo=True) as base:
        _, body, _ = _get(base + "/")
    assert 'href="demo"' in body
    assert "Run the six-scene demonstration" in body


# --- enabled: everything sensitive stays gated -----------------------------


@pytest.mark.parametrize("path", MUST_STAY_GATED)
def test_sensitive_routes_stay_gated_even_with_the_demo_enabled(path):
    with running_server(api_key="s3cret", public_demo=True) as base:
        status, _, _ = _get(base + path)
    assert status == 401, f"{path} must never be served without the API key"


def test_investigate_endpoint_stays_gated_with_the_demo_enabled():
    with running_server(api_key="s3cret", public_demo=True) as base:
        req = urllib.request.Request(
            base + "/api/investigate",
            data=json.dumps({"identifier": "0xB741c00f6D63b6dEd0cCADA1a82bCBADc38A572B"}).encode(),
            method="POST",
            headers={"Content-Type": "application/json"},
        )
        try:
            with urllib.request.urlopen(req, timeout=5) as resp:
                status = resp.status
        except urllib.error.HTTPError as exc:
            status = exc.code
    assert status == 401


def test_post_routes_stay_gated_with_the_demo_enabled():
    """The allowlist is GET-only; a POST to an allowlisted path stays gated."""
    with running_server(api_key="s3cret", public_demo=True) as base:
        req = urllib.request.Request(
            base + "/api/guard/near/agent-demo",
            data=b"{}",
            method="POST",
            headers={"Content-Type": "application/json"},
        )
        try:
            with urllib.request.urlopen(req, timeout=5) as resp:
                status = resp.status
        except urllib.error.HTTPError as exc:
            status = exc.code
    assert status == 401


# --- the demonstration content is real, not fabricated ---------------------


def test_public_agent_demo_reproduces_the_security_story():
    with running_server(api_key="s3cret", public_demo=True) as base:
        status, payload, _ = _get(base + "/api/guard/near/agent-demo")
    assert status == 200
    assert payload["reproduced"] is True
    assert payload["malicious"]["decision"] == "BLOCK"
    assert payload["malicious"]["signer_calls"] == 0
    assert payload["legitimate"]["decision"] == "ALLOW"
    assert payload["legitimate"]["settlement_state"] == "VERIFIED"


def test_public_agent_demo_binds_the_authorization_to_the_signed_bytes():
    with running_server(api_key="s3cret", public_demo=True) as base:
        _, payload, _ = _get(base + "/api/guard/near/agent-demo")
    binding = payload["legitimate"]["authorization_binding"]
    assert binding["transaction_digest"] == payload["legitimate"]["signed_bytes_digest"]


# --- the live settlement check ---------------------------------------------


def test_settlement_check_verifies_the_reference_transaction_offline():
    """The check must reach VERIFIED from a real capture, with the real verifier.

    The RPC transport is substituted; the verification logic is the production
    code. A capture of the real testnet ``tx`` response stands in for the socket.
    """
    from tracesettle.model import SourceStatus
    from tracesettle.near.rpc import RpcResult

    class _StubRpc:
        def __init__(self, result):
            self._result = result

        def tx_status(self, tx_hash, sender_account_id):
            return self._result

    capture = {
        "final_execution_status": "FINAL",
        "transaction": {
            "hash": REFERENCE_TX_HASH,
            "signer_id": REFERENCE_SIGNER,
            "receiver_id": REFERENCE_RECEIVER,
            "nonce": 43,
            "actions": [{"Transfer": {"deposit": "10000000000000000000000"}}],
        },
        "transaction_outcome": {"block_hash": "6p8EdGjyX4MFGzi3868SYXPAXSXbwnA7Ls9V8FT7dkTZ"},
        "status": {"SuccessValue": ""},
    }
    check = verify_reference_settlement(
        rpc=_StubRpc(RpcResult(SourceStatus.OK, data=capture))
    )
    assert check.available is True
    assert check.state == "VERIFIED"
    assert check.verified is True
    assert check.network == "testnet"


def test_settlement_check_never_upgrades_an_outage_into_a_verdict():
    from tracesettle.model import SourceStatus
    from tracesettle.near.rpc import RpcResult

    class _DownRpc:
        def tx_status(self, tx_hash, sender_account_id):
            return RpcResult(SourceStatus.TIMEOUT, error="timeout")

    check = verify_reference_settlement(rpc=_DownRpc())
    assert isinstance(check, SettlementCheck)
    assert check.available is False
    assert check.state == "UNAVAILABLE"
    assert check.verified is False
    assert check.verification is None


def test_settlement_check_is_always_testnet_and_read_only():
    check = SettlementCheck(
        available=True,
        network="testnet",
        tx_hash=REFERENCE_TX_HASH,
        explorer_url="https://testnet.nearblocks.io/txns/" + REFERENCE_TX_HASH,
        verification=None,
        note="",
    )
    payload = check.to_dict()
    assert payload["mainnet"] is False
    assert payload["network"] == "testnet"


def test_settlement_check_route_is_served_and_reports_its_scope(monkeypatch):
    """The route answers and states its scope, with the RPC transport substituted.

    The suite makes no real network calls, so the RPC transport is replaced by a
    stub returning a real capture; the route, the handler and the verifier are the
    production code.
    """
    from tracesettle.model import SourceStatus
    from tracesettle.near import settlement_check as sc_module
    from tracesettle.near.rpc import RpcResult

    capture = {
        "final_execution_status": "FINAL",
        "transaction": {
            "hash": REFERENCE_TX_HASH,
            "signer_id": REFERENCE_SIGNER,
            "receiver_id": REFERENCE_RECEIVER,
            "nonce": 43,
            "actions": [{"Transfer": {"deposit": "10000000000000000000000"}}],
        },
        "transaction_outcome": {"block_hash": "6p8EdGjyX4MFGzi3868SYXPAXSXbwnA7Ls9V8FT7dkTZ"},
        "status": {"SuccessValue": ""},
    }

    class _StubRpc:
        def __init__(self, *args, **kwargs):
            pass

        def tx_status(self, tx_hash, sender_account_id):
            return RpcResult(SourceStatus.OK, data=capture)

    monkeypatch.setattr(sc_module, "NearRpc", _StubRpc)

    with running_server(api_key="s3cret", public_demo=True) as base:
        status, payload, _ = _get(base + "/api/guard/near/settlement-check")
    assert status == 200
    assert payload["network"] == "testnet"
    assert payload["mainnet"] is False
    assert payload["tx_hash"]
    assert payload["state"] in {"VERIFIED", "UNAVAILABLE", "PENDING", "CONFIRMED", "DISPUTED"}


def test_settlement_check_dispatch_without_a_socket(monkeypatch):
    from tracesettle.model import SourceStatus
    from tracesettle.near import settlement_check as sc_module
    from tracesettle.near.rpc import RpcResult

    capture = {
        "final_execution_status": "FINAL",
        "transaction": {
            "hash": REFERENCE_TX_HASH,
            "signer_id": REFERENCE_SIGNER,
            "receiver_id": REFERENCE_RECEIVER,
            "nonce": 43,
            "actions": [{"Transfer": {"deposit": "10000000000000000000000"}}],
        },
        "transaction_outcome": {"block_hash": "6p8EdGjyX4MFGzi3868SYXPAXSXbwnA7Ls9V8FT7dkTZ"},
        "status": {"SuccessValue": ""},
    }

    class _StubRpc:
        def __init__(self, *args, **kwargs):
            pass

        def tx_status(self, tx_hash, sender_account_id):
            return RpcResult(SourceStatus.OK, data=capture)

    monkeypatch.setattr(sc_module, "NearRpc", _StubRpc)
    api = GuardAPI(make_service(authority=make_authority()))
    response = api.dispatch("GET", "/api/guard/near/settlement-check", {}, None)
    assert response.status == 200
    assert response.payload["network"] == "testnet"


# --- rate limiting still applies to the keyless surface --------------------


def test_public_demo_routes_are_rate_limited():
    from tracesettle.ratelimit import TokenBucketLimiter

    tight = TokenBucketLimiter(rate_per_minute=60, burst=2)
    with running_server(api_key="s3cret", public_demo=True, guard_limiter=tight) as base:
        statuses = [_get(base + "/api/guard/near/agent-demo")[0] for _ in range(6)]
    assert 429 in statuses, "a keyless route must still be rate-limited"
    assert statuses.count(200) >= 1


def test_the_demo_transport_is_substituted_but_the_code_is_real():
    """Sanity: the demonstration needs no network to run through its logic."""
    with running_server(api_key="s3cret", public_demo=True) as base:
        # agent-demo is fully offline; it must answer even with no opener patched.
        status, payload, _ = _get(base + "/api/guard/near/agent-demo")
    assert status == 200 and payload["reproduced"] is True


# --- the public pages must not request a missing favicon -------------------


def test_public_pages_declare_an_inline_favicon():
    """A page that requests a favicon which does not exist logs a 404.

    The demonstration and the landing page must declare a same-origin inline
    icon, so a first-time visitor's browser never logs a failed request.
    """
    from tracesettle.ui import _DEMO_HTML, _INDEX_HTML

    for html in (_DEMO_HTML, _INDEX_HTML):
        assert 'rel="icon"' in html
        assert "data:image/svg+xml" in html


def test_the_demo_page_is_served_with_a_restrictive_csp():
    """The demonstration must not be able to load a third-party origin."""
    with running_server(api_key="s3cret", public_demo=True) as base:
        status, body, headers = _get(base + "/demo")
    assert status == 200
    csp = headers.get("Content-Security-Policy", "")
    assert "default-src 'none'" in csp
    assert "script-src 'unsafe-inline'" in csp
    # Only same-origin connections are permitted; no wildcard origin.
    assert "connect-src 'self'" in csp
    assert "*" not in csp


def test_console_401_hint_is_honest_about_the_public_demo():
    """The console's unauthorized message must not point at a disabled /demo.

    When the public demonstration is off, /demo answers 404, so the console must
    not tell an operator to open it. When it is on, the hint is present.
    """
    with running_server(api_key="s3cret", public_demo=False) as base:
        off = _get(base + "/console")[1]
    with running_server(api_key="s3cret", public_demo=True) as base:
        on = _get(base + "/console")[1]
    assert "open the public demonstration at /demo" not in off
    assert "open the public demonstration at /demo" in on
    # No un-substituted template placeholder ever reaches a client.
    for html in (off, on):
        assert "__DEMO_HINT__" not in html
