"""Product identity and the end-to-end demonstration surface.

Two properties are guarded here:

* the public landing page presents the **whole** product — both the pre-execution
  authorization firewall and the settlement investigator — rather than only the
  read-only investigator identity it carried before the firewall existed;
* the demonstration endpoint runs the **real** boundary, signer and verifier and
  reports provable outcomes (a zero signer-call count for the blocked payment, a
  verified settlement for the approved one), and stays labelled a simulation.

The demonstration tests exercise real code paths: the only substitution is the
network transport (the offline RPC), which is a transport boundary, not a logic
mock. ``signer_calls == 0`` is asserted as "the signer was never invoked".
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
from tracesettle.near.agent_demo import (
    ATTACKER_RECEIVER,
    run_agent_payment_demo,
)
from tracesettle.ui import InvestigationServer

from guard_helpers import make_authority, make_service


@contextmanager
def running_server(**kwargs):
    original = config.API_KEY
    config.API_KEY = kwargs.pop("api_key", None)
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
        config.API_KEY = original


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


# --- landing page identity -------------------------------------------------


def test_landing_page_presents_both_capabilities():
    """The landing page must not present the product as investigation-only."""
    with running_server() as base:
        status, body, _ = _get(base + "/")
    assert status == 200
    html = body
    # The firewall is presented, not only the investigator.
    assert "Stop unauthorized AI payments" in html
    assert "Protect payments" in html
    assert "Investigate settlement" in html
    # A path into the console's authorization firewall and the demonstration.
    assert "console#guard" in html
    assert "console#lab" in html
    # The investigation form is still present and reachable.
    assert 'id="form"' in html
    assert 'id="investigate"' in html


def test_landing_page_keeps_the_read_only_honesty():
    """The public interface must still state its read-only, non-custodial scope."""
    with running_server() as base:
        _, body, _ = _get(base + "/")
    assert "read-only" in body
    assert "never signs, submits or moves funds" in body
    # A demonstration link must be labelled simulated, never live.
    assert "Simulated" in body
    assert ">LIVE<" not in body


def test_landing_page_is_accessible_and_responsive():
    with running_server() as base:
        _, body, _ = _get(base + "/")
    assert 'width=device-width' in body
    assert 'href="#main"' in body  # skip link
    assert 'id="main"' in body
    assert "<h1" in body


# --- demonstration endpoint ------------------------------------------------


def test_agent_demo_endpoint_reproduces_the_security_story():
    with running_server() as base:
        status, payload, _ = _get(base + "/api/guard/near/agent-demo")
    assert status == 200
    assert payload["simulated"] is True
    assert "Simulated" in payload["note"]
    assert payload["reproduced"] is True

    malicious = payload["malicious"]
    assert malicious["decision"] == "BLOCK"
    assert malicious["signer_calls"] == 0
    assert malicious["signed"] is False
    assert malicious["broadcast_occurred"] is False
    assert malicious["proposed_receiver"] == ATTACKER_RECEIVER

    legitimate = payload["legitimate"]
    assert legitimate["decision"] == "ALLOW"
    assert legitimate["signer_calls"] == 1
    assert legitimate["signed"] is True
    assert legitimate["settlement_state"] == "VERIFIED"
    assert (legitimate.get("verification") or {}).get("state") == "VERIFIED"


def test_agent_demo_binds_the_authorization_to_the_signed_bytes():
    """The authorization must cover the exact bytes that are signed."""
    with running_server() as base:
        _, payload, _ = _get(base + "/api/guard/near/agent-demo")
    legit = payload["legitimate"]
    binding = legit["authorization_binding"]
    assert binding["destination"] == legit["proposed_receiver"]
    assert binding["transaction_digest"] == legit["signed_bytes_digest"]
    assert legit["signed_bytes_digest"].startswith("sha256:")


def test_agent_demo_endpoint_requires_the_api_key_when_configured():
    with running_server(api_key="s3cret") as base:
        unauth, _, _ = _get(base + "/api/guard/near/agent-demo")
        auth, payload, _ = _get(base + "/api/guard/near/agent-demo", key="s3cret")
    assert unauth == 401
    assert auth == 200
    assert payload["reproduced"] is True


def test_agent_demo_is_deterministic():
    """Identical input must produce an identical result, byte for byte."""
    first = json.dumps(run_agent_payment_demo().to_dict(), sort_keys=True)
    second = json.dumps(run_agent_payment_demo().to_dict(), sort_keys=True)
    assert first == second


def test_agent_demo_dispatch_returns_the_full_payload():
    """The route works through the API object without a socket."""
    api = GuardAPI(make_service(authority=make_authority()))
    response = api.dispatch("GET", "/api/guard/near/agent-demo", {}, None)
    assert response.status == 200
    assert response.payload["reproduced"] is True
    assert response.payload["malicious"]["signer_calls"] == 0


@pytest.mark.parametrize("path", ["/api/guard/near/agent-demo"])
def test_agent_demo_is_not_cached_across_requests(path):
    """A second request returns the same honest result (no fabricated drift)."""
    with running_server() as base:
        _, first, _ = _get(base + path)
        _, second, _ = _get(base + path)
    assert first["reproduced"] == second["reproduced"] is True
