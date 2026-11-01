"""HTTP-level per-service authentication tests: a real server, real sockets.

These verify the property the module exists for: a caller cannot adopt another
service's identity by editing ``service_id``, by replaying another service's
credential, or by presenting a revoked or expired one. The server, routing, and
credential resolution are the real code paths; only the outbound investigation
network is substituted (the guard endpoints make no outbound calls).
"""

from __future__ import annotations

import json
import threading
import urllib.error
import urllib.request
from contextlib import contextmanager
from datetime import datetime, timedelta, timezone

from tracesettle.serviceauth import CREDENTIAL_HEADER, ServiceRegistry, mint_secret
from tracesettle.ui import InvestigationServer

from guard_helpers import APPROVED_DESTINATION, make_authority, make_service

KEY_A = "treasury-agent"
KEY_B = "settlement-agent"

LEGIT = {
    "service_id": KEY_A,
    "operation": "WITHDRAWAL",
    "chain": "eth",
    "asset": "USDC",
    "amount": "1250.50",
    "destination": APPROVED_DESTINATION,
    "request_id": "sa-1",
}


def _future(seconds: int = 3600) -> str:
    return (datetime.now(timezone.utc) + timedelta(seconds=seconds)).strftime("%Y-%m-%dT%H:%M:%SZ")


def _past(seconds: int = 3600) -> str:
    return (datetime.now(timezone.utc) - timedelta(seconds=seconds)).strftime("%Y-%m-%dT%H:%M:%SZ")


@contextmanager
def running_server(*, registry=None, api_key=None, **kwargs):
    server = InvestigationServer(
        ("127.0.0.1", 0),
        timeout_seconds=2.0,
        max_attempts=1,
        guard_service=make_service(authority=make_authority()),
        service_registry=registry,
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


def _request(method, url, payload=None, credential=None):
    data = None if payload is None else json.dumps(payload).encode()
    headers = {"Content-Type": "application/json"}
    if credential is not None:
        headers[CREDENTIAL_HEADER] = credential
    req = urllib.request.Request(url, data=data, method=method, headers=headers)
    try:
        with urllib.request.urlopen(req, timeout=5) as resp:
            return resp.status, json.loads(resp.read() or b"{}")
    except urllib.error.HTTPError as e:
        body = e.read()
        try:
            parsed = json.loads(body)
        except json.JSONDecodeError:
            parsed = body
        return e.code, parsed


def _evaluate(base, payload, credential=None):
    return _request("POST", base + "/api/guard/evaluate", {"transaction": payload}, credential)


# --- no registry: loopback development is unchanged ------------------------


def test_without_a_registry_the_declared_identity_is_used():
    with running_server(registry=None) as base:
        status, body = _evaluate(base, LEGIT)
    assert status == 200
    assert body["decision"] == "ALLOW"


# --- registry configured: a credential is required -------------------------


def test_missing_credential_is_refused():
    registry = ServiceRegistry()
    registry.mint(KEY_A)
    with running_server(registry=registry) as base:
        status, _ = _evaluate(base, LEGIT)
    assert status == 401


def test_wrong_credential_is_refused():
    registry = ServiceRegistry()
    registry.mint(KEY_A)
    with running_server(registry=registry) as base:
        status, _ = _evaluate(base, LEGIT, credential=mint_secret())
    assert status == 401


def test_correct_credential_allows_the_honest_request():
    registry = ServiceRegistry()
    _, secret = registry.mint(KEY_A)
    with running_server(registry=registry) as base:
        status, body = _evaluate(base, LEGIT, credential=secret)
    assert status == 200
    assert body["decision"] == "ALLOW"


# --- impersonation ---------------------------------------------------------


def test_service_a_cannot_impersonate_service_b():
    """A's credential with a body that claims B is refused."""
    registry = ServiceRegistry()
    _, secret_a = registry.mint(KEY_A)
    registry.mint(KEY_B)
    with running_server(registry=registry) as base:
        status, _ = _evaluate(base, dict(LEGIT, service_id=KEY_B), credential=secret_a)
    assert status == 403


def test_changing_service_id_does_not_change_the_authenticated_identity():
    registry = ServiceRegistry()
    _, secret_b = registry.mint(KEY_B)
    with running_server(registry=registry) as base:
        # B's own credential with B's declared id is fine...
        ok_status, _ = _evaluate(base, dict(LEGIT, service_id=KEY_B), credential=secret_b)
        # ...but the same credential cannot claim A.
        forged_status, _ = _evaluate(base, dict(LEGIT, service_id=KEY_A), credential=secret_b)
    assert ok_status == 200
    assert forged_status == 403


def test_each_service_uses_its_own_credential_independently():
    registry = ServiceRegistry()
    _, secret_a = registry.mint(KEY_A)
    _, secret_b = registry.mint(KEY_B)
    with running_server(registry=registry) as base:
        a_status, _ = _evaluate(base, dict(LEGIT, service_id=KEY_A), credential=secret_a)
        b_status, _ = _evaluate(base, dict(LEGIT, service_id=KEY_B), credential=secret_b)
    assert a_status == 200
    assert b_status == 200


# --- revocation and expiry -------------------------------------------------


def test_revoked_credential_cannot_authorize_requests():
    registry = ServiceRegistry()
    credential, secret = registry.mint(KEY_A)
    registry.revoke(credential.credential_id)
    with running_server(registry=registry) as base:
        status, _ = _evaluate(base, LEGIT, credential=secret)
    assert status == 401


def test_expired_credential_cannot_authorize_requests():
    registry = ServiceRegistry()
    secret = mint_secret()
    registry.add(KEY_A, secret, expires_at=_past())
    with running_server(registry=registry) as base:
        status, _ = _evaluate(base, LEGIT, credential=secret)
    assert status == 401


# --- rotation --------------------------------------------------------------


def test_rotated_credential_works_and_the_old_one_does_not():
    registry = ServiceRegistry()
    _, old_secret = registry.mint(KEY_A)
    _, new_secret = registry.rotate(KEY_A)
    with running_server(registry=registry) as base:
        new_status, _ = _evaluate(base, LEGIT, credential=new_secret)
        old_status, _ = _evaluate(base, LEGIT, credential=old_secret)
    assert new_status == 200
    assert old_status == 401


# --- the credential is never echoed ----------------------------------------


def test_no_response_echoes_the_credential():
    registry = ServiceRegistry()
    _, secret = registry.mint(KEY_A)
    with running_server(registry=registry) as base:
        _, ok_body = _evaluate(base, LEGIT, credential=secret)
        _, bad_body = _evaluate(base, LEGIT, credential="wrong-credential-value-0000000000")
    assert secret not in json.dumps(ok_body)
    assert secret not in json.dumps(bad_body)
    assert "wrong-credential-value" not in json.dumps(bad_body)


def test_admin_route_is_not_gated_by_service_credential():
    """Incident status is an administrative route: API key only, not a service credential."""
    registry = ServiceRegistry()
    registry.mint(KEY_A)
    with running_server(registry=registry) as base:
        # No service credential, but no API key configured either: the admin
        # route proceeds (404 for an unknown incident, not 401).
        status, _ = _request("POST", base + "/api/guard/incidents/nope/status", {"status": "OPEN"})
    assert status == 404
