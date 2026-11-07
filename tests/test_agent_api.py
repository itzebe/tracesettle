"""The agent-facing integration: real sockets, real guard, sandbox-scoped.

An independent judge drives ``/api/agent/*``. These tests exercise the whole
surface over a real HTTP socket (only the outbound investigation/settlement
network is substituted), and assert the security properties that make the
surface safe to expose without the operator's key:

* ``connect`` mints a scoped credential; ``evaluate`` returns a decision;
* a payment to an approved destination is ``ALLOW`` and yields an authorization;
* a payment to an unapproved destination is ``BLOCK`` and never reaches the
  executor;
* an amount above the limit is ``BLOCK``; above the threshold is
  ``REQUIRE_APPROVAL``;
* the authorization is bound to the exact parameters (a substituted destination
  is refused) and is single-use (a replay is refused);
* the approval secret is separate from the API credential, so an agent cannot
  self-approve;
* a credential cannot name another service, and one credential's evidence is not
  visible to another;
* revocation takes effect immediately.
"""

from __future__ import annotations

import json
import threading
import urllib.error
import urllib.request
from contextlib import contextmanager

from tracesettle import config
from tracesettle.ui import InvestigationServer

from guard_helpers import make_authority, make_service

APPROVED = "0x1111111111111111111111111111111111111111"
ATTACKER = "0xdeadbeefdeadbeefdeadbeefdeadbeefdeadbeef"

CRED_HEADER = "X-Sandbox-Credential"
APPROVAL_HEADER = "X-Approval-Secret"


@contextmanager
def running_server(**kwargs):
    original = config.PUBLIC_DEMO_ENABLED
    config.PUBLIC_DEMO_ENABLED = True
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
        config.PUBLIC_DEMO_ENABLED = original


def _request(method, url, payload=None, headers=None, timeout=10):
    data = None if payload is None else json.dumps(payload).encode()
    all_headers = {"Content-Type": "application/json", **(headers or {})}
    req = urllib.request.Request(url, data=data, method=method, headers=all_headers)
    try:
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            return resp.status, json.loads(resp.read().decode())
    except urllib.error.HTTPError as e:
        body = e.read().decode()
        try:
            return e.code, json.loads(body)
        except json.JSONDecodeError:
            return e.code, {"raw": body}


def _connect(base, label="judge"):
    status, cred = _request("POST", f"{base}/api/agent/connect", {"label": label})
    assert status == 201, cred
    return cred


def _tx(destination=APPROVED, amount="50", **extra):
    tx = {
        "operation": "WITHDRAWAL",
        "chain": "base",
        "asset": "USDC",
        "amount": amount,
        "destination": destination,
    }
    tx.update(extra)
    return tx


# --- credential issuance ---------------------------------------------------


def test_connect_mints_a_scoped_credential():
    with running_server() as base:
        cred = _connect(base, label="my agent")
        assert cred["service_id"].startswith("sandbox-")
        assert cred["api_credential"]
        assert cred["approval_secret"]
        assert cred["api_credential"] != cred["approval_secret"]
        assert cred["ttl_seconds"] > 0
        assert set(cred["endpoints"]) >= {"evaluate", "execute", "approval", "evidence"}


def test_connect_returns_the_sandbox_allowlist_and_limits():
    with running_server() as base:
        cred = _connect(base)
        assert APPROVED in cred["approved_destinations"]
        assert cred["example_blocked_destination"] == ATTACKER


# --- evaluation ------------------------------------------------------------


def test_approved_destination_is_allowed_with_an_authorization():
    with running_server() as base:
        cred = _connect(base)
        headers = {CRED_HEADER: cred["api_credential"]}
        status, decision = _request(
            "POST", f"{base}/api/agent/evaluate", _tx(), headers
        )
        assert status == 200
        assert decision["decision"] == "ALLOW"
        assert decision["authorizes_signing"] is True
        assert decision["authorization"]


def test_unapproved_destination_is_blocked_and_never_reaches_the_executor():
    with running_server() as base:
        cred = _connect(base)
        headers = {CRED_HEADER: cred["api_credential"]}
        status, decision = _request(
            "POST", f"{base}/api/agent/evaluate", _tx(destination=ATTACKER), headers
        )
        assert status == 200
        assert decision["decision"] == "BLOCK"
        assert decision["authorizes_signing"] is False
        # There is nothing to present, so the executor is never reached.
        status, result = _request(
            "POST", f"{base}/api/agent/execute", {"transaction": _tx(destination=ATTACKER)}, headers
        )
        assert result["executor_calls"] == 0
        assert result["sign_result"]["outcome"] == "REFUSED"


def test_amount_above_the_limit_is_blocked():
    with running_server() as base:
        cred = _connect(base)
        headers = {CRED_HEADER: cred["api_credential"]}
        status, decision = _request(
            "POST", f"{base}/api/agent/evaluate", _tx(amount="99999"), headers
        )
        assert decision["decision"] == "BLOCK"


def test_amount_above_the_threshold_requires_approval():
    with running_server() as base:
        cred = _connect(base)
        headers = {CRED_HEADER: cred["api_credential"]}
        status, decision = _request(
            "POST", f"{base}/api/agent/evaluate", _tx(amount="250"), headers
        )
        assert decision["decision"] == "REQUIRE_APPROVAL"
        assert decision["authorizes_signing"] is False


# --- the signing boundary --------------------------------------------------


def test_an_allowed_transaction_executes_through_the_real_signer():
    with running_server() as base:
        cred = _connect(base)
        headers = {CRED_HEADER: cred["api_credential"]}
        tx = _tx()
        _, decision = _request("POST", f"{base}/api/agent/evaluate", tx, headers)
        status, result = _request(
            "POST",
            f"{base}/api/agent/execute",
            {"transaction": tx, "authorization": decision["authorization"]},
            headers,
        )
        assert result["sign_result"]["outcome"] == "EXECUTED"
        assert result["executor_calls"] == 1
        assert result["broadcast"] is False
        assert result["simulated"] is True


def test_a_substituted_destination_is_refused_by_the_signer():
    with running_server() as base:
        cred = _connect(base)
        headers = {CRED_HEADER: cred["api_credential"]}
        _, decision = _request("POST", f"{base}/api/agent/evaluate", _tx(), headers)
        # Present the authorization with a *different*, also-approved destination.
        status, result = _request(
            "POST",
            f"{base}/api/agent/execute",
            {
                "transaction": _tx(destination="0x2222222222222222222222222222222222222222"),
                "authorization": decision["authorization"],
            },
            headers,
        )
        assert result["sign_result"]["outcome"] == "REFUSED"
        assert result["sign_result"]["state"] == "WRONG_PARAMETERS"
        assert result["executor_calls"] == 0


def test_an_authorization_is_single_use():
    with running_server() as base:
        cred = _connect(base)
        headers = {CRED_HEADER: cred["api_credential"]}
        tx = _tx()
        _, decision = _request("POST", f"{base}/api/agent/evaluate", tx, headers)
        auth = decision["authorization"]
        _, first = _request(
            "POST", f"{base}/api/agent/execute", {"transaction": tx, "authorization": auth}, headers
        )
        assert first["sign_result"]["outcome"] == "EXECUTED"
        _, second = _request(
            "POST", f"{base}/api/agent/execute", {"transaction": tx, "authorization": auth}, headers
        )
        assert second["sign_result"]["outcome"] == "REFUSED"
        assert second["sign_result"]["state"] == "REPLAYED"
        assert second["executor_calls"] == 1


# --- approval separation of duties -----------------------------------------


def test_the_api_credential_cannot_self_approve():
    with running_server() as base:
        cred = _connect(base)
        headers = {CRED_HEADER: cred["api_credential"]}
        status, response = _request(
            "POST", f"{base}/api/agent/approval", {"transaction": _tx(amount="250")}, headers
        )
        assert status == 403
        assert "approval secret" in response["error"]


def test_the_approval_secret_raises_a_threshold_payment_to_allow():
    with running_server() as base:
        cred = _connect(base)
        cred_headers = {CRED_HEADER: cred["api_credential"]}
        approval_headers = {
            CRED_HEADER: cred["api_credential"],
            APPROVAL_HEADER: cred["approval_secret"],
        }
        tx = _tx(amount="250", request_id="approve-me")
        status, approval = _request(
            "POST", f"{base}/api/agent/approval", {"transaction": tx}, approval_headers
        )
        assert status == 200
        assert approval["approval"]["signature"]
        # Without the approval the decision stays REQUIRE_APPROVAL.
        _, without = _request("POST", f"{base}/api/agent/evaluate", tx, cred_headers)
        assert without["decision"] == "REQUIRE_APPROVAL"
        # With it, the decision is raised to ALLOW and an authorization is minted.
        _, with_approval = _request(
            "POST",
            f"{base}/api/agent/evaluate",
            {"transaction": tx, "approval": approval["approval"]},
            cred_headers,
        )
        assert with_approval["decision"] == "ALLOW"
        assert with_approval["authorization"]


def test_an_approval_for_a_different_amount_is_refused():
    with running_server() as base:
        cred = _connect(base)
        approval_headers = {
            CRED_HEADER: cred["api_credential"],
            APPROVAL_HEADER: cred["approval_secret"],
        }
        cred_headers = {CRED_HEADER: cred["api_credential"]}
        _, approval = _request(
            "POST",
            f"{base}/api/agent/approval",
            {"transaction": _tx(amount="250", request_id="bound")},
            approval_headers,
        )
        # Present the approval with a *different* amount: the payload binding fails.
        _, decision = _request(
            "POST",
            f"{base}/api/agent/evaluate",
            {"transaction": _tx(amount="300", request_id="bound"), "approval": approval["approval"]},
            cred_headers,
        )
        assert decision["decision"] == "REQUIRE_APPROVAL"


# --- credential isolation and lifecycle ------------------------------------


def test_a_credential_cannot_name_another_service():
    with running_server() as base:
        cred = _connect(base)
        headers = {CRED_HEADER: cred["api_credential"]}
        status, response = _request(
            "POST",
            f"{base}/api/agent/evaluate",
            _tx(service_id="treasury-agent"),
            headers,
        )
        assert status == 403


def test_one_credential_cannot_see_another_credentials_evidence():
    with running_server() as base:
        a = _connect(base, label="alpha")
        b = _connect(base, label="beta")
        a_headers = {CRED_HEADER: a["api_credential"]}
        b_headers = {CRED_HEADER: b["api_credential"]}
        tx = _tx()
        _, decision = _request("POST", f"{base}/api/agent/evaluate", tx, a_headers)
        _request(
            "POST",
            f"{base}/api/agent/execute",
            {"transaction": tx, "authorization": decision["authorization"]},
            a_headers,
        )
        _, a_evidence = _request("GET", f"{base}/api/agent/evidence", None, a_headers)
        _, b_evidence = _request("GET", f"{base}/api/agent/evidence", None, b_headers)
        assert a_evidence["executor_calls"] == 1
        assert b_evidence["executor_calls"] == 0
        assert b_evidence["credential_id"] != a_evidence["credential_id"]


def test_a_revoked_credential_is_refused():
    with running_server() as base:
        cred = _connect(base)
        headers = {CRED_HEADER: cred["api_credential"]}
        status, _ = _request("POST", f"{base}/api/agent/revoke", {}, headers)
        assert status == 200
        status, response = _request("POST", f"{base}/api/agent/evaluate", _tx(), headers)
        assert status == 401
        assert response["reason"] == "REVOKED"


def test_an_unknown_credential_is_refused():
    with running_server() as base:
        status, response = _request(
            "POST", f"{base}/api/agent/evaluate", _tx(), {CRED_HEADER: "not-a-real-credential"}
        )
        assert status == 401
        assert response["reason"] == "INVALID"


def test_a_missing_credential_is_refused():
    with running_server() as base:
        status, response = _request("POST", f"{base}/api/agent/evaluate", _tx())
        assert status == 401
        assert response["reason"] == "MISSING"


# --- machine-readable contract ---------------------------------------------


def test_openapi_is_served_and_names_the_routes():
    with running_server() as base:
        status, spec = _request("GET", f"{base}/api/agent/openapi.json")
        assert status == 200
        assert spec["openapi"].startswith("3.")
        assert "/api/agent/evaluate" in spec["paths"]
        assert "/api/agent/execute" in spec["paths"]
        assert "SandboxCredential" in spec["components"]["securitySchemes"]


def test_config_reports_the_sandbox_scope_honestly():
    with running_server() as base:
        status, cfg = _request("GET", f"{base}/api/agent/config")
        assert status == 200
        assert cfg["sandbox"]["per_transaction_limit"] == "500"
        assert "simulated" in cfg["honest_scope"]


def test_agent_routes_are_absent_when_the_public_demo_is_disabled():
    original = config.PUBLIC_DEMO_ENABLED
    config.PUBLIC_DEMO_ENABLED = False
    try:
        server = InvestigationServer(
            ("127.0.0.1", 0),
            timeout_seconds=2.0,
            max_attempts=1,
            guard_service=make_service(authority=make_authority()),
        )
        host, port = server.server_address[:2]
        thread = threading.Thread(target=server.serve_forever, daemon=True)
        thread.start()
        try:
            base = f"http://{host}:{port}"
            status, _ = _request("POST", f"{base}/api/agent/connect", {"label": "x"})
            assert status == 404
            status, _ = _request("GET", f"{base}/api/agent/config")
            assert status == 404
        finally:
            server.shutdown()
            server.server_close()
            thread.join(timeout=5)
    finally:
        config.PUBLIC_DEMO_ENABLED = original
