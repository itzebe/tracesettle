"""Guard API routing tests (no socket: the handler owns the transport).

These exercise the real :class:`GuardAPI` and the real service. They check
routing, validation, serialization, and the property that a decision's
authorization is returned only when it is asked for.
"""

from __future__ import annotations

import pytest

from tracesettle.guard.api import SIMULATION_NOTE, GuardAPI
from tracesettle.guard.model import IncidentStatus

from guard_helpers import (
    APPROVED_DESTINATION,
    UNAPPROVED_DESTINATION,
    make_service,
)


@pytest.fixture
def api() -> GuardAPI:
    return GuardAPI(make_service())


LEGIT = {
    "service_id": "treasury-agent",
    "operation": "WITHDRAWAL",
    "chain": "eth",
    "asset": "USDC",
    "amount": "1250.50",
    "destination": APPROVED_DESTINATION,
    "request_id": "api-1",
}
SUSPICIOUS = dict(LEGIT, amount="480000", destination=UNAPPROVED_DESTINATION, request_id="api-2")


def test_evaluate_allow_returns_decision(api):
    response = api.dispatch("POST", "/api/guard/evaluate", {}, {"transaction": LEGIT})
    assert response.status == 200
    assert response.payload["decision"] == "ALLOW"
    assert response.payload["authorizes_signing"] is True
    # The token is omitted unless it is explicitly requested.
    assert "authorization" not in response.payload


def test_evaluate_can_return_the_authorization(api):
    response = api.dispatch(
        "POST", "/api/guard/evaluate", {}, {"transaction": LEGIT, "return_authorization": True}
    )
    assert response.payload["authorization"]["authorization_id"].startswith("auth_")
    assert response.payload["authorization"]["fingerprint"]


def test_evaluate_accepts_top_level_transaction_fields(api):
    response = api.dispatch("POST", "/api/guard/evaluate", {}, dict(LEGIT))
    assert response.payload["decision"] == "ALLOW"


def test_evaluate_block_returns_findings(api):
    response = api.dispatch(
        "POST", "/api/guard/evaluate", {}, {"transaction": SUSPICIOUS, "return_authorization": True}
    )
    assert response.payload["decision"] == "BLOCK"
    codes = {f["code"] for f in response.payload["findings"]}
    assert "UNAPPROVED_DESTINATION" in codes
    assert "AMOUNT_EXCEEDS_LIMIT" in codes
    assert response.payload.get("authorization") is None
    assert response.payload["authorizes_signing"] is False


def test_evaluate_rejects_missing_fields(api):
    response = api.dispatch("POST", "/api/guard/evaluate", {}, {"transaction": {"service_id": "x"}})
    assert response.status == 400
    assert "error" in response.payload


def test_evaluate_rejects_a_non_object_body(api):
    assert api.dispatch("POST", "/api/guard/evaluate", {}, ["not", "an", "object"]).status == 400


def test_evaluate_rejects_a_float_amount(api):
    response = api.dispatch("POST", "/api/guard/evaluate", {}, {"transaction": dict(LEGIT, amount=1.5)})
    assert response.status == 400


def test_sign_executes_with_a_valid_token(api):
    evaluate = api.dispatch(
        "POST", "/api/guard/evaluate", {}, {"transaction": LEGIT, "return_authorization": True}
    )
    token = evaluate.payload["authorization"]
    response = api.dispatch(
        "POST", "/api/guard/sign", {}, {"transaction": LEGIT, "authorization": token}
    )
    assert response.status == 200
    assert response.payload["outcome"] == "EXECUTED"
    assert response.payload["simulated"] is True


def test_sign_refuses_without_an_authorization(api):
    response = api.dispatch("POST", "/api/guard/sign", {}, {"transaction": LEGIT, "authorization": None})
    assert response.payload["outcome"] == "REFUSED"
    assert response.payload["state"] == "MISSING"


def test_sign_refuses_a_replayed_token(api):
    evaluate = api.dispatch(
        "POST", "/api/guard/evaluate", {}, {"transaction": LEGIT, "return_authorization": True}
    )
    token = evaluate.payload["authorization"]
    first = api.dispatch("POST", "/api/guard/sign", {}, {"transaction": LEGIT, "authorization": token})
    second = api.dispatch("POST", "/api/guard/sign", {}, {"transaction": LEGIT, "authorization": token})
    assert first.payload["outcome"] == "EXECUTED"
    assert second.payload["outcome"] == "REFUSED"
    assert second.payload["state"] == "REPLAYED"


def test_sign_refuses_a_substituted_transaction(api):
    evaluate = api.dispatch(
        "POST", "/api/guard/evaluate", {}, {"transaction": LEGIT, "return_authorization": True}
    )
    token = evaluate.payload["authorization"]
    other = dict(LEGIT, destination=UNAPPROVED_DESTINATION)
    response = api.dispatch("POST", "/api/guard/sign", {}, {"transaction": other, "authorization": token})
    assert response.payload["outcome"] == "REFUSED"
    assert response.payload["state"] == "WRONG_PARAMETERS"


def test_sign_rejects_a_missing_transaction(api):
    assert api.dispatch("POST", "/api/guard/sign", {}, {"authorization": None}).status == 400


def test_sign_binds_expected_service_to_the_authenticated_caller():
    """A body-supplied expected_service_id cannot override the authenticated identity.

    Without service auth (loopback) the body value is honoured; with an
    authenticated caller the credential wins, so a caller cannot make the signer
    validate (or attribute a refusal) against a service it is not.
    """
    api = GuardAPI(make_service())
    evaluate = api.dispatch(
        "POST", "/api/guard/evaluate", {}, {"transaction": LEGIT, "return_authorization": True}
    )
    token = evaluate.payload["authorization"]
    # Authenticated as 'treasury-agent' (the token's service), but the body claims
    # to expect a *different* service. The credential must win, so this is ALLOWed.
    response = api.dispatch(
        "POST",
        "/api/guard/sign",
        {},
        {"transaction": LEGIT, "authorization": token, "expected_service_id": "someone-else"},
        authenticated_service_id="treasury-agent",
    )
    assert response.payload["outcome"] == "EXECUTED"
    assert response.payload["service_id"] == "treasury-agent"


def test_sign_refusal_is_attributed_to_the_authenticated_caller():
    """A refusal under an authenticated caller is counted against the caller."""
    api = GuardAPI(make_service())
    response = api.dispatch(
        "POST",
        "/api/guard/sign",
        {},
        {
            "transaction": dict(LEGIT, service_id="attacker-service"),
            "authorization": {
                "version": "ts-auth-v1",
                "authorization_id": "auth_forged",
                "decision_id": "dec_forged",
                "service_id": "treasury-agent",
                "key_id": "test-key",
                "nonce": "n",
                "issued_at": "2026-01-01T00:00:00Z",
                "expires_at": "2030-01-01T00:00:00Z",
                "fingerprint": "x",
                "parameters": {},
                "signature": "00" * 32,
            },
        },
        authenticated_service_id="attacker-service",
    )
    assert response.payload["outcome"] == "REFUSED"
    assert response.payload["service_id"] == "attacker-service"


def test_policy_endpoint_returns_the_policy(api):
    response = api.dispatch("GET", "/api/guard/policy", {}, None)
    assert response.status == 200
    assert response.payload["policy"]["policy_id"]


def test_metrics_endpoint(api):
    response = api.dispatch("GET", "/api/guard/metrics", {}, None)
    assert response.status == 200
    assert "counts" in response.payload


def test_incidents_endpoint_and_filter_validation(api):
    api.dispatch("POST", "/api/guard/evaluate", {}, {"transaction": SUSPICIOUS})
    ok = api.dispatch("GET", "/api/guard/incidents", {"status": "OPEN"}, None)
    assert ok.status == 200
    assert ok.payload["incidents"]
    bad = api.dispatch("GET", "/api/guard/incidents", {"status": "NOPE"}, None)
    assert bad.status == 400


def test_incident_limit_is_bounded(api):
    assert api.dispatch("GET", "/api/guard/incidents", {"limit": "100000"}, None).status == 400
    assert api.dispatch("GET", "/api/guard/incidents", {"limit": "abc"}, None).status == 400


def test_incident_status_update(api):
    api.dispatch("POST", "/api/guard/evaluate", {}, {"transaction": SUSPICIOUS})
    incident = api.dispatch("GET", "/api/guard/incidents", {}, None).payload["incidents"][0]
    path = f"/api/guard/incidents/{incident['incident_id']}/status"
    response = api.dispatch("POST", path, {}, {"status": "ACKNOWLEDGED"})
    assert response.status == 200
    assert response.payload["incident"]["status"] == IncidentStatus.ACKNOWLEDGED.value


def test_incident_status_update_validates_input(api):
    assert api.dispatch("POST", "/api/guard/incidents/x/status", {}, {"status": "BOGUS"}).status == 400
    assert api.dispatch("POST", "/api/guard/incidents/x/status", {}, {}).status == 400
    assert api.dispatch("POST", "/api/guard/incidents/nope/status", {}, {"status": "OPEN"}).status == 404


def test_audit_endpoint_can_verify(api):
    api.dispatch("POST", "/api/guard/evaluate", {}, {"transaction": LEGIT})
    response = api.dispatch("GET", "/api/guard/audit", {"verify": "1"}, None)
    assert response.payload["verification"]["ok"] is True
    assert response.payload["records"]


def test_scenarios_endpoint_is_labelled_as_simulation(api):
    response = api.dispatch("GET", "/api/guard/scenarios", {}, None)
    assert response.status == 200
    assert response.payload["note"] == SIMULATION_NOTE
    assert "simulation" in response.payload["note"].lower()
    ids = {s["id"] for s in response.payload["scenarios"]}
    assert ids == {"legitimate_transfer", "suspicious_transfer", "authorization_bypass"}


def test_scenarios_are_runnable_end_to_end(api):
    scenarios = api.dispatch("GET", "/api/guard/scenarios", {}, None).payload["scenarios"]
    by_id = {s["id"]: s for s in scenarios}

    legit = by_id["legitimate_transfer"]
    evaluated = api.dispatch(
        "POST",
        "/api/guard/evaluate",
        {},
        {"transaction": legit["transaction"], "simulated": True, "return_authorization": True},
    )
    assert evaluated.payload["decision"] == legit["expected_decision"]
    signed = api.dispatch(
        "POST",
        "/api/guard/sign",
        {},
        {"transaction": legit["transaction"], "authorization": evaluated.payload["authorization"]},
    )
    assert signed.payload["outcome"] == "EXECUTED"
    assert signed.payload["simulated"] is True

    suspicious = by_id["suspicious_transfer"]
    blocked = api.dispatch(
        "POST", "/api/guard/evaluate", {}, {"transaction": suspicious["transaction"], "simulated": True}
    )
    assert blocked.payload["decision"] == suspicious["expected_decision"]
    refused = api.dispatch(
        "POST", "/api/guard/sign", {}, {"transaction": suspicious["transaction"], "authorization": None}
    )
    assert refused.payload["outcome"] == "REFUSED"

    bypass = by_id["authorization_bypass"]
    bypass_eval = api.dispatch(
        "POST",
        "/api/guard/evaluate",
        {},
        {"transaction": bypass["transaction"], "simulated": True, "return_authorization": True},
    )
    no_token = api.dispatch(
        "POST", "/api/guard/sign", {}, {"transaction": bypass["transaction"], "authorization": None}
    )
    assert no_token.payload["outcome"] == "REFUSED"
    other = dict(bypass["transaction"], destination=APPROVED_DESTINATION, amount="42")
    substituted = api.dispatch(
        "POST",
        "/api/guard/sign",
        {},
        {"transaction": other, "authorization": bypass_eval.payload["authorization"]},
    )
    assert substituted.payload["outcome"] == "REFUSED"
    assert substituted.payload["state"] == "WRONG_PARAMETERS"


def test_unknown_route_is_404(api):
    assert api.dispatch("GET", "/api/guard/nope", {}, None).status == 404
    assert api.dispatch("POST", "/api/guard/nope", {}, {}).status == 404


def test_unsupported_method_is_405(api):
    assert api.dispatch("DELETE", "/api/guard/policy", {}, None).status == 405


def test_authorization_is_never_returned_for_a_block(api):
    response = api.dispatch(
        "POST", "/api/guard/evaluate", {}, {"transaction": SUSPICIOUS, "return_authorization": True}
    )
    assert "authorization" not in response.payload or response.payload["authorization"] is None


def test_client_asserted_flag_is_reported_not_honoured(api):
    response = api.dispatch(
        "POST", "/api/guard/evaluate", {}, {"transaction": dict(LEGIT, approved=True)}
    )
    assert response.payload["decision"] != "ALLOW"
    codes = {f["code"] for f in response.payload["findings"]}
    assert "CLIENT_ASSERTED_APPROVAL_IGNORED" in codes


def test_request_payload_helper_rejects_bad_identifiers():
    from tracesettle.guard.service import RequestValidationError, request_from_payload

    with pytest.raises(RequestValidationError):
        request_from_payload({"service_id": "has spaces", "operation": "X", "chain": "eth",
                              "asset": "USDC", "amount": "1", "destination": "d"})
    with pytest.raises(RequestValidationError):
        request_from_payload({"service_id": "s", "operation": "X", "chain": "eth",
                              "asset": "USDC", "amount": "-5", "destination": "d"})


def test_request_payload_records_only_field_names_for_extras():
    from tracesettle.guard.service import request_from_payload

    request = request_from_payload(
        dict(LEGIT, secret_note="do not store this value", extra="x")
    )
    assert request.metadata["unrecognised_fields"] == ["extra", "secret_note"]
    assert "do not store this value" not in repr(request.to_dict())


def test_request_payload_generates_a_reference_when_absent():
    from tracesettle.guard.service import request_from_payload

    payload = {k: v for k, v in LEGIT.items() if k != "request_id"}
    request = request_from_payload(payload)
    assert request.request_id.startswith("req_")
