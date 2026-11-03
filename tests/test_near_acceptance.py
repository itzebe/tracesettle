"""Product-level acceptance: the NEAR capabilities must be *connected*.

The unit tests prove the NEAR modules behave correctly in isolation. These tests
prove the opposite and complementary property: the shipped application actually
uses them. Each test drives the real server (or the real report builder) over a
real investigation, so a capability that exists only as a library — reachable
from a unit test but not wired into a route — fails here.

Covered:

* the settlement assurance view is present in the real ``/api/investigate``
  report and in the rendered Markdown, and a provider success claim never raises
  the level on its own;
* the guard ``evaluate -> sign`` workflow executes a legitimate transaction and
  refuses a replayed authorization, over real HTTP;
* the NEAR agent-evaluate route returns a decision derived from real transaction
  parameters.
"""

from __future__ import annotations

import json
import threading
import urllib.error
import urllib.request
from contextlib import contextmanager

from tracesettle.investigation import build_result, investigate
from tracesettle.report import build_report
from tracesettle.ui import InvestigationServer

from conftest import REAL_DEPOSIT_ADDRESS, client_for, load_raw

CREATED_AT = "2026-11-03T00:00:00Z"


def _wire_full_success(opener):
    opener.json("GET", "/v0/status", load_raw("oneclick_status_SUCCESS.json"))
    opener.json("POST", "ethereum-rpc", load_raw("evm_receipt_origin.json"), once=True)
    opener.json("POST", "ethereum-rpc", load_raw("evm_receipt_destination.json"))
    opener.json("POST", "solver-relay", load_raw("solver_relay_get_status_SETTLED.json"))
    opener.json(
        "POST",
        "rpc.fastnear",
        load_raw("near_rpc_tx.json"),
        body_contains="5E3GdbhwUYj9RFXhkk3rMyPwom4xvMYjtCFj7i2uypFb",
    )
    opener.json(
        "POST",
        "rpc.fastnear",
        load_raw("near_rpc_tx_omft.json"),
        body_contains="FbrSoTHbQdwD6HxabhaozvQQVBA4kF2Qn2c3W2otp284",
    )
    return opener


# --- settlement assurance is connected to the report ------------------------


def test_report_carries_the_settlement_assurance_view(opener):
    """The report the product emits must contain the assurance, not just the engine result."""
    _wire_full_success(opener)
    inv = investigate(REAL_DEPOSIT_ADDRESS, client_for(opener))
    report = build_report(inv, build_result(inv), CREATED_AT)

    data = report.to_dict()
    assurance = data["settlement_assurance"]
    assert assurance is not None
    assert assurance["level"] == "VERIFIED"
    assert assurance["independently_verified"] is True
    assert assurance["provider_claimed_success"] is True
    # The assurance view names the settlement stages explicitly.
    names = [s["name"] for s in assurance["stages"]]
    assert names[:3] == ["deposit_address", "source_chain_transaction", "deposit_confirmation"]
    assert "intent_execution" in names
    assert "destination_receipt" in names


def test_markdown_report_renders_the_assurance_section(opener):
    _wire_full_success(opener)
    inv = investigate(REAL_DEPOSIT_ADDRESS, client_for(opener))
    md = build_report(inv, build_result(inv), CREATED_AT).to_markdown()
    assert "## Settlement assurance" in md
    assert "Assurance level" in md
    assert "Settlement stage" in md


def test_provider_success_without_evidence_is_not_verified(opener):
    """A provider SUCCESS with no decisive evidence must not become VERIFIED.

    Only the provider status is available; every on-chain lookup is absent. The
    engine cannot confirm a stage, so the assurance level must not be VERIFIED
    even though the provider claims SUCCESS.
    """
    opener.json("GET", "/v0/status", load_raw("oneclick_status_SUCCESS.json"))
    # Every on-chain source is unreachable, so no decisive evidence can exist.
    # A timeout short-circuits the endpoint list (only a definitive NOT_FOUND
    # tries a fallback), so no further host is contacted.
    opener.timeout("POST", "ethereum-rpc")
    opener.timeout("POST", "rpc.fastnear")
    opener.timeout("POST", "solver-relay")
    inv = investigate(REAL_DEPOSIT_ADDRESS, client_for(opener))
    report = build_report(inv, build_result(inv), CREATED_AT)

    assurance = report.to_dict()["settlement_assurance"]
    assert assurance["provider_claimed_success"] is True
    assert assurance["independently_verified"] is False
    assert assurance["level"] != "VERIFIED"


# --- real HTTP: the investigate route exposes the assurance -----------------


@contextmanager
def running_server(**kwargs):
    server = InvestigationServer(
        ("127.0.0.1", 0), timeout_seconds=5.0, max_attempts=1, **kwargs
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


def _post(url, payload):
    req = urllib.request.Request(
        url,
        data=json.dumps(payload).encode(),
        method="POST",
        headers={"Content-Type": "application/json"},
    )
    try:
        with urllib.request.urlopen(req, timeout=10) as resp:
            return resp.status, json.loads(resp.read())
    except urllib.error.HTTPError as e:  # pragma: no cover - surfaces a clear failure
        return e.code, json.loads(e.read())


def test_http_investigate_response_includes_assurance(opener):
    """The real route, not just the report builder, must expose the assurance.

    The server builds its own ``HttpClient``; patch the module-level opener so the
    route uses the canned transport, then assert the JSON body carries the field.
    """
    import tracesettle.ui as ui_module

    _wire_full_success(opener)
    original = ui_module.HttpClient
    ui_module.HttpClient = lambda **kw: client_for(opener, attempts=1)  # type: ignore[assignment]
    try:
        with running_server() as base:
            status, body = _post(base + "/api/investigate?format=full", {"identifier": REAL_DEPOSIT_ADDRESS})
    finally:
        ui_module.HttpClient = original  # type: ignore[assignment]

    assert status == 200
    data = body["data"]
    assert data["settlement_assurance"]["level"] == "VERIFIED"
    assert "## Settlement assurance" in body["markdown"]


# --- real HTTP: the guard evaluate -> sign workflow -------------------------


def test_http_guard_workflow_executes_then_refuses_replay():
    """A legitimate request is authorized and executed once; the same token is then refused."""
    with running_server() as base:
        transaction = {
            "service_id": "treasury-agent",
            "operation": "WITHDRAWAL",
            "chain": "eth",
            "asset": "USDC",
            "amount": "1250.50",
            "destination": "0x4e6d3A556e485188E9C9a528bc72c88BD92BD735",
        }
        status, decision = _post(
            base + "/api/guard/evaluate",
            {"transaction": transaction, "return_authorization": True},
        )
        assert status == 200
        assert decision["decision"] == "ALLOW"
        authorization = decision["authorization"]
        assert authorization is not None

        status, sign = _post(
            base + "/api/guard/sign",
            {
                "transaction": transaction,
                "authorization": authorization,
                "expected_service_id": "treasury-agent",
            },
        )
        assert status == 200
        assert sign["outcome"] == "EXECUTED"

        # Replaying the identical authorization must be refused.
        status, replay = _post(
            base + "/api/guard/sign",
            {
                "transaction": transaction,
                "authorization": authorization,
                "expected_service_id": "treasury-agent",
            },
        )
        assert status == 200
        assert replay["outcome"] != "EXECUTED"
        assert replay["state"] in {"REPLAYED", "REFUSED"}


def test_http_guard_refuses_transaction_changed_after_approval():
    """An authorization bound to one transaction must not release a different one."""
    with running_server() as base:
        original = {
            "service_id": "treasury-agent",
            "operation": "WITHDRAWAL",
            "chain": "eth",
            "asset": "USDC",
            "amount": "1250.50",
            "destination": "0x4e6d3A556e485188E9C9a528bc72c88BD92BD735",
        }
        _, decision = _post(
            base + "/api/guard/evaluate",
            {"transaction": original, "return_authorization": True},
        )
        authorization = decision["authorization"]
        tampered = dict(original, amount="99999.00")
        _, sign = _post(
            base + "/api/guard/sign",
            {
                "transaction": tampered,
                "authorization": authorization,
                "expected_service_id": "treasury-agent",
            },
        )
        assert sign["outcome"] != "EXECUTED"


def test_http_near_agent_evaluate_blocks_unapproved_destination():
    with running_server() as base:
        status, decision = _post(
            base + "/api/guard/near/agent-evaluate",
            {
                "transaction": {
                    "service_id": "treasury-agent",
                    "operation": "WITHDRAWAL",
                    "chain": "base",
                    "asset": "USDC",
                    "amount": "1250.50",
                    "destination": "0xdeadbeefdeadbeefdeadbeefdeadbeefdeadbeef",
                    "scope": "INTENTS",
                    "policy_action": "withdraw",
                }
            },
        )
        assert status == 200
        assert decision["outcome"] in {"BLOCK", "REQUIRE_APPROVAL", "HOLD", "UNKNOWN"}
        assert decision["permits_signing"] is False
