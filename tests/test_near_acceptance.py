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
from guard_helpers import make_service

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


def _get(url):
    try:
        with urllib.request.urlopen(url, timeout=10) as resp:
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


# --- real HTTP: the whole Intents lifecycle over a socket -------------------
#
# The lifecycle tests in ``test_near_lifecycle.py`` call the lifecycle object
# directly. That proves the lifecycle is correct, but not that the *routes* are
# wired to it: a route registered under a different path, gated by the wrong
# flag, or answered without a body would pass every direct-call test and fail in
# the product. These tests drive the real server over a real socket with the
# transport substituted, so the path, the gating and the serialization are all
# exercised end to end.


def _wire_lifecycle_quote(opener, *, deposit_address, dry=False):
    """A quote response for the lifecycle's ``POST /v0/quote`` call."""
    quote = {"amountIn": "1000000", "amountOut": "997398", "amountOutFormatted": "0.997398"}
    if not dry:
        quote["depositAddress"] = deposit_address
        quote["deadline"] = "2999-01-01T00:00:00Z"
    opener.json("POST", "/v0/quote", {"quote": quote, "correlationId": "c"})


def _lifecycle_payload(**overrides):
    base = {
        "service_id": "treasury-agent",
        "operation": "SETTLEMENT",
        "chain": "eth",
        "asset": "USDC",
        "amount": "1000000",
        "origin_asset": "nep141:eth-0xa0b86991c6218b36c1d19d4a2e9eb0ce3606eb48.omft.near",
        "destination_asset": "nep141:base-0x833589fcd6edb6e08f4c7c32d4f71b54bda02913.omft.near",
        "recipient": "0x4e6d3A556e485188E9C9a528bc72c88BD92BD735",
        "refund_to": "0x4e6d3A556e485188E9C9a528bc72c88BD92BD735",
        "swap_type": "EXACT_INPUT",
        "slippage_tolerance": 100,
    }
    base.update(overrides)
    return base


def _wire_opener_into_server(opener, monkeypatch):
    """Route the server's own ``HttpClient`` through the canned transport.

    The server builds its own client, so patch the module-level class the way
    ``test_http_investigate_response_includes_assurance`` does.
    """
    import tracesettle.ui as ui_module

    monkeypatch.setattr(
        ui_module,
        "HttpClient",
        lambda **kw: client_for(opener, attempts=1),
    )


def test_http_lifecycle_full_journey_over_a_socket(opener, monkeypatch, tmp_path):
    """Create -> authorize -> live quote -> approve -> status -> assurance, over HTTP.

    Every step is a real request to a real socket. The live quote issues a deposit
    address, the approval is recorded, the provider status is read, and the
    independent assurance is computed — none of it by calling the lifecycle
    object directly.
    """
    from tracesettle.intents_store import IntentStore
    from tracesettle.near.lifecycle import NearIntentsLifecycle

    store = IntentStore(tmp_path / "intents.db")
    _wire_opener_into_server(opener, monkeypatch)
    try:
        with running_server(lifecycle=NearIntentsLifecycle(
            guard_service=make_service(), http_client=client_for(opener), store=store
        )) as base:
            # 1. create + authorize (guard runs on the real parameters)
            status, created = _post(
                base + "/api/guard/near/lifecycle", {"transaction": _lifecycle_payload()}
            )
            assert status == 200, created
            assert created["decision"]["outcome"] == "ALLOW"
            assert created["permits_signing"] is True
            intent_id = created["intent_id"]

            # 2. live quote (only permitted because the decision permits signing)
            _wire_lifecycle_quote(opener, deposit_address=REAL_DEPOSIT_ADDRESS)
            status, quoted = _post(
                base + f"/api/guard/near/lifecycle/{intent_id}/quote", {"dry": False}
            )
            assert status == 200, quoted
            assert quoted["state"] == "DEPOSIT_ADDRESS_ISSUED"
            assert quoted["deposit_address"] == REAL_DEPOSIT_ADDRESS
            assert quoted["expiry"]["usable"] is True

            # 3. approve the live quote
            status, approved = _post(
                base + f"/api/guard/near/lifecycle/{intent_id}/approve", {"approve": True}
            )
            assert status == 200, approved
            assert approved["state"] == "QUOTE_APPROVED"

            # 4. read the provider status
            opener.json("GET", "/v0/status", load_raw("oneclick_status_SUCCESS.json"))
            status, refreshed = _post(
                base + f"/api/guard/near/lifecycle/{intent_id}/status", {}
            )
            assert status == 200, refreshed
            assert refreshed["provider_status"] == "SUCCESS"
            # A provider SUCCESS is a reported claim, never a verified settlement.
            assert refreshed["lifecycle"]["label"] != "SETTLEMENT_VERIFIED"

            # 5. independent assurance over real on-chain evidence
            _wire_full_success(opener)
            status, assurance = _post(
                base + f"/api/guard/near/lifecycle/{intent_id}/assurance", {}
            )
            assert status == 200, assurance
            assert assurance["assurance"]["level"] == "VERIFIED"
            assert assurance["assurance"]["independently_verified"] is True

            # 6. the record is retrievable and carries the durable event trail
            status, fetched = _get(base + f"/api/guard/near/lifecycle/{intent_id}")
            assert status == 200, fetched
            assert fetched["intent"]["deposit_address"] == REAL_DEPOSIT_ADDRESS
            assert fetched["intent"]["quote_approved"] is True
            kinds = [e["kind"] for e in fetched["intent"]["events"]]
            assert "DECISION" in kinds and "QUOTE" in kinds and "ASSURANCE" in kinds
    finally:
        store.close()


def test_http_lifecycle_refuses_a_live_quote_without_authorization(opener, monkeypatch, tmp_path):
    """A blocked intent must not obtain a fundable deposit address over HTTP.

    The destination is not approved, so the guard blocks the create. A live quote
    for that intent must be refused, and no quote request may reach the provider.
    """
    from tracesettle.intents_store import IntentStore
    from tracesettle.near.lifecycle import NearIntentsLifecycle

    store = IntentStore(tmp_path / "intents.db")
    _wire_opener_into_server(opener, monkeypatch)
    try:
        with running_server(lifecycle=NearIntentsLifecycle(
            guard_service=make_service(), http_client=client_for(opener), store=store
        )) as base:
            status, created = _post(
                base + "/api/guard/near/lifecycle",
                {"transaction": _lifecycle_payload(recipient="0xdeadbeefdeadbeefdeadbeefdeadbeefdeadbeef",
                                                   refund_to="0xdeadbeefdeadbeefdeadbeefdeadbeefdeadbeef")},
            )
            assert status == 200, created
            assert created["decision"]["outcome"] != "ALLOW"
            assert created["permits_signing"] is False

            status, quoted = _post(
                base + f"/api/guard/near/lifecycle/{created['intent_id']}/quote", {"dry": False}
            )
            # The route surfaces the refusal as a client error, not a deposit address.
            assert status == 400, quoted
            assert "deposit_address" not in quoted
    finally:
        store.close()


def test_http_lifecycle_routes_are_absent_without_the_flag(monkeypatch):
    """With the lifecycle disabled the routes must 404, not expose a journey."""
    monkeypatch.setattr("tracesettle.config.NEAR_LIFECYCLE_ENABLED", False)
    # An explicit ``lifecycle=None`` mirrors a server built without the flag.
    with running_server(lifecycle=None) as base:
        status, body = _post(base + "/api/guard/near/lifecycle", {"transaction": {}})
        assert status == 404
        assert "not enabled" in json.dumps(body)
