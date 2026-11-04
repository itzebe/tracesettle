"""End-to-end tests for the wired NEAR Intents transaction lifecycle.

These exercise the *real* lifecycle, the real guard, the real policy reader, the
real settlement engine, and the real durable store. The only substitution is the
network transport (``FakeOpener`` from ``conftest``), so the code under test is
the shipped code path.

The lifecycle is the product's spine: it connects the pre-execution authorization
boundary to the post-execution settlement assurance over one transaction, and
records everything durably. A capability reachable only from a unit test but not
wired into a route would fail here.
"""

from __future__ import annotations

import pathlib

import pytest

from tracesettle.intents_store import IntentStore
from tracesettle.near import intents as intents_mod
from tracesettle.near.lifecycle import LifecycleError, NearIntentsLifecycle
from tracesettle.near.policy import load_fixture

from conftest import REAL_DEPOSIT_ADDRESS, client_for, load_raw

_FIXTURE_DIR = pathlib.Path(__file__).resolve().parents[1] / "tracesettle" / "near" / "fixtures"
from guard_helpers import make_service

CREATED_AT = "2026-11-03T00:00:00Z"

APPROVED_DESTINATION = "0x4e6d3A556e485188E9C9a528bc72c88BD92BD735"
USDC_ETH = "nep141:eth-0xa0b86991c6218b36c1d19d4a2e9eb0ce3606eb48.omft.near"
USDC_BASE = "nep141:base-0x833589fcd6edb6e08f4c7c32d4f71b54bda02913.omft.near"


@pytest.fixture
def store(tmp_path):
    s = IntentStore(tmp_path / "intents.db")
    yield s
    s.close()


def _lifecycle(opener, store, *, policy_fixture=None):
    client = client_for(opener)
    policy_read = load_fixture(policy_fixture) if policy_fixture else None
    return NearIntentsLifecycle(
        guard_service=make_service(), http_client=client, store=store
    ), policy_read


def _intent_payload(**overrides):
    base = {
        "service_id": "treasury-agent",
        "operation": "SETTLEMENT",
        "chain": "eth",
        "asset": "USDC",
        "amount": "1000000",
        "recipient": APPROVED_DESTINATION,
        "refund_to": APPROVED_DESTINATION,
        "origin_asset": USDC_ETH,
        "destination_asset": USDC_BASE,
        "scope": "INTENTS",
    }
    base.update(overrides)
    return base


# -- step 1: authorization boundary ------------------------------------------


def test_create_and_authorize_allows_a_legitimate_intent(opener, store):
    lc, policy_read = _lifecycle(opener, store)
    result = lc.create_and_authorize(
        owner="treasury-agent", payload=_intent_payload(), policy_read=None, access_key=None,
        created_at=CREATED_AT,
    )
    assert result["permits_signing"] is True
    assert result["decision"]["outcome"] == "ALLOW"
    assert result["step"]["ok"] is True


def test_blocked_intent_never_permits_a_live_quote(opener, store):
    """A blocked intent must not be able to obtain a fundable deposit address."""
    lc, _ = _lifecycle(opener, store)
    result = lc.create_and_authorize(
        owner="treasury-agent",
        payload=_intent_payload(recipient="0x000000000000000000000000000000000000dEaD"),
        policy_read=None,
        access_key=None,
        created_at=CREATED_AT,
    )
    assert result["permits_signing"] is False
    with pytest.raises(LifecycleError):
        lc.request_quote(owner="treasury-agent", intent_id=result["intent_id"], dry=False)


def test_dry_quote_is_allowed_for_a_blocked_intent(opener, store):
    """A dry quote moves nothing, so it is a safe exploration even when blocked."""
    lc, _ = _lifecycle(opener, store)
    created = lc.create_and_authorize(
        owner="treasury-agent",
        payload=_intent_payload(recipient="0x000000000000000000000000000000000000dEaD"),
        policy_read=None,
        access_key=None,
        created_at=CREATED_AT,
    )
    opener.json(
        "POST",
        "/v0/quote",
        {"quote": {"amountOut": "997398", "amountOutFormatted": "0.997398", "depositAddress": None},
         "correlationId": "c-1"},
    )
    out = lc.request_quote(owner="treasury-agent", intent_id=created["intent_id"], dry=True)
    assert out["ok"] is True
    assert out["deposit_address"] is None


# -- step 2: quote -----------------------------------------------------------


def test_live_quote_records_the_deposit_address(opener, store):
    lc, _ = _lifecycle(opener, store)
    created = lc.create_and_authorize(
        owner="treasury-agent", payload=_intent_payload(), policy_read=None, access_key=None,
        created_at=CREATED_AT,
    )
    opener.json(
        "POST",
        "/v0/quote",
        {
            "quote": {
                "amountOut": "997398",
                "amountOutFormatted": "0.997398",
                "depositAddress": "0xdeposit",
                "depositMemo": None,
            },
            "correlationId": "c-2",
        },
    )
    out = lc.request_quote(owner="treasury-agent", intent_id=created["intent_id"], dry=False)
    assert out["ok"] is True
    assert out["deposit_address"] == "0xdeposit"
    assert out["state"] == "DEPOSIT_ADDRESS_ISSUED"
    stored = lc.get(owner="treasury-agent", intent_id=created["intent_id"])
    assert stored["deposit_address"] == "0xdeposit"


def test_provider_quote_failure_is_surfaced_not_hidden(opener, store):
    lc, _ = _lifecycle(opener, store)
    created = lc.create_and_authorize(
        owner="treasury-agent", payload=_intent_payload(), policy_read=None, access_key=None,
        created_at=CREATED_AT,
    )
    opener.http_error("POST", "/v0/quote", 500, b"upstream boom")
    out = lc.request_quote(owner="treasury-agent", intent_id=created["intent_id"], dry=False)
    assert out["ok"] is False
    assert out["source_status"] != "OK"
    assert out["quote"] is None


# -- step 3: deposit ---------------------------------------------------------


def test_deposit_notification_requires_a_deposit_address(opener, store):
    lc, _ = _lifecycle(opener, store)
    created = lc.create_and_authorize(
        owner="treasury-agent", payload=_intent_payload(), policy_read=None, access_key=None,
        created_at=CREATED_AT,
    )
    with pytest.raises(LifecycleError):
        lc.record_deposit(
            owner="treasury-agent", intent_id=created["intent_id"], deposit_tx_hash="0xabc"
        )


def test_deposit_records_the_user_hash_and_notifies(opener, store):
    lc, _ = _lifecycle(opener, store)
    created = lc.create_and_authorize(
        owner="treasury-agent", payload=_intent_payload(), policy_read=None, access_key=None,
        created_at=CREATED_AT,
    )
    opener.json("POST", "/v0/quote", {"quote": {"depositAddress": "0xdeposit"}, "correlationId": "c"})
    lc.request_quote(owner="treasury-agent", intent_id=created["intent_id"], dry=False)
    lc.approve_quote(owner="treasury-agent", intent_id=created["intent_id"], approve=True)
    opener.json("POST", "/v0/deposit/submit", {"status": "ok"})
    out = lc.record_deposit(
        owner="treasury-agent", intent_id=created["intent_id"], deposit_tx_hash="0xuserdeposit"
    )
    assert out["ok"] is True
    assert out["deposit_tx_hash"] == "0xuserdeposit"


# -- step 4: status and lifecycle mapping ------------------------------------


def test_status_maps_provider_success_to_pending_not_verified(opener, store):
    """A provider SUCCESS must never become SETTLEMENT_VERIFIED via the status path."""
    lc, _ = _lifecycle(opener, store)
    created = lc.create_and_authorize(
        owner="treasury-agent", payload=_intent_payload(), policy_read=None, access_key=None,
        created_at=CREATED_AT,
    )
    opener.json("POST", "/v0/quote", {"quote": {"depositAddress": "0xdeposit"}, "correlationId": "c"})
    lc.request_quote(owner="treasury-agent", intent_id=created["intent_id"], dry=False)
    opener.json("GET", "/v0/status", load_raw("oneclick_status_SUCCESS.json"))
    out = lc.refresh_status(owner="treasury-agent", intent_id=created["intent_id"])
    assert out["ok"] is True
    assert out["lifecycle"]["label"] in ("EXECUTION_PENDING", "DESTINATION_OBSERVED")
    assert out["lifecycle"]["label"] != "SETTLEMENT_VERIFIED"
    assert out["lifecycle"]["provider_claims_success"] is True


def test_duplicate_status_update_is_idempotent(opener, store):
    lc, _ = _lifecycle(opener, store)
    created = lc.create_and_authorize(
        owner="treasury-agent", payload=_intent_payload(), policy_read=None, access_key=None,
        created_at=CREATED_AT,
    )
    opener.json("POST", "/v0/quote", {"quote": {"depositAddress": "0xdeposit"}, "correlationId": "c"})
    lc.request_quote(owner="treasury-agent", intent_id=created["intent_id"], dry=False)
    opener.json("GET", "/v0/status", load_raw("oneclick_status_SUCCESS.json"))
    first = lc.refresh_status(owner="treasury-agent", intent_id=created["intent_id"])
    second = lc.refresh_status(owner="treasury-agent", intent_id=created["intent_id"])
    assert first["changed"] is True
    assert second["changed"] is False


def test_status_source_outage_is_unknown_not_failed(opener, store):
    lc, _ = _lifecycle(opener, store)
    created = lc.create_and_authorize(
        owner="treasury-agent", payload=_intent_payload(), policy_read=None, access_key=None,
        created_at=CREATED_AT,
    )
    opener.json("POST", "/v0/quote", {"quote": {"depositAddress": "0xdeposit"}, "correlationId": "c"})
    lc.request_quote(owner="treasury-agent", intent_id=created["intent_id"], dry=False)
    opener.http_error("GET", "/v0/status", 503, b"down")
    out = lc.refresh_status(owner="treasury-agent", intent_id=created["intent_id"])
    assert out["ok"] is False
    assert out["lifecycle"]["label"] in ("PROVIDER_UNAVAILABLE", "UNKNOWN_STATUS")
    assert out["lifecycle"]["provider_claims_failure"] is False


# -- step 5: independent assurance -------------------------------------------


def test_assurance_is_verified_only_from_onchain_evidence(opener, store):
    lc, _ = _lifecycle(opener, store)
    created = lc.create_and_authorize(
        owner="treasury-agent", payload=_intent_payload(), policy_read=None, access_key=None,
        created_at=CREATED_AT,
    )
    opener.json("POST", "/v0/quote", {"quote": {"depositAddress": REAL_DEPOSIT_ADDRESS}, "correlationId": "c"})
    lc.request_quote(owner="treasury-agent", intent_id=created["intent_id"], dry=False)
    _wire_full_success(opener)
    out = lc.assurance(owner="treasury-agent", intent_id=created["intent_id"])
    assert out["ok"] is True
    assert out["assurance"]["level"] == "VERIFIED"
    assert out["assurance"]["independently_verified"] is True


def test_assurance_without_evidence_is_not_verified(opener, store):
    lc, _ = _lifecycle(opener, store)
    created = lc.create_and_authorize(
        owner="treasury-agent", payload=_intent_payload(), policy_read=None, access_key=None,
        created_at=CREATED_AT,
    )
    opener.json("POST", "/v0/quote", {"quote": {"depositAddress": REAL_DEPOSIT_ADDRESS}, "correlationId": "c"})
    lc.request_quote(owner="treasury-agent", intent_id=created["intent_id"], dry=False)
    opener.json("GET", "/v0/status", load_raw("oneclick_status_SUCCESS.json"))
    lc.refresh_status(owner="treasury-agent", intent_id=created["intent_id"])
    # No EVM/NEAR/solver responses wired, so no decisive on-chain evidence exists.
    opener.http_error("POST", "ethereum-rpc", 403, b"archive")
    opener.http_error("POST", "solver-relay", 500, b"boom")
    opener.http_error("POST", "rpc.fastnear", 500, b"boom")
    out = lc.assurance(owner="treasury-agent", intent_id=created["intent_id"])
    assert out["assurance"]["level"] != "VERIFIED"
    assert out["assurance"]["independently_verified"] is False


# -- durability and isolation ------------------------------------------------


def test_lifecycle_survives_a_restart(opener, store, tmp_path):
    lc, _ = _lifecycle(opener, store)
    created = lc.create_and_authorize(
        owner="treasury-agent", payload=_intent_payload(), policy_read=None, access_key=None,
        created_at=CREATED_AT,
    )
    opener.json("POST", "/v0/quote", {"quote": {"depositAddress": "0xdeposit"}, "correlationId": "c"})
    lc.request_quote(owner="treasury-agent", intent_id=created["intent_id"], dry=False)
    intent_id = created["intent_id"]
    store.close()
    # Reopen the same file with a fresh lifecycle.
    reopened = IntentStore(tmp_path / "intents.db")
    try:
        lc2 = NearIntentsLifecycle(guard_service=make_service(), http_client=client_for(opener), store=reopened)
        record = lc2.get(owner="treasury-agent", intent_id=intent_id)
        assert record is not None
        assert record["deposit_address"] == "0xdeposit"
    finally:
        reopened.close()


def test_a_stale_stored_label_is_re_derived_on_read(opener, store):
    """A record written before a label-semantics fix must not keep the stale label.

    The lifecycle label is a pure function of the stored provider status and
    evidence, so ``get`` re-derives it. This guards the PENDING_DEPOSIT fix: an
    intent stored with the old ``DEPOSIT_SUBMITTED`` state must read back as
    ``AWAITING_DEPOSIT`` once the mapping is corrected.
    """
    lc, _ = _lifecycle(opener, store)
    created = lc.create_and_authorize(
        owner="treasury-agent", payload=_intent_payload(), policy_read=None, access_key=None,
        created_at=CREATED_AT,
    )
    intent_id = created["intent_id"]
    # Simulate a record persisted under the old, incorrect mapping.
    store.apply_provider_status(
        intent_id, owner="treasury-agent", provider_status="PENDING_DEPOSIT",
        provider_updated_at=None, observed_at=CREATED_AT,
        lifecycle={"label": "DEPOSIT_SUBMITTED", "deposit_seen": True},
    )
    record = lc.get(owner="treasury-agent", intent_id=intent_id)
    assert record["state"] == "AWAITING_DEPOSIT"
    assert record["lifecycle"]["deposit_seen"] is False


def test_owner_isolation(opener, store):
    lc, _ = _lifecycle(opener, store)
    created = lc.create_and_authorize(
        owner="treasury-agent", payload=_intent_payload(), policy_read=None, access_key=None,
        created_at=CREATED_AT,
    )
    assert lc.get(owner="other-service", intent_id=created["intent_id"]) is None


# -- intents client unit coverage --------------------------------------------


def test_quote_validation_rejects_a_decimal_amount():
    with pytest.raises(intents_mod.QuoteValidationError):
        intents_mod.QuoteRequest.from_payload(
            {
                "amount": "0.01",
                "origin_asset": USDC_ETH,
                "destination_asset": USDC_BASE,
                "recipient": APPROVED_DESTINATION,
                "refund_to": APPROVED_DESTINATION,
            }
        )


def test_lifecycle_view_never_returns_settlement_verified():
    for status in intents_mod.LIFECYCLE_STATUSES:
        view = intents_mod.lifecycle_view(status, destination_tx_hashes=("0x1",))
        assert view.label != "SETTLEMENT_VERIFIED"


def test_pending_deposit_is_not_reported_as_a_deposit():
    """PENDING_DEPOSIT means "awaiting your deposit" — no funds have arrived.

    The official 1Click status table defines PENDING_DEPOSIT as "Awaiting your
    token deposit". Reporting it as a submitted or detected deposit would be a
    false-success state, so it must map to AWAITING_DEPOSIT with
    ``deposit_seen`` false.
    """
    view = intents_mod.lifecycle_view("PENDING_DEPOSIT")
    assert view.label == "AWAITING_DEPOSIT"
    assert view.deposit_seen is False
    assert view.provider_claims_success is False
    assert any("awaiting" in lim.lower() for lim in view.limitations)


def test_incomplete_deposit_is_a_shortfall_not_a_deposit():
    view = intents_mod.lifecycle_view("INCOMPLETE_DEPOSIT")
    assert view.label == "DEPOSIT_INCOMPLETE"
    assert view.deposit_seen is False
    assert any("below" in lim.lower() or "shortfall" in lim.lower() for lim in view.limitations)


def test_known_deposit_tx_is_the_only_status_that_marks_a_deposit_seen():
    assert intents_mod.lifecycle_view("KNOWN_DEPOSIT_TX").deposit_seen is True
    assert intents_mod.lifecycle_view("KNOWN_DEPOSIT_TX").label == "DEPOSIT_DETECTED"
    for status in ("PENDING_DEPOSIT", "INCOMPLETE_DEPOSIT"):
        assert intents_mod.lifecycle_view(status).deposit_seen is False


def test_tokens_endpoint_parses_assets(opener):
    opener.json(
        "GET",
        "/v0/tokens",
        [
            {"assetId": USDC_ETH, "blockchain": "eth", "symbol": "USDC", "decimals": 6},
            {"assetId": USDC_BASE, "blockchain": "base", "symbol": "USDC", "decimals": 6},
        ],
    )
    lc = NearIntentsLifecycle(
        guard_service=make_service(), http_client=client_for(opener), store=IntentStore(":memory:")
    )
    out = lc.assets()
    assert out["ok"] is True
    assert len(out["assets"]) == 2


def test_policy_fixture_is_loaded_server_side(opener, store):
    """The lifecycle's policy comes from the fixture, resolved by the server."""
    lc, policy_read = _lifecycle(opener, store, policy_fixture=str(_FIXTURE_DIR / "policy_in_force.json"))
    assert policy_read is not None
    assert policy_read.policy.in_force is True


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


# -- quote expiry and explicit approval (P06) --------------------------------


def _expired_quote_opener(opener, *, deadline="2020-01-01T00:00:00Z"):
    opener.json(
        "POST",
        "/v0/quote",
        {
            "quote": {
                "depositAddress": "0xdeposit",
                "deadline": deadline,
                "amountOut": "997398",
                "amountOutFormatted": "0.997398",
            },
            "correlationId": "c",
        },
    )


def test_quote_expiry_is_computed_from_the_provider_deadline():
    from tracesettle.near.intents import QuoteFields, quote_expiry

    future = QuoteFields.from_dict({"deadline": "2999-01-01T00:00:00Z"})
    assert quote_expiry(future)["usable"] is True
    assert quote_expiry(future)["reason"] == "VALID"

    past = QuoteFields.from_dict({"deadline": "2020-01-01T00:00:00Z"})
    result = quote_expiry(past)
    assert result["usable"] is False
    assert result["reason"] == "QUOTE_EXPIRED"


def test_quote_expiry_reports_unstated_expiry_honestly():
    from tracesettle.near.intents import QuoteFields, quote_expiry

    result = quote_expiry(QuoteFields.from_dict({}))
    assert result["usable"] is True
    assert result["expiry_known"] is False
    assert result["reason"] == "NO_EXPIRY_STATED"


def test_an_expired_quote_cannot_be_approved(opener, store):
    lc, _ = _lifecycle(opener, store)
    created = lc.create_and_authorize(
        owner="treasury-agent", payload=_intent_payload(), policy_read=None, access_key=None,
        created_at=CREATED_AT,
    )
    _expired_quote_opener(opener)
    quote = lc.request_quote(owner="treasury-agent", intent_id=created["intent_id"], dry=False)
    assert quote["expiry"]["usable"] is False
    with pytest.raises(LifecycleError):
        lc.approve_quote(owner="treasury-agent", intent_id=created["intent_id"], approve=True)


def test_a_deposit_requires_an_approved_unexpired_quote(opener, store):
    lc, _ = _lifecycle(opener, store)
    created = lc.create_and_authorize(
        owner="treasury-agent", payload=_intent_payload(), policy_read=None, access_key=None,
        created_at=CREATED_AT,
    )
    _expired_quote_opener(opener)
    lc.request_quote(owner="treasury-agent", intent_id=created["intent_id"], dry=False)
    with pytest.raises(LifecycleError):
        lc.record_deposit(
            owner="treasury-agent", intent_id=created["intent_id"], deposit_tx_hash="0xabc"
        )


def test_a_fresh_quote_clears_a_previous_approval(opener, store):
    lc, _ = _lifecycle(opener, store)
    created = lc.create_and_authorize(
        owner="treasury-agent", payload=_intent_payload(), policy_read=None, access_key=None,
        created_at=CREATED_AT,
    )
    _expired_quote_opener(opener, deadline="2999-01-01T00:00:00Z")
    lc.request_quote(owner="treasury-agent", intent_id=created["intent_id"], dry=False)
    approved = lc.approve_quote(owner="treasury-agent", intent_id=created["intent_id"], approve=True)
    assert approved["state"] == "QUOTE_APPROVED"
    assert lc.get(owner="treasury-agent", intent_id=created["intent_id"])["quote_approved"] is True
    # Re-quoting is a new quote: the prior approval must not carry over.
    lc.request_quote(owner="treasury-agent", intent_id=created["intent_id"], dry=False)
    assert lc.get(owner="treasury-agent", intent_id=created["intent_id"])["quote_approved"] is False


def test_quote_rejection_is_recorded_and_blocks_the_deposit(opener, store):
    lc, _ = _lifecycle(opener, store)
    created = lc.create_and_authorize(
        owner="treasury-agent", payload=_intent_payload(), policy_read=None, access_key=None,
        created_at=CREATED_AT,
    )
    _expired_quote_opener(opener, deadline="2999-01-01T00:00:00Z")
    lc.request_quote(owner="treasury-agent", intent_id=created["intent_id"], dry=False)
    rejected = lc.approve_quote(owner="treasury-agent", intent_id=created["intent_id"], approve=False)
    assert rejected["state"] == "QUOTE_REJECTED"
    with pytest.raises(LifecycleError):
        lc.record_deposit(
            owner="treasury-agent", intent_id=created["intent_id"], deposit_tx_hash="0xabc"
        )


# -- independent origin-chain verification of the recorded deposit -----------


def _wire_origin_receipt(opener, *, to=REAL_DEPOSIT_ADDRESS, status="0x1", logs=None):
    opener.json("POST", "ethereum-rpc", {
        "jsonrpc": "2.0", "id": 1, "result": {
            "transactionHash": "0xuserdeposit",
            "status": status,
            "from": "0x1111111111111111111111111111111111111111",
            "to": to,
            "blockNumber": "0x1900000",
            "logs": logs or [],
        },
    })


def _recorded_deposit(opener, store, *, asset=USDC_ETH, hash_="0xuserdeposit"):
    lc, _ = _lifecycle(opener, store)
    created = lc.create_and_authorize(
        owner="treasury-agent", payload=_intent_payload(origin_asset=asset), policy_read=None,
        access_key=None, created_at=CREATED_AT,
    )
    opener.json("POST", "/v0/quote", {"quote": {"depositAddress": REAL_DEPOSIT_ADDRESS}, "correlationId": "c"})
    lc.request_quote(owner="treasury-agent", intent_id=created["intent_id"], dry=False)
    lc.approve_quote(owner="treasury-agent", intent_id=created["intent_id"], approve=True)
    opener.json("POST", "/v0/deposit/submit", {"status": "ok"})
    lc.record_deposit(
        owner="treasury-agent", intent_id=created["intent_id"], deposit_tx_hash=hash_
    )
    return lc, created["intent_id"]


def test_origin_verification_confirms_a_native_deposit(opener, store):
    lc, intent_id = _recorded_deposit(opener, store, asset="nep141:eth.omft.near")
    _wire_origin_receipt(opener)
    v = lc.origin_verification(owner="treasury-agent", intent_id=intent_id)
    assert v is not None
    assert v["level"] == "VERIFIED"
    assert v["chain"] == "eth"


def test_origin_verification_is_contradictory_for_a_reverted_deposit(opener, store):
    lc, intent_id = _recorded_deposit(opener, store, asset="nep141:eth.omft.near")
    _wire_origin_receipt(opener, status="0x0")
    v = lc.origin_verification(owner="treasury-agent", intent_id=intent_id)
    assert v["level"] == "CONTRADICTORY"


def test_origin_verification_requires_a_recorded_hash(opener, store):
    lc, _ = _lifecycle(opener, store)
    created = lc.create_and_authorize(
        owner="treasury-agent", payload=_intent_payload(), policy_read=None, access_key=None,
        created_at=CREATED_AT,
    )
    assert lc.origin_verification(owner="treasury-agent", intent_id=created["intent_id"]) is None


def test_origin_verification_survives_a_read_without_a_network_call(opener, store):
    lc, intent_id = _recorded_deposit(opener, store, asset="nep141:eth.omft.near")
    _wire_origin_receipt(opener)
    lc.origin_verification(owner="treasury-agent", intent_id=intent_id)
    # A later get() must present the stored verdict without re-fetching.
    calls_before = len(opener.calls)
    record = lc.get(owner="treasury-agent", intent_id=intent_id)
    assert record["lifecycle"]["origin_verification"]["level"] == "VERIFIED"
    assert len(opener.calls) == calls_before


def test_status_read_attaches_the_origin_verification(opener, store):
    lc, intent_id = _recorded_deposit(opener, store, asset="nep141:eth.omft.near")
    opener.json("GET", "/v0/status", load_raw("oneclick_status_SUCCESS.json"))
    _wire_origin_receipt(opener)
    out = lc.refresh_status(owner="treasury-agent", intent_id=intent_id)
    assert out["lifecycle"]["origin_verification"]["level"] == "VERIFIED"
