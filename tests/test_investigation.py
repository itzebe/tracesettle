"""End-to-end investigation tests: identifier -> evidence -> engine -> report.

These drive the real orchestrator and adapters with a fake transport, using the
real Phase 1 fixtures plus clearly-labelled synthetic fixtures.
"""

from __future__ import annotations

from tracesettle.identifiers import classify_identifier, validate_deposit_address
from tracesettle.investigation import build_result, investigate
from tracesettle.model import (
    IdentifierType,
    OverallOutcome,
    Provenance,
    SourceStatus,
    Stage,
    StageState,
    Verification,
)
from tracesettle.report import build_report

from conftest import (
    ev as make_ev,
    FakeOpener,
    REAL_DEPOSIT_ADDRESS,
    REAL_INTENT_HASH,
    REAL_ORIGIN_TX,
    client_for,
    load_raw,
    load_synthetic,
)

CREATED_AT = "2026-10-19T22:00:00Z"


def _wire_full_success(opener: FakeOpener) -> FakeOpener:
    """Wire every real fixture for the verified ETH -> USDC swap."""
    opener.json("GET", "/v0/status", load_raw("oneclick_status_SUCCESS.json"))
    opener.json("POST", "ethereum-rpc", load_raw("evm_receipt_origin.json"), once=True)
    opener.json("POST", "ethereum-rpc", load_raw("evm_receipt_destination.json"))
    opener.json("POST", "solver-relay", load_raw("solver_relay_get_status_SETTLED.json"))
    # NEAR RPC: first the intents tx (has the intent logs), then the bridge leg.
    opener.json("POST", "rpc.fastnear", load_raw("near_rpc_tx.json"), once=True)
    opener.json("POST", "rpc.fastnear", load_raw("near_rpc_tx_omft.json"))
    return opener


# --- Scenario 1: full successful investigation ------------------------------


def test_full_success_investigation(opener: FakeOpener):
    _wire_full_success(opener)
    inv = investigate(REAL_DEPOSIT_ADDRESS, client_for(opener))
    result = build_result(inv)

    assert inv.identifier_type is IdentifierType.DEPOSIT_ADDRESS
    assert result.outcome is OverallOutcome.SETTLED_VERIFIED
    assert result.last_confirmed_stage is Stage.DESTINATION_CHAIN_DELIVERY
    assert result.stage(Stage.SOURCE_CHAIN_DEPOSIT).state is StageState.CONFIRMED
    assert result.stage(Stage.NEAR_SETTLEMENT).state is StageState.CONFIRMED
    assert result.stage(Stage.DESTINATION_CHAIN_DELIVERY).state is StageState.CONFIRMED
    assert result.contradictions == ()

    # Correlation is via explicit identifiers only.
    intent_items = [
        e for e in inv.evidence if e.event_type.value == "INTENT_EVENT_OBSERVED"
    ]
    assert intent_items and REAL_INTENT_HASH in intent_items[0].details["intent_hashes"]


def test_full_success_report_is_exportable(opener: FakeOpener):
    _wire_full_success(opener)
    inv = investigate(REAL_DEPOSIT_ADDRESS, client_for(opener))
    report = build_report(inv, build_result(inv), CREATED_AT)

    data = report.to_dict()
    assert data["tool"]["read_only"] is True
    assert data["outcome"] == "SETTLED_VERIFIED"
    assert "cannot recover" in data["disclaimer"]
    assert data["evidence"]
    # Every evidence item has a classification and a source.
    for item in data["evidence"]:
        assert item["verification"] in {v.value for v in Verification}
        assert item["source"]
    # JSON and Markdown both render.
    assert "TRACESETTLE investigation report" in report.to_markdown()
    assert data["investigation_id"].startswith("ts-")


def test_report_contains_no_secrets(opener: FakeOpener):
    _wire_full_success(opener)
    inv = investigate(REAL_DEPOSIT_ADDRESS, client_for(opener))
    report = build_report(inv, build_result(inv), CREATED_AT)
    blob = report.to_json().lower()
    # No credential material or credential-bearing field names. (The disclaimer may
    # legitimately *mention* private keys; that is a statement about behaviour, not
    # a leaked value.)
    for needle in ("x-api-key", "api_key", "api-key", "authorization", "bearer ", "secret_key", "private_key", "seed_phrase"):
        assert needle not in blob, f"report leaked '{needle}'"


# --- Scenario 2: failed intent with a verified refund -----------------------


def test_verified_refund_end_to_end(opener: FakeOpener):
    opener.json("GET", "/v0/status", load_synthetic("oneclick_status_REFUNDED.json"))
    opener.json("POST", "ethereum-rpc", load_synthetic("evm_receipt_refund_verified.json"))
    inv = investigate("0xcccc000000000000000000000000000000000003", client_for(opener))
    result = build_result(inv)
    assert result.outcome is OverallOutcome.REFUND_VERIFIED
    assert result.stage(Stage.REFUND).state is StageState.CONFIRMED
    assert result.safety["reported_refund_not_confirmed"] is True


# --- Scenario 3: reported refund that cannot be verified --------------------


def test_reported_refund_unverified_end_to_end(opener: FakeOpener):
    # 1Click reports a refund, but the origin receipt has no matching transfer.
    opener.json("GET", "/v0/status", load_synthetic("oneclick_status_REFUNDED.json"))
    origin = load_raw("evm_receipt_origin.json")
    origin["result"]["transactionHash"] = "0xaaaa000000000000000000000000000000000000000000000000000000000001"
    # Pay the refund address (0xaaaa...0001) so it is classified as a refund candidate,
    # but with no matching ERC-20 Transfer log, so it cannot be confirmed.
    origin["result"]["to"] = "0xaaaa000000000000000000000000000000000001"
    origin["result"]["logs"] = []
    opener.json("POST", "ethereum-rpc", origin)
    inv = investigate("0xcccc000000000000000000000000000000000003", client_for(opener))
    result = build_result(inv)
    assert result.outcome is OverallOutcome.REFUND_REPORTED_UNVERIFIED
    assert result.stage(Stage.REFUND).state is StageState.REPORTED
    assert any("refund" in n.lower() for n in inv.notes)


# --- Scenario 4: successful source, missing downstream ----------------------


def test_source_confirmed_missing_downstream(opener: FakeOpener):
    opener.json("GET", "/v0/status", load_raw("oneclick_status_SUCCESS.json"))
    opener.json("POST", "ethereum-rpc", load_raw("evm_receipt_origin.json"))
    # NEAR RPC and solver relay are unavailable.
    opener.timeout("POST", "rpc.fastnear")
    opener.timeout("POST", "solver-relay")
    inv = investigate(REAL_DEPOSIT_ADDRESS, client_for(opener))
    result = build_result(inv)
    assert result.stage(Stage.SOURCE_CHAIN_DEPOSIT).state is StageState.CONFIRMED
    assert result.stage(Stage.NEAR_SETTLEMENT).state is StageState.UNAVAILABLE
    assert result.outcome is not OverallOutcome.SETTLED_VERIFIED
    assert result.safety["unavailable_rpc_is_not_failure"] is True


# --- Scenario 6: 1Click 404 -------------------------------------------------


def test_oneclick_404_end_to_end(opener: FakeOpener):
    opener.http_error("GET", "/v0/status", 404, b"{}")
    inv = investigate("0xdeadbeefdeadbeefdeadbeefdeadbeefdeadbeef", client_for(opener))
    result = build_result(inv)
    assert result.outcome is OverallOutcome.NOT_FOUND
    assert "not proof" in result.summary.lower() or "not found" in result.summary.lower()


# --- Scenario 7: 1Click 401 -------------------------------------------------


def test_oneclick_401_end_to_end(opener: FakeOpener):
    opener.http_error("GET", "/v0/status", 401, b"{}")
    inv = investigate(REAL_DEPOSIT_ADDRESS, client_for(opener))
    result = build_result(inv)
    assert inv.source_statuses["oneclick_status"] is SourceStatus.UNAUTHORIZED
    assert result.outcome is not OverallOutcome.FAILED_VERIFIED
    assert "unavailable" in result.summary.lower()


# --- Scenario 8: RPC unavailable -------------------------------------------


def test_all_sources_unavailable_does_not_claim_failure(opener: FakeOpener):
    opener.network_error("GET", "/v0/status")
    inv = investigate(REAL_DEPOSIT_ADDRESS, client_for(opener))
    result = build_result(inv)
    assert result.outcome is not OverallOutcome.FAILED_VERIFIED
    assert result.safety["unavailable_rpc_is_not_failure"] is True


# --- Scenario 9: destination exists but transfer unverifiable ---------------


def test_destination_exists_but_transfer_unverifiable(opener: FakeOpener):
    opener.json("GET", "/v0/status", load_raw("oneclick_status_SUCCESS.json"))
    opener.json("POST", "ethereum-rpc", load_raw("evm_receipt_origin.json"), once=True)
    # Destination receipt succeeds but has no USDC transfer log to the recipient.
    dest = load_raw("evm_receipt_destination.json")
    dest["result"]["logs"] = []
    opener.json("POST", "ethereum-rpc", dest)
    opener.json("POST", "rpc.fastnear", load_raw("near_rpc_tx.json"))
    opener.json("POST", "solver-relay", load_raw("solver_relay_get_status_SETTLED.json"))
    inv = investigate(REAL_DEPOSIT_ADDRESS, client_for(opener))
    result = build_result(inv)
    assert result.stage(Stage.DESTINATION_CHAIN_DELIVERY).state is not StageState.CONFIRMED
    assert result.outcome is OverallOutcome.DELIVERY_UNVERIFIED
    assert result.safety["no_missing_destination_is_failure"] is True


# --- Scenario 10: uncorrelatable identifier --------------------------------


def test_ambiguous_base58_hash_is_not_forced_into_a_wrong_path(opener: FakeOpener):
    # A 44-char base58 string is ambiguous between a NEAR tx hash and an intent hash.
    ambiguous = "1111111111111111111111111111111111111111111"
    assert classify_identifier(ambiguous) is IdentifierType.UNKNOWN
    opener.json("POST", "solver-relay", {"result": {"intent_hash": ambiguous, "status": "NOT_FOUND_OR_NOT_VALID"}})
    inv = investigate(ambiguous, client_for(opener))
    result = build_result(inv)
    assert any("base58" in n for n in inv.notes)
    assert result.outcome is not OverallOutcome.SETTLED_VERIFIED


def test_origin_tx_hash_cannot_be_reverse_looked_up(opener: FakeOpener):
    inv = investigate(REAL_ORIGIN_TX, client_for(opener))
    assert inv.identifier_type is IdentifierType.ORIGIN_CHAIN_TX_HASH
    assert any("reverse lookup" in n for n in inv.notes)
    assert inv.source_reports == []
    result = build_result(inv)
    assert result.outcome is OverallOutcome.UNKNOWN


# --- Intent-hash-only investigation ----------------------------------------


def test_intent_hash_only_uses_solver_relay_and_states_limitation(opener: FakeOpener):
    opener.json("POST", "solver-relay", load_raw("solver_relay_get_status_SETTLED.json"))
    inv = investigate(REAL_INTENT_HASH, client_for(opener), identifier_type=IdentifierType.INTENT_HASH)
    result = build_result(inv)
    assert result.stage(Stage.NEAR_SETTLEMENT).state is StageState.REPORTED
    assert any("no reverse lookup" in n for n in inv.notes)


# --- Scenario 12: unsupported chain ----------------------------------------


def test_unsupported_destination_chain_is_unavailable(opener: FakeOpener):
    payload = load_raw("oneclick_status_SUCCESS.json")
    payload["quoteResponse"]["quoteRequest"]["destinationAsset"] = "nep141:doge-xyz.omft.near"
    opener.json("GET", "/v0/status", payload)
    opener.json("POST", "ethereum-rpc", load_raw("evm_receipt_origin.json"))
    opener.json("POST", "rpc.fastnear", load_raw("near_rpc_tx.json"))
    opener.json("POST", "solver-relay", load_raw("solver_relay_get_status_SETTLED.json"))
    inv = investigate(REAL_DEPOSIT_ADDRESS, client_for(opener))
    result = build_result(inv)
    assert result.stage(Stage.DESTINATION_CHAIN_DELIVERY).state is StageState.UNAVAILABLE
    assert result.outcome is not OverallOutcome.FAILED_VERIFIED
    assert any("no configured public RPC" in n for n in inv.notes)


# --- Scenario 11: malformed API response -----------------------------------


def test_malformed_status_response_end_to_end(opener: FakeOpener):
    opener.json("GET", "/v0/status", {"unexpected": True})
    inv = investigate(REAL_DEPOSIT_ADDRESS, client_for(opener))
    result = build_result(inv)
    assert inv.source_statuses["oneclick_status"] is SourceStatus.MALFORMED
    assert result.outcome is not OverallOutcome.SETTLED_VERIFIED


# --- Scenario 14: simulated evidence is labelled ---------------------------


def test_simulated_evidence_marked_in_report(opener: FakeOpener):
    from tracesettle.model import EventType

    opener.http_error("GET", "/v0/status", 404, b"{}")
    inv = investigate(REAL_DEPOSIT_ADDRESS, client_for(opener))
    inv.evidence.append(
        make_ev(
            "ev-sim",
            Stage.DESTINATION_CHAIN_DELIVERY,
            EventType.DESTINATION_TRANSFER_OBSERVED,
            Verification.SIMULATED,
            provenance=Provenance.SIMULATED,
        )
    )
    report = build_report(inv, build_result(inv), CREATED_AT)
    assert report.to_dict()["stages"]
    sim = [e for e in report.to_dict()["evidence"] if e["provenance"] == "SIMULATED"]
    assert sim and sim[0]["verification"] == "SIMULATED"
    # The engine must label the result as containing simulated evidence.
    assert "simulated" in report.to_dict()["summary"].lower()


# --- Invalid identifiers ----------------------------------------------------


def test_invalid_deposit_address_is_rejected():
    ok, reason = validate_deposit_address("0xnothex")
    assert not ok and reason


def test_empty_identifier():
    inv = investigate("", client_for(FakeOpener()))
    assert inv.notes and "No identifier" in inv.notes[0]
    assert build_result(inv).outcome is OverallOutcome.UNKNOWN


# --- Correlation safety -----------------------------------------------------


def test_origin_deposit_is_attributed_by_recipient_not_amount(opener: FakeOpener):
    """Attribution uses the deposit address, never the amount."""
    opener.json("GET", "/v0/status", load_raw("oneclick_status_SUCCESS.json"))
    # An origin receipt that pays an unrelated address must not count as the deposit.
    origin = load_raw("evm_receipt_origin.json")
    origin["result"]["to"] = "0x0000000000000000000000000000000000000099"
    opener.json("POST", "ethereum-rpc", origin)
    opener.json("POST", "rpc.fastnear", load_raw("near_rpc_tx.json"))
    opener.json("POST", "solver-relay", load_raw("solver_relay_get_status_SETTLED.json"))
    inv = investigate(REAL_DEPOSIT_ADDRESS, client_for(opener))
    result = build_result(inv)
    assert result.stage(Stage.SOURCE_CHAIN_DEPOSIT).state is not StageState.CONFIRMED
    assert any("could not be attributed" in n for n in inv.notes)
