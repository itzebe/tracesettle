"""Deterministic reconciliation-engine tests (no network, no I/O)."""

from __future__ import annotations

from tracesettle.model import (
    EventType,
    OverallOutcome,
    Provenance,
    SourceStatus,
    Stage,
    StageState,
    Verification,
)
from tracesettle.reconcile import reconcile

from conftest import ev


def _assert_no_invariant_violated(result):
    violated = [name for name, ok in result.safety.items() if not ok]
    assert not violated, f"safety invariants violated: {violated}"


def _full_happy_path():
    return [
        ev(
            "ev-origin-exec",
            Stage.SOURCE_CHAIN_DEPOSIT,
            EventType.SOURCE_TX_EXECUTED,
            Verification.CONFIRMED,
            reported_status="SUCCESS",
            tx_hash="0xorigin",
            chain="eth",
        ),
        ev(
            "ev-deposit",
            Stage.BRIDGE_DEPOSIT_CREDIT,
            EventType.DEPOSIT_OBSERVED,
            Verification.REPORTED,
            reported_status="SUCCESS",
        ),
        ev(
            "ev-near-intent",
            Stage.NEAR_SETTLEMENT,
            EventType.INTENT_EVENT_OBSERVED,
            Verification.CONFIRMED,
            tx_hash="nearhash",
            chain="near",
            details={"intent_hashes": ["intent1"], "standard": "dip4"},
        ),
        ev(
            "ev-dest-transfer",
            Stage.DESTINATION_CHAIN_DELIVERY,
            EventType.DESTINATION_TRANSFER_OBSERVED,
            Verification.CONFIRMED,
            reported_status="SUCCESS",
            tx_hash="0xdest",
            chain="eth",
        ),
    ]


# --- Scenario 1: successful settlement with sufficient evidence -------------


def test_successful_settlement_is_verified():
    result = reconcile(_full_happy_path(), {"oneclick_status": SourceStatus.OK})
    assert result.outcome is OverallOutcome.SETTLED_VERIFIED
    assert result.last_confirmed_stage is Stage.DESTINATION_CHAIN_DELIVERY
    assert result.stage(Stage.NEAR_SETTLEMENT).state is StageState.CONFIRMED
    assert result.stage(Stage.DESTINATION_CHAIN_DELIVERY).state is StageState.CONFIRMED
    assert result.contradictions == ()


def test_identical_evidence_produces_identical_result():
    evidence = _full_happy_path()
    a = reconcile(evidence, {"oneclick_status": SourceStatus.OK})
    # Same evidence, different input order -> identical result.
    b = reconcile(list(reversed(evidence)), {"oneclick_status": SourceStatus.OK})
    assert a.to_dict() == b.to_dict()


# --- Scenario 4: successful source transaction, missing downstream ----------


def test_source_confirmed_but_downstream_missing_is_incomplete():
    result = reconcile(
        [
            ev(
                "ev-origin-exec",
                Stage.SOURCE_CHAIN_DEPOSIT,
                EventType.SOURCE_TX_EXECUTED,
                Verification.CONFIRMED,
                reported_status="SUCCESS",
            )
        ],
        {"oneclick_status": SourceStatus.OK},
    )
    assert result.outcome is OverallOutcome.INCOMPLETE
    assert result.last_confirmed_stage is Stage.SOURCE_CHAIN_DEPOSIT
    assert result.stage(Stage.DESTINATION_CHAIN_DELIVERY).state is StageState.MISSING


def test_source_success_alone_is_not_settlement():
    result = reconcile(
        [
            ev(
                "ev-origin-exec",
                Stage.SOURCE_CHAIN_DEPOSIT,
                EventType.SOURCE_TX_EXECUTED,
                Verification.CONFIRMED,
                reported_status="SUCCESS",
            )
        ],
        {"oneclick_status": SourceStatus.OK},
    )
    assert result.outcome is not OverallOutcome.SETTLED_VERIFIED
    assert result.safety["source_success_is_not_settlement"] is True


# --- Reported-only settlement -----------------------------------------------


def test_reported_settlement_only_is_not_verified():
    result = reconcile(
        [
            ev(
                "ev-claim",
                Stage.NEAR_SETTLEMENT,
                EventType.SETTLEMENT_CLAIMED,
                Verification.REPORTED,
                reported_status="SUCCESS",
            )
        ],
        {"oneclick_status": SourceStatus.OK},
    )
    assert result.outcome is OverallOutcome.SETTLED_REPORTED_ONLY
    assert result.last_confirmed_stage is None


# --- Scenario 2: failed intent with a verified refund -----------------------


def test_verified_refund():
    result = reconcile(
        [
            ev(
                "ev-refund",
                Stage.REFUND,
                EventType.REFUND_TX_CONFIRMED,
                Verification.CONFIRMED,
                tx_hash="0xrefund",
                chain="eth",
            ),
            ev(
                "ev-refund-claim",
                Stage.REFUND,
                EventType.REFUND_CLAIMED,
                Verification.REPORTED,
                reported_status="REFUNDED",
                details={"refunded_amount": "1000000000"},
            ),
        ],
        {"oneclick_status": SourceStatus.OK},
    )
    assert result.outcome is OverallOutcome.REFUND_VERIFIED
    assert result.stage(Stage.REFUND).state is StageState.CONFIRMED
    assert result.safety["reported_refund_not_confirmed"] is True


# --- Scenario 3: reported refund that cannot be independently verified -------


def test_reported_refund_without_evidence_is_not_confirmed():
    result = reconcile(
        [
            ev(
                "ev-refund-claim",
                Stage.REFUND,
                EventType.REFUND_CLAIMED,
                Verification.REPORTED,
                reported_status="REFUNDED",
                details={"refunded_amount": "1000000000"},
            )
        ],
        {"oneclick_status": SourceStatus.OK},
    )
    assert result.outcome is OverallOutcome.REFUND_REPORTED_UNVERIFIED
    assert result.stage(Stage.REFUND).state is StageState.REPORTED
    assert result.safety["reported_refund_not_confirmed"] is True
    assert any("refund" in q.lower() for q in result.unresolved_questions)


def test_zero_refund_is_not_proof_of_no_refund():
    result = reconcile(
        [
            ev(
                "ev-failed",
                Stage.NEAR_SETTLEMENT,
                EventType.UPSTREAM_STATUS,
                Verification.REPORTED,
                reported_status="FAILED",
                details={"refunded_amount": "0"},
            )
        ],
        {"oneclick_status": SourceStatus.OK},
    )
    assert result.outcome is OverallOutcome.FAILED_REPORTED_UNVERIFIED
    assert result.stage(Stage.REFUND).state is not StageState.CONFIRMED
    assert result.safety["zero_refund_is_not_proof_of_no_refund"] is True
    assert result.safety["reported_failure_is_not_loss"] is True


# --- Refund coverage: the eight required cases ------------------------------
#
# 1. failed intent with an independently verified refund            -> REFUND_VERIFIED
# 2. reported refund without independent evidence                  -> REFUND_REPORTED_UNVERIFIED
# 3. failed intent with no refund evidence                         -> REFUND MISSING
# 4. reported zero refund amount                                   -> never "no refund"
# 5. unavailable refund-verification source                        -> REFUND UNAVAILABLE
# 6. conflicting refund claims                                     -> CONTRADICTORY / not confirmed
# 7. refund tx succeeds on-chain but cannot be linked to the intent -> not confirmed
# 8. refund tx exists but wrong asset or wrong recipient           -> not confirmed


def test_refund_case_3_failed_intent_no_refund_evidence():
    """A failed intent with no refund evidence leaves REFUND MISSING, not 'no refund'."""
    result = reconcile(
        [
            ev(
                "ev-failed",
                Stage.NEAR_SETTLEMENT,
                EventType.UPSTREAM_STATUS,
                Verification.REPORTED,
                reported_status="FAILED",
            )
        ],
        {"oneclick_status": SourceStatus.OK},
    )
    assert result.stage(Stage.REFUND).state is StageState.MISSING
    assert result.outcome is not OverallOutcome.REFUND_VERIFIED
    assert "does not mean" in result.stage(Stage.REFUND).summary.lower()
    _assert_no_invariant_violated(result)


def test_refund_case_4_reported_zero_amount():
    """refundedAmount '0' must never be reported as proof no refund can occur."""
    result = reconcile(
        [
            ev(
                "ev-refund",
                Stage.REFUND,
                EventType.REFUND_CLAIMED,
                Verification.REPORTED,
                reported_status="REFUNDED",
                details={"refunded_amount": "0"},
            )
        ],
        {"oneclick_status": SourceStatus.OK},
    )
    assert result.stage(Stage.REFUND).state is not StageState.CONFIRMED
    assert result.outcome is not OverallOutcome.REFUND_VERIFIED
    _assert_no_invariant_violated(result)


def test_refund_case_5_unavailable_refund_verification_source():
    """A reported refund whose origin RPC was unreachable is UNAVAILABLE, not confirmed."""
    result = reconcile(
        [
            ev(
                "ev-refund",
                Stage.REFUND,
                EventType.REFUND_CLAIMED,
                Verification.REPORTED,
                reported_status="REFUNDED",
                details={"refunded_amount": "1000000"},
            ),
            ev(
                "ev-refund-unavailable",
                Stage.REFUND,
                EventType.REFUND_TX_CONFIRMED,
                Verification.UNAVAILABLE,
                details={"reason": "TIMEOUT"},
            ),
        ],
        {"oneclick_status": SourceStatus.OK, "evm_rpc": SourceStatus.TIMEOUT},
    )
    stage = result.stage(Stage.REFUND)
    assert stage.state is StageState.UNAVAILABLE
    assert result.outcome is not OverallOutcome.REFUND_VERIFIED
    assert "unavailable" in stage.summary.lower()
    _assert_no_invariant_violated(result)


def test_refund_case_6_conflicting_refund_claims():
    """A confirmed refund transaction alongside a reported failure is a contradiction."""
    result = reconcile(
        [
            ev(
                "ev-refund-claim",
                Stage.REFUND,
                EventType.REFUND_CLAIMED,
                Verification.REPORTED,
                reported_status="REFUNDED",
                details={"refunded_amount": "1000000"},
            ),
            ev(
                "ev-refund-tx",
                Stage.REFUND,
                EventType.REFUND_TX_CONFIRMED,
                Verification.CONFIRMED,
                tx_hash="0xrefund",
                chain="eth",
            ),
            # A destination transfer independently confirmed at the same time.
            ev(
                "ev-delivery",
                Stage.DESTINATION_CHAIN_DELIVERY,
                EventType.DESTINATION_TRANSFER_OBSERVED,
                Verification.CONFIRMED,
                tx_hash="0xdest",
                chain="eth",
            ),
        ],
        {"oneclick_status": SourceStatus.OK},
    )
    # A refund confirmed while delivery is also confirmed is contradictory and must
    # be surfaced, not silently resolved.
    assert result.contradictions, "expected a contradiction to be reported"
    assert result.outcome is OverallOutcome.CONTRADICTORY


def test_refund_case_7_tx_succeeds_but_cannot_be_linked():
    """A successful origin tx that cannot be linked to the intent must not confirm a refund.

    The refund stage can only be confirmed from evidence explicitly tied to the
    investigated swap. A receipt that exists but was never attributed to the
    refund address is not refund evidence.
    """
    result = reconcile(
        [
            ev(
                "ev-refund-claim",
                Stage.REFUND,
                EventType.REFUND_CLAIMED,
                Verification.REPORTED,
                reported_status="REFUNDED",
                details={"refunded_amount": "1000000"},
            ),
            # The origin tx was observed but explicitly not attributed to this swap.
            ev(
                "ev-origin-unattributed",
                Stage.SOURCE_CHAIN_DEPOSIT,
                EventType.SOURCE_TX_INCLUDED,
                Verification.UNAVAILABLE,
                details={"reason": "NOT_ATTRIBUTABLE"},
            ),
        ],
        {"oneclick_status": SourceStatus.OK},
    )
    assert result.stage(Stage.REFUND).state is not StageState.CONFIRMED
    assert result.outcome is OverallOutcome.REFUND_REPORTED_UNVERIFIED
    _assert_no_invariant_violated(result)


def test_refund_case_8_wrong_asset_or_recipient_not_confirmed():
    """A confirmed refund requires a matching transfer; wrong asset/recipient is not one.

    This asserts the contract at the engine boundary: REFUND_TX_CONFIRMED is only
    ever produced by the adapter's transfer matcher, which requires the expected
    token contract AND recipient. A transfer to a different address, or of a
    different token, produces no such item.
    """
    from tracesettle.adapters import evm_rpc

    refund_address = "0xaaaa000000000000000000000000000000000001"
    padded = "0x" + "0" * 24 + refund_address[2:]  # 32-byte left-padded topic

    def transfer_log(token: str, to_topic: str) -> dict:
        return {
            "address": token,
            "topics": [evm_rpc.TRANSFER_TOPIC, "0x" + "0" * 24 + "b" * 40, to_topic],
            "data": "0x" + format(1000000, "x"),
        }

    receipt = evm_rpc.EvmReceiptData(
        tx_hash="0xrefund",
        chain="eth",
        status="0x1",
        to_address=refund_address,
        from_address="0xbbbb000000000000000000000000000000000002",
        logs=[
            transfer_log(
                "0xa0b86991c6218b36c1d19d4a2e9eb0ce3606eb48",  # USDC
                "0x" + "0" * 24 + "9" * 40,  # WRONG recipient
            )
        ],
    )
    # Expecting the refund address, not 0x999...
    expectation = evm_rpc.ExpectedTransfer(
        token_contract="0xa0b86991c6218b36c1d19d4a2e9eb0ce3606eb48",
        recipient=refund_address,
        amount_base_units="1000000",
    )
    match = evm_rpc.match_expected_transfer(receipt, expectation)
    assert match.matched is False
    assert "recipient" in match.reason.lower()

    # A different token to the right recipient must also fail to match.
    wrong_token = evm_rpc.EvmReceiptData(
        tx_hash="0xrefund2",
        chain="eth",
        status="0x1",
        to_address=refund_address,
        from_address="0xbbbb000000000000000000000000000000000002",
        logs=[
            transfer_log(
                "0xdead00000000000000000000000000000000beef",  # WRONG token
                padded,  # right recipient
            )
        ],
    )
    match2 = evm_rpc.match_expected_transfer(wrong_token, expectation)
    assert match2.matched is False
    assert "token" in match2.reason.lower() or "recipient" in match2.reason.lower()

    # The correct asset to the correct recipient does match, so the negative cases
    # above are meaningful rather than passing vacuously.
    correct = evm_rpc.EvmReceiptData(
        tx_hash="0xrefund3",
        chain="eth",
        status="0x1",
        to_address=refund_address,
        from_address="0xbbbb000000000000000000000000000000000002",
        logs=[
            transfer_log(
                "0xa0b86991c6218b36c1d19d4a2e9eb0ce3606eb48",
                padded,
            )
        ],
    )
    assert evm_rpc.match_expected_transfer(correct, expectation).matched is True


def test_reported_failure_is_not_funds_lost():
    result = reconcile(
        [
            ev(
                "ev-failed",
                Stage.NEAR_SETTLEMENT,
                EventType.UPSTREAM_STATUS,
                Verification.REPORTED,
                reported_status="FAILED",
            )
        ],
        {"oneclick_status": SourceStatus.OK},
    )
    assert result.outcome is OverallOutcome.FAILED_REPORTED_UNVERIFIED
    # The engine must never *assert* loss; the only place the word may appear is
    # inside the explicit disclaimer that a reported failure is not proof of loss.
    summary = result.summary.lower()
    assert "not proof that funds were lost" in summary
    assert "funds were lost." not in summary.replace("not proof that funds were lost.", "")
    assert result.safety["reported_failure_is_not_loss"] is True


# --- Scenario 5: conflicting upstream status and chain evidence -------------


def test_confirmed_failure_and_confirmed_success_conflict():
    result = reconcile(
        [
            ev(
                "ev-near-fail",
                Stage.NEAR_SETTLEMENT,
                EventType.NEAR_TX_EXECUTION,
                Verification.CONFIRMED,
                reported_status="FAILED",
                details={"execution_failed": True},
            ),
            ev(
                "ev-dest-ok",
                Stage.DESTINATION_CHAIN_DELIVERY,
                EventType.DESTINATION_TX_EXECUTED,
                Verification.CONFIRMED,
                reported_status="SUCCESS",
            ),
        ],
        {"near_rpc": SourceStatus.OK},
    )
    assert result.outcome is OverallOutcome.CONTRADICTORY
    assert result.contradictions


def test_reported_failure_vs_confirmed_onchain_intent_conflicts():
    result = reconcile(
        [
            ev(
                "ev-failed",
                Stage.NEAR_SETTLEMENT,
                EventType.UPSTREAM_STATUS,
                Verification.REPORTED,
                reported_status="FAILED",
            ),
            ev(
                "ev-intent",
                Stage.NEAR_SETTLEMENT,
                EventType.INTENT_EVENT_OBSERVED,
                Verification.CONFIRMED,
                details={"intent_hashes": ["intent1"], "standard": "dip4"},
            ),
        ],
        {"oneclick_status": SourceStatus.OK},
    )
    assert result.outcome is OverallOutcome.CONTRADICTORY
    assert any("FAILED" in c.description for c in result.contradictions)


def test_different_status_vocabularies_alone_are_not_contradictory():
    """SETTLED (solver relay) and SUCCESS (1Click) do not conflict."""
    result = reconcile(
        [
            ev(
                "ev-oneclick",
                Stage.NEAR_SETTLEMENT,
                EventType.SETTLEMENT_CLAIMED,
                Verification.REPORTED,
                reported_status="SUCCESS",
            ),
            ev(
                "ev-solver",
                Stage.NEAR_SETTLEMENT,
                EventType.SETTLEMENT_CLAIMED,
                Verification.REPORTED,
                reported_status="SETTLED",
            ),
        ],
        {"oneclick_status": SourceStatus.OK, "solver_relay": SourceStatus.OK},
    )
    assert result.contradictions == ()
    assert result.outcome is OverallOutcome.SETTLED_REPORTED_ONLY


# --- Scenario 8/12: unavailable RPC and unsupported chain -------------------


def test_unavailable_source_yields_unavailable_not_failure():
    result = reconcile(
        [
            ev(
                "ev-origin",
                Stage.SOURCE_CHAIN_DEPOSIT,
                EventType.SOURCE_TX_EXECUTED,
                Verification.CONFIRMED,
                reported_status="SUCCESS",
            )
        ],
        {"oneclick_status": SourceStatus.OK, "evm_rpc": SourceStatus.TIMEOUT},
    )
    assert result.stage(Stage.DESTINATION_CHAIN_DELIVERY).state is StageState.UNAVAILABLE
    assert result.outcome is not OverallOutcome.FAILED_VERIFIED
    assert result.safety["unavailable_rpc_is_not_failure"] is True


def test_unsupported_chain_source_marks_stage_unavailable():
    result = reconcile([], {"oneclick_status": SourceStatus.OK, "evm_rpc": SourceStatus.UNSUPPORTED})
    assert result.stage(Stage.DESTINATION_CHAIN_DELIVERY).state is StageState.UNAVAILABLE
    assert result.outcome is OverallOutcome.UNKNOWN


# --- Scenario 14: simulated evidence must be labelled -----------------------


def test_simulated_evidence_is_labelled_and_not_confirmed():
    result = reconcile(
        [
            ev(
                "ev-sim",
                Stage.DESTINATION_CHAIN_DELIVERY,
                EventType.DESTINATION_TRANSFER_OBSERVED,
                Verification.SIMULATED,
                provenance=Provenance.SIMULATED,
            )
        ],
        {"oneclick_status": SourceStatus.OK},
    )
    assert result.stage(Stage.DESTINATION_CHAIN_DELIVERY).state is StageState.SIMULATED
    assert "simulated" in result.summary.lower()
    assert result.outcome is not OverallOutcome.SETTLED_VERIFIED


# --- Scenario 6: 1Click 404 / nothing found ---------------------------------


def test_not_found_is_not_failure():
    result = reconcile([], {"oneclick_status": SourceStatus.NOT_FOUND})
    assert result.outcome is OverallOutcome.NOT_FOUND
    assert "not proof" in result.summary.lower() or "not found" in result.summary.lower()


# --- Missing destination is never a failed transfer -------------------------


def test_missing_destination_is_never_failed_transfer():
    result = reconcile(
        [
            ev(
                "ev-origin",
                Stage.SOURCE_CHAIN_DEPOSIT,
                EventType.SOURCE_TX_EXECUTED,
                Verification.CONFIRMED,
                reported_status="SUCCESS",
            ),
            ev(
                "ev-near",
                Stage.NEAR_SETTLEMENT,
                EventType.INTENT_EVENT_OBSERVED,
                Verification.CONFIRMED,
                details={"intent_hashes": ["i"], "standard": "dip4"},
            ),
        ],
        {"oneclick_status": SourceStatus.OK},
    )
    assert result.outcome is OverallOutcome.DELIVERY_UNVERIFIED
    assert result.stage(Stage.DESTINATION_CHAIN_DELIVERY).state is StageState.MISSING
    assert result.safety["no_missing_destination_is_failure"] is True
    assert "failed" not in result.summary.lower()


# --- Refund confirmation requires on-chain, confirmed evidence --------------


def test_refund_requires_refund_tx_event_not_merely_confirmed():
    """A CONFIRMED item that is not a REFUND_TX_CONFIRMED event must not confirm REFUND."""
    result = reconcile(
        [
            ev(
                "ev-refund-odd",
                Stage.REFUND,
                EventType.UPSTREAM_STATUS,
                Verification.CONFIRMED,
                reported_status="REFUNDED",
            )
        ],
        {"oneclick_status": SourceStatus.OK},
    )
    assert result.stage(Stage.REFUND).state is not StageState.CONFIRMED
    assert result.outcome is not OverallOutcome.REFUND_VERIFIED
    assert result.safety["refund_confirmation_requires_onchain_evidence"] is True
    _assert_no_invariant_violated(result)


def test_refund_tx_without_hash_is_not_confirmed():
    """A refund transaction with no tx hash cannot confirm the stage."""
    result = reconcile(
        [
            ev(
                "ev-refund",
                Stage.REFUND,
                EventType.REFUND_TX_CONFIRMED,
                Verification.CONFIRMED,
                tx_hash=None,
            )
        ],
        {"oneclick_status": SourceStatus.OK},
    )
    assert result.stage(Stage.REFUND).state is not StageState.CONFIRMED
    assert result.outcome is not OverallOutcome.REFUND_VERIFIED
    assert result.safety["refund_confirmation_requires_onchain_evidence"] is True


def test_bitcoin_refund_requires_confirmed_flag():
    """A Bitcoin refund evidence item without confirmed=True must not confirm REFUND."""
    result = reconcile(
        [
            ev(
                "ev-btc-refund",
                Stage.REFUND,
                EventType.REFUND_TX_CONFIRMED,
                Verification.CONFIRMED,
                chain="btc",
                tx_hash="a" * 64,
                details={"confirmed": False},
            )
        ],
        {"oneclick_status": SourceStatus.OK, "btc_rpc": SourceStatus.OK},
    )
    assert result.stage(Stage.REFUND).state is not StageState.CONFIRMED
    assert result.outcome is not OverallOutcome.REFUND_VERIFIED
    assert result.safety["bitcoin_refund_requires_confirmed_payout"] is True
    _assert_no_invariant_violated(result)


def test_bitcoin_refund_confirmed_flag_confirms():
    """The positive case: confirmed=True with a hash does confirm REFUND."""
    result = reconcile(
        [
            ev(
                "ev-btc-refund",
                Stage.REFUND,
                EventType.REFUND_TX_CONFIRMED,
                Verification.CONFIRMED,
                chain="btc",
                tx_hash="a" * 64,
                details={"confirmed": True, "observed_output_sats": 12884},
            )
        ],
        {"oneclick_status": SourceStatus.OK, "btc_rpc": SourceStatus.OK},
    )
    assert result.stage(Stage.REFUND).state is StageState.CONFIRMED
    assert result.outcome is OverallOutcome.REFUND_VERIFIED
    assert result.safety["bitcoin_refund_requires_confirmed_payout"] is True


def test_simulated_refund_only_is_simulated_stage():
    """A simulated refund payout alone leaves REFUND SIMULATED, never CONFIRMED."""
    from tracesettle.model import Provenance

    result = reconcile(
        [
            ev(
                "ev-sim-refund",
                Stage.REFUND,
                EventType.REFUND_TX_CONFIRMED,
                Verification.CONFIRMED,
                provenance=Provenance.SIMULATED,
                chain="btc",
                tx_hash="b" * 64,
                details={"confirmed": True},
            )
        ],
        {"oneclick_status": SourceStatus.OK},
    )
    assert result.stage(Stage.REFUND).state is StageState.SIMULATED
    assert result.outcome is not OverallOutcome.REFUND_VERIFIED
    assert result.safety["simulated_evidence_never_confirms"] is True


def test_refund_is_unavailable_when_status_source_is_down():
    """With the refund-reporting source down, REFUND must be UNAVAILABLE, not MISSING."""
    result = reconcile([], {"oneclick_status": SourceStatus.SERVER_ERROR})
    stage = result.stage(Stage.REFUND)
    assert stage.state is StageState.UNAVAILABLE
    assert "not evidence that no refund occurred" in stage.summary.lower()


def test_refund_is_missing_only_when_status_source_answered():
    """When the status source answered and claims no refund, REFUND is MISSING."""
    result = reconcile([], {"oneclick_status": SourceStatus.OK})
    assert result.stage(Stage.REFUND).state is StageState.MISSING


def test_incomplete_refund_search_is_unknown_not_unavailable():
    """An incomplete search is insufficient evidence, not a source outage.

    The refund-reporting source answered (so this is not UNAVAILABLE) and a payout
    search was attempted but could not be completed. The stage must be UNKNOWN, and
    the overall result must still be an unverified refund claim — never verified.
    """
    result = reconcile(
        [
            ev(
                "ev-refund-claim",
                Stage.REFUND,
                EventType.REFUND_CLAIMED,
                Verification.REPORTED,
                reported_status="REFUNDED",
                details={"refunded_amount": "11746"},
            ),
            ev(
                "ev-refund-incomplete",
                Stage.REFUND,
                EventType.REFUND_TX_CONFIRMED,
                Verification.INCOMPLETE,
                source="btc_rpc",
                chain="btc",
                details={"reason": "INCOMPLETE_ADDRESS_HISTORY"},
            ),
        ],
        {"oneclick_status": SourceStatus.OK, "btc_rpc": SourceStatus.OK},
    )
    stage = result.stage(Stage.REFUND)
    assert stage.state is StageState.UNKNOWN
    assert "insufficient evidence" in stage.summary.lower()
    assert result.outcome is OverallOutcome.REFUND_REPORTED_UNVERIFIED
    _assert_no_invariant_violated(result)


def test_incomplete_search_without_a_claim_is_not_verified_or_failed():
    """An incomplete search with no refund claim is UNKNOWN, not MISSING/FAILED."""
    result = reconcile(
        [
            ev(
                "ev-refund-incomplete",
                Stage.REFUND,
                EventType.REFUND_TX_CONFIRMED,
                Verification.INCOMPLETE,
                source="btc_rpc",
                chain="btc",
                details={"reason": "INCOMPLETE_ADDRESS_HISTORY"},
            ),
        ],
        {"oneclick_status": SourceStatus.OK, "btc_rpc": SourceStatus.OK},
    )
    assert result.stage(Stage.REFUND).state is StageState.UNKNOWN
    assert result.outcome is not OverallOutcome.REFUND_VERIFIED
    assert result.outcome is not OverallOutcome.FAILED_VERIFIED
    _assert_no_invariant_violated(result)


def test_contradictory_refund_outranks_an_incomplete_search():
    """A contradiction is stronger than an incomplete search: the stage contradicts."""
    result = reconcile(
        [
            ev(
                "ev-refund-claim",
                Stage.REFUND,
                EventType.REFUND_CLAIMED,
                Verification.REPORTED,
                reported_status="REFUNDED",
            ),
            ev(
                "ev-refund-incomplete",
                Stage.REFUND,
                EventType.REFUND_TX_CONFIRMED,
                Verification.INCOMPLETE,
                source="btc_rpc",
                chain="btc",
                details={"reason": "INCOMPLETE_ADDRESS_HISTORY"},
            ),
            ev(
                "ev-refund-contradiction",
                Stage.REFUND,
                EventType.REFUND_TX_CONFIRMED,
                Verification.CONTRADICTORY,
                source="btc_rpc",
                chain="btc",
                tx_hash="a" * 64,
                details={"reason": "TXID_BYTES_MISMATCH"},
            ),
        ],
        {"oneclick_status": SourceStatus.OK, "btc_rpc": SourceStatus.OK},
    )
    assert result.stage(Stage.REFUND).state is StageState.CONTRADICTORY
    assert result.outcome is OverallOutcome.CONTRADICTORY


def test_ambiguous_refund_payout_reads_as_correlation_gap():
    """An ambiguous payout is reported as a correlation gap, not a source outage."""
    result = reconcile(
        [
            ev(
                "ev-refund",
                Stage.REFUND,
                EventType.REFUND_CLAIMED,
                Verification.REPORTED,
                reported_status="REFUNDED",
                details={"refunded_amount": "11746"},
            ),
            ev(
                "ev-refund-unavailable",
                Stage.REFUND,
                EventType.REFUND_TX_CONFIRMED,
                Verification.UNAVAILABLE,
                source="btc_rpc",
                details={"reason": "AMBIGUOUS_REFUND_PAYOUT"},
            ),
        ],
        {"oneclick_status": SourceStatus.OK, "btc_rpc": SourceStatus.OK},
    )
    stage = result.stage(Stage.REFUND)
    assert stage.state is StageState.UNAVAILABLE
    assert "correlation gap" in stage.summary.lower()
    assert "source-availability" not in stage.summary.lower()
    assert result.outcome is OverallOutcome.REFUND_REPORTED_UNVERIFIED
    _assert_no_invariant_violated(result)


# --- Transaction-level failure vs. independently confirmed delivery ----------
#
# intents.near batches many intents into one NEAR transaction, so a sibling
# receipt's failure must never be attributed to the transaction (or to another
# intent). Independently confirmed settlement/delivery must outrank a
# transaction-level failure flag, and a genuine transaction-level failure must
# still be reported as FAILED_VERIFIED.


def test_failed_sibling_receipt_does_not_mask_confirmed_settlement():
    """A confirmed intent event wins over a sibling receipt's failure."""
    result = reconcile(
        [
            ev(
                "ev-near-intent",
                Stage.NEAR_SETTLEMENT,
                EventType.INTENT_EVENT_OBSERVED,
                Verification.CONFIRMED,
                tx_hash="nearhash",
                chain="near",
                details={"intent_hashes": ["intent1"], "standard": "dip4"},
            ),
            ev(
                "ev-near-exec",
                Stage.NEAR_SETTLEMENT,
                EventType.NEAR_TX_EXECUTION,
                Verification.CONFIRMED,
                tx_hash="nearhash",
                chain="near",
                reported_status="FAILED",
                details={"execution_failed": True},
            ),
        ],
        {"near_rpc": SourceStatus.OK},
        expected_intent_hashes=["intent1"],
    )
    assert result.outcome is not OverallOutcome.FAILED_VERIFIED
    assert result.stage(Stage.NEAR_SETTLEMENT).state is StageState.CONFIRMED
    _assert_no_invariant_violated(result)


def test_failed_sibling_receipt_does_not_mask_confirmed_delivery():
    """A confirmed destination transfer wins over a sibling receipt's failure."""
    result = reconcile(
        [
            ev(
                "ev-near-intent",
                Stage.NEAR_SETTLEMENT,
                EventType.INTENT_EVENT_OBSERVED,
                Verification.CONFIRMED,
                tx_hash="nearhash",
                chain="near",
                details={"intent_hashes": ["intent1"], "standard": "dip4"},
            ),
            ev(
                "ev-near-exec",
                Stage.NEAR_SETTLEMENT,
                EventType.NEAR_TX_EXECUTION,
                Verification.CONFIRMED,
                tx_hash="nearhash",
                chain="near",
                reported_status="FAILED",
                details={"execution_failed": True},
            ),
            ev(
                "ev-dest-transfer",
                Stage.DESTINATION_CHAIN_DELIVERY,
                EventType.DESTINATION_TRANSFER_OBSERVED,
                Verification.CONFIRMED,
                reported_status="SUCCESS",
                tx_hash="0xdest",
                chain="eth",
            ),
        ],
        {"near_rpc": SourceStatus.OK, "evm_rpc": SourceStatus.OK},
        expected_intent_hashes=["intent1"],
    )
    assert result.outcome is OverallOutcome.SETTLED_VERIFIED
    assert result.stage(Stage.DESTINATION_CHAIN_DELIVERY).state is StageState.CONFIRMED
    _assert_no_invariant_violated(result)


def test_genuine_transaction_level_failure_is_failed_verified():
    """A transaction-level failure with no confirmed settlement/delivery still reports FAILED_VERIFIED."""
    result = reconcile(
        [
            ev(
                "ev-near-exec",
                Stage.NEAR_SETTLEMENT,
                EventType.NEAR_TX_EXECUTION,
                Verification.CONFIRMED,
                tx_hash="nearhash",
                chain="near",
                reported_status="FAILED",
                details={"execution_failed": True},
            ),
        ],
        {"near_rpc": SourceStatus.OK},
    )
    assert result.outcome is OverallOutcome.FAILED_VERIFIED
    _assert_no_invariant_violated(result)


def test_failure_without_confirmed_settlement_or_delivery_is_not_masked():
    """A failure flag with only reported (not confirmed) downstream evidence still fails."""
    result = reconcile(
        [
            ev(
                "ev-near-exec",
                Stage.NEAR_SETTLEMENT,
                EventType.NEAR_TX_EXECUTION,
                Verification.CONFIRMED,
                tx_hash="nearhash",
                chain="near",
                reported_status="FAILED",
                details={"execution_failed": True},
            ),
            ev(
                "ev-oneclick",
                Stage.NEAR_SETTLEMENT,
                EventType.SETTLEMENT_CLAIMED,
                Verification.REPORTED,
                source="oneclick_status",
                reported_status="PROCESSING",
            ),
        ],
        {"near_rpc": SourceStatus.OK, "oneclick_status": SourceStatus.OK},
    )
    assert result.outcome is OverallOutcome.FAILED_VERIFIED
    _assert_no_invariant_violated(result)


# --- Delivery vs. refund contradictions --------------------------------------
#
# Funds cannot both have reached the destination recipient and been returned to
# the sender. A confirmed delivery alongside any refund assertion is a material
# contradiction, and an independently confirmed refund makes the conflict
# stronger, never something to suppress.


def _confirmed_delivery(evidence_id: str = "ev-dest-transfer"):
    return ev(
        evidence_id,
        Stage.DESTINATION_CHAIN_DELIVERY,
        EventType.DESTINATION_TRANSFER_OBSERVED,
        Verification.CONFIRMED,
        reported_status="SUCCESS",
        tx_hash="0xdest",
        chain="eth",
    )


def _reported_refund(evidence_id: str = "ev-oneclick-refund"):
    return ev(
        evidence_id,
        Stage.REFUND,
        EventType.REFUND_CLAIMED,
        Verification.REPORTED,
        source="oneclick_status",
        reported_status="REFUNDED",
        details={"refunded_amount": "11746"},
    )


def _confirmed_refund(evidence_id: str = "ev-refund-confirmed"):
    return ev(
        evidence_id,
        Stage.REFUND,
        EventType.REFUND_TX_CONFIRMED,
        Verification.CONFIRMED,
        source="evm_rpc",
        reported_status="CONFIRMED",
        tx_hash="0xrefund",
        chain="eth",
        details={"reason": "matched"},
    )


def test_confirmed_delivery_and_reported_refund_conflict():
    result = reconcile(
        [_confirmed_delivery(), _reported_refund()],
        {"evm_rpc": SourceStatus.OK, "oneclick_status": SourceStatus.OK},
    )
    assert result.contradictions
    ids = {i for c in result.contradictions for i in c.evidence_ids}
    assert "ev-dest-transfer" in ids and "ev-oneclick-refund" in ids
    _assert_no_invariant_violated(result)


def test_confirmed_delivery_and_confirmed_refund_conflict():
    """An independently confirmed refund must not suppress the contradiction."""
    result = reconcile(
        [_confirmed_delivery(), _confirmed_refund()],
        {"evm_rpc": SourceStatus.OK},
    )
    assert result.contradictions, "a confirmed delivery + confirmed refund must conflict"
    ids = {i for c in result.contradictions for i in c.evidence_ids}
    assert "ev-dest-transfer" in ids and "ev-refund-confirmed" in ids
    # The report must not present the contradiction as a clean refund.
    assert result.outcome is OverallOutcome.CONTRADICTORY
    _assert_no_invariant_violated(result)


def test_confirmed_refund_without_delivery_is_verified():
    result = reconcile([_confirmed_refund()], {"evm_rpc": SourceStatus.OK})
    assert not result.contradictions
    assert result.outcome is OverallOutcome.REFUND_VERIFIED
    _assert_no_invariant_violated(result)


def test_confirmed_delivery_without_refund_has_no_contradiction():
    result = reconcile(
        [_confirmed_delivery()],
        {"evm_rpc": SourceStatus.OK, "oneclick_status": SourceStatus.OK},
    )
    assert not result.contradictions
    assert result.outcome is OverallOutcome.DELIVERY_UNVERIFIED
    _assert_no_invariant_violated(result)


def test_unavailable_refund_marker_does_not_conflict_with_delivery():
    """A refund marker that asserts *no* refund must not create a contradiction."""
    result = reconcile(
        [
            _confirmed_delivery(),
            ev(
                "ev-refund-unavailable",
                Stage.REFUND,
                EventType.REFUND_TX_CONFIRMED,
                Verification.UNAVAILABLE,
                source="btc_rpc",
                details={"reason": "SOURCE_UNAVAILABLE"},
            ),
        ],
        {"evm_rpc": SourceStatus.OK, "btc_rpc": SourceStatus.TIMEOUT},
    )
    assert not result.contradictions
    assert result.outcome is OverallOutcome.DELIVERY_UNVERIFIED
    _assert_no_invariant_violated(result)
