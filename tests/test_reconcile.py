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
