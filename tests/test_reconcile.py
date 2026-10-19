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
