"""Every safety invariant from the Phase 2 specification, asserted directly.

Each test is written to FAIL if the engine ever makes the forbidden claim.
"""

from __future__ import annotations

import pytest

from tracesettle.model import (
    EventType,
    OverallOutcome,
    Provenance,
    SourceStatus,
    Stage,
    StageState,
    Verification,
)
from tracesettle.reconcile import SAFETY_INVARIANTS, reconcile

from conftest import ev


def test_all_documented_invariants_are_present():
    expected = {
        "no_missing_destination_is_failure",
        "zero_refund_is_not_proof_of_no_refund",
        "reported_refund_not_confirmed",
        "reported_failure_is_not_loss",
        "source_success_is_not_settlement",
        "unavailable_rpc_is_not_failure",
        "no_amount_or_time_correlation",
        "hash_commitment_is_not_proof",
    }
    assert expected == set(SAFETY_INVARIANTS)


def _assert_no_invariant_violated(result):
    violated = [name for name, ok in result.safety.items() if not ok]
    assert not violated, f"safety invariants violated: {violated}"


# 1. Missing destination transaction is never a failed transfer.


@pytest.mark.parametrize(
    "source_statuses",
    [
        {"oneclick_status": SourceStatus.OK},
        {"oneclick_status": SourceStatus.OK, "evm_rpc": SourceStatus.TIMEOUT},
        {"oneclick_status": SourceStatus.OK, "evm_rpc": SourceStatus.UNSUPPORTED},
    ],
)
def test_missing_destination_never_failed(source_statuses):
    result = reconcile(
        [
            ev(
                "ev-near",
                Stage.NEAR_SETTLEMENT,
                EventType.INTENT_EVENT_OBSERVED,
                Verification.CONFIRMED,
                details={"intent_hashes": ["i"], "standard": "dip4"},
            )
        ],
        source_statuses,
    )
    assert result.outcome is not OverallOutcome.FAILED_VERIFIED
    assert result.stage(Stage.DESTINATION_CHAIN_DELIVERY).state is not StageState.CONFIRMED
    _assert_no_invariant_violated(result)


# 2. refundedAmount "0" is not proof no refund occurred/can occur.


def test_zero_refund_is_not_proof():
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
    assert result.stage(Stage.REFUND).state is not StageState.CONFIRMED
    assert result.outcome is not OverallOutcome.REFUND_VERIFIED
    # The engine must not assert that no refund can occur.
    assert "no refund" not in result.summary.lower() or "does not mean" in result.summary.lower()
    _assert_no_invariant_violated(result)


# 3. A reported refund is not confirmed without the refund transaction.


def test_reported_refund_never_confirmed_without_tx():
    result = reconcile(
        [
            ev(
                "ev-refund",
                Stage.REFUND,
                EventType.REFUND_CLAIMED,
                Verification.REPORTED,
                reported_status="REFUNDED",
                details={"refunded_amount": "1000"},
            )
        ],
        {"oneclick_status": SourceStatus.OK},
    )
    assert result.stage(Stage.REFUND).state is StageState.REPORTED
    assert result.outcome is OverallOutcome.REFUND_REPORTED_UNVERIFIED
    _assert_no_invariant_violated(result)


# 4. A reported intent failure is not proof funds were lost.


def test_reported_failure_is_not_loss():
    for status in ("FAILED", "INCOMPLETE_DEPOSIT"):
        result = reconcile(
            [
                ev(
                    "ev-f",
                    Stage.NEAR_SETTLEMENT,
                    EventType.UPSTREAM_STATUS,
                    Verification.REPORTED,
                    reported_status=status,
                )
            ],
            {"oneclick_status": SourceStatus.OK},
        )
        assert result.outcome is OverallOutcome.FAILED_REPORTED_UNVERIFIED
        assert "lost." not in result.summary.replace("not proof that funds were lost.", "")
        _assert_no_invariant_violated(result)


# 5. A successful source transaction is not proof the swap settled.


def test_source_success_is_not_settlement():
    result = reconcile(
        [
            ev(
                "ev-src",
                Stage.SOURCE_CHAIN_DEPOSIT,
                EventType.SOURCE_TX_EXECUTED,
                Verification.CONFIRMED,
                reported_status="SUCCESS",
            ),
            ev(
                "ev-deposit",
                Stage.BRIDGE_DEPOSIT_CREDIT,
                EventType.DEPOSIT_OBSERVED,
                Verification.REPORTED,
                reported_status="SUCCESS",
            ),
        ],
        {"oneclick_status": SourceStatus.OK},
    )
    assert result.outcome is not OverallOutcome.SETTLED_VERIFIED
    assert result.last_confirmed_stage is Stage.SOURCE_CHAIN_DEPOSIT
    _assert_no_invariant_violated(result)


# 6. An unavailable RPC never causes a failed label.


@pytest.mark.parametrize(
    "status",
    [
        SourceStatus.TIMEOUT,
        SourceStatus.NETWORK_ERROR,
        SourceStatus.SERVER_ERROR,
        SourceStatus.RATE_LIMITED,
        SourceStatus.UNAUTHORIZED,
        SourceStatus.UNSUPPORTED,
        SourceStatus.MALFORMED,
    ],
)
def test_unavailable_rpc_never_failure(status):
    result = reconcile([], {"oneclick_status": SourceStatus.OK, "evm_rpc": status})
    assert result.outcome is not OverallOutcome.FAILED_VERIFIED
    assert result.outcome is not OverallOutcome.FAILED_REPORTED_UNVERIFIED
    _assert_no_invariant_violated(result)


# 7. Amount / timestamp similarity must never be a correlation basis.


def test_engine_never_correlates_by_amount_or_timestamp():
    """Structurally, the engine has no access to amounts/timestamps for linking.

    Two pieces of evidence with identical amounts and timestamps but no shared
    identifier must not be linked into a settlement claim.
    """
    result = reconcile(
        [
            ev(
                "ev-a",
                Stage.SOURCE_CHAIN_DEPOSIT,
                EventType.SOURCE_TX_EXECUTED,
                Verification.CONFIRMED,
                reported_status="SUCCESS",
                details={"amount": "1000", "timestamp": "2026-01-01T00:00:00Z"},
            ),
            ev(
                "ev-b",
                Stage.DESTINATION_CHAIN_DELIVERY,
                EventType.DESTINATION_TRANSFER_OBSERVED,
                Verification.REPORTED,
                reported_status="SUCCESS",
                details={"amount": "1000", "timestamp": "2026-01-01T00:00:00Z"},
            ),
        ],
        {"oneclick_status": SourceStatus.OK},
    )
    # The destination stage is only REPORTED, so nothing is treated as verified.
    assert result.stage(Stage.DESTINATION_CHAIN_DELIVERY).state is StageState.REPORTED
    assert result.outcome is not OverallOutcome.SETTLED_VERIFIED
    assert result.safety["no_amount_or_time_correlation"] is True


# 8. A hash commitment is not proof the committed event is true.


def test_hash_commitment_is_not_proof():
    """A confirmed transaction hash is not proof the semantic event occurred."""
    result = reconcile(
        [
            ev(
                "ev-near-included",
                Stage.NEAR_SETTLEMENT,
                EventType.NEAR_TX_INCLUDED,
                Verification.CONFIRMED,
                tx_hash="abc",
            ),
            ev(
                "ev-near-final",
                Stage.NEAR_SETTLEMENT,
                EventType.NEAR_TX_FINAL,
                Verification.CONFIRMED,
                tx_hash="abc",
            ),
        ],
        {"near_rpc": SourceStatus.OK},
    )
    # Inclusion + finality alone must not confirm settlement.
    assert result.stage(Stage.NEAR_SETTLEMENT).state is not StageState.CONFIRMED
    assert result.outcome is not OverallOutcome.SETTLED_VERIFIED
    assert result.safety["hash_commitment_is_not_proof"] is True


# Additional: simulated evidence can never produce a verified outcome.


def test_simulated_never_produces_verified_outcome():
    result = reconcile(
        [
            ev(
                "ev-sim",
                Stage.DESTINATION_CHAIN_DELIVERY,
                EventType.DESTINATION_TRANSFER_OBSERVED,
                Verification.SIMULATED,
                provenance=Provenance.SIMULATED,
            ),
            ev(
                "ev-sim2",
                Stage.NEAR_SETTLEMENT,
                EventType.INTENT_EVENT_OBSERVED,
                Verification.SIMULATED,
                provenance=Provenance.SIMULATED,
            ),
        ],
        {"oneclick_status": SourceStatus.OK},
    )
    assert result.outcome not in {OverallOutcome.SETTLED_VERIFIED, OverallOutcome.REFUND_VERIFIED}
    assert "simulated" in result.summary.lower()


# Additional: the engine never invents a failure outcome without confirmed failure.


def test_no_failed_verified_without_confirmed_failure_evidence():
    result = reconcile(
        [
            ev(
                "ev-x",
                Stage.NEAR_SETTLEMENT,
                EventType.SETTLEMENT_CLAIMED,
                Verification.REPORTED,
                reported_status="SUCCESS",
            )
        ],
        {"oneclick_status": SourceStatus.OK},
    )
    assert result.outcome is not OverallOutcome.FAILED_VERIFIED


# THE GATE: the engine must never claim a refund or a destination delivery
# without the required evidence, across a broad matrix of partial evidence.

_CLAIM_GATE_CASES = {
    "empty": [],
    "reported_refund_only": [
        ev(
            "ev-refund",
            Stage.REFUND,
            EventType.REFUND_CLAIMED,
            Verification.REPORTED,
            reported_status="REFUNDED",
            details={"refunded_amount": "5"},
        )
    ],
    "refunded_status_zero_amount": [
        ev(
            "ev-refund",
            Stage.REFUND,
            EventType.REFUND_CLAIMED,
            Verification.REPORTED,
            reported_status="REFUNDED",
            details={"refunded_amount": "0"},
        )
    ],
    "destination_included_only": [
        ev(
            "ev-dest-inc",
            Stage.DESTINATION_CHAIN_DELIVERY,
            EventType.DESTINATION_TX_INCLUDED,
            Verification.CONFIRMED,
            tx_hash="0x1",
        )
    ],
    "destination_executed_only": [
        ev(
            "ev-dest-exec",
            Stage.DESTINATION_CHAIN_DELIVERY,
            EventType.DESTINATION_TX_EXECUTED,
            Verification.CONFIRMED,
            reported_status="SUCCESS",
            tx_hash="0x1",
        )
    ],
    "destination_transfer_unavailable": [
        ev(
            "ev-dest-xfer",
            Stage.DESTINATION_CHAIN_DELIVERY,
            EventType.DESTINATION_TRANSFER_OBSERVED,
            Verification.UNAVAILABLE,
        )
    ],
    "reported_success_no_chain_evidence": [
        ev(
            "ev-claim",
            Stage.NEAR_SETTLEMENT,
            EventType.SETTLEMENT_CLAIMED,
            Verification.REPORTED,
            reported_status="SUCCESS",
        )
    ],
    "simulated_delivery": [
        ev(
            "ev-sim",
            Stage.DESTINATION_CHAIN_DELIVERY,
            EventType.DESTINATION_TRANSFER_OBSERVED,
            Verification.SIMULATED,
            provenance=Provenance.SIMULATED,
        )
    ],
    "simulated_refund": [
        ev(
            "ev-sim",
            Stage.REFUND,
            EventType.REFUND_TX_CONFIRMED,
            Verification.SIMULATED,
            provenance=Provenance.SIMULATED,
        )
    ],
}


@pytest.mark.parametrize("name", sorted(_CLAIM_GATE_CASES))
def test_engine_never_claims_without_required_evidence(name):
    """Fails if the engine claims refund/delivery without the required evidence."""
    result = reconcile(_CLAIM_GATE_CASES[name], {"oneclick_status": SourceStatus.OK})
    assert result.outcome is not OverallOutcome.REFUND_VERIFIED, (
        f"{name}: engine claimed a verified refund without a confirmed refund transaction"
    )
    assert result.outcome is not OverallOutcome.SETTLED_VERIFIED, (
        f"{name}: engine claimed verified settlement without confirmed delivery evidence"
    )
    _assert_no_invariant_violated(result)


def test_gate_also_holds_when_all_sources_are_down():
    statuses = {
        "oneclick_status": SourceStatus.TIMEOUT,
        "near_rpc": SourceStatus.NETWORK_ERROR,
        "evm_rpc": SourceStatus.SERVER_ERROR,
        "solver_relay": SourceStatus.RATE_LIMITED,
    }
    for name, evidence in _CLAIM_GATE_CASES.items():
        result = reconcile(evidence, statuses)
        assert result.outcome is not OverallOutcome.REFUND_VERIFIED, name
        assert result.outcome is not OverallOutcome.SETTLED_VERIFIED, name
