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
        "refund_confirmation_requires_onchain_evidence",
        "bitcoin_refund_requires_confirmed_payout",
        "reported_failure_is_not_loss",
        "source_success_is_not_settlement",
        "unavailable_rpc_is_not_failure",
        "no_amount_or_time_correlation",
        "hash_commitment_is_not_proof",
        "simulated_evidence_never_confirms",
        "reverted_execution_never_confirms",
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


def test_missing_destination_is_not_failure_but_a_genuine_failure_is_not_a_violation():
    """The invariant forbids inferring failure from absence, not confirmed failure.

    A confirmed transaction-level failure with no confirmed delivery is a genuine
    FAILED_VERIFIED and must not be reported as an invariant violation; a verdict
    with no confirmed failure evidence must never be FAILED_VERIFIED.
    """
    genuine = reconcile(
        [
            ev(
                "ev-near-exec",
                Stage.NEAR_SETTLEMENT,
                EventType.NEAR_TX_EXECUTION,
                Verification.CONFIRMED,
                tx_hash="h",
                chain="near",
                reported_status="FAILED",
                details={"execution_failed": True},
            )
        ],
        {"near_rpc": SourceStatus.OK},
    )
    assert genuine.outcome is OverallOutcome.FAILED_VERIFIED
    assert genuine.safety["no_missing_destination_is_failure"] is True
    _assert_no_invariant_violated(genuine)


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


def test_simulated_evidence_with_confirmed_label_never_confirms():
    """Simulated provenance must dominate a CONFIRMED verification label.

    A stage can only be confirmed by authoritative, non-simulated evidence. This
    holds even when simulated evidence is mislabelled as CONFIRMED, so no future
    adapter or fixture can accidentally produce a verified outcome from test data.
    """
    sim = lambda i, stage, evt: ev(  # noqa: E731
        i, stage, evt, Verification.CONFIRMED, provenance=Provenance.SIMULATED
    )
    result = reconcile(
        [
            sim("ev-sim-src", Stage.SOURCE_CHAIN_DEPOSIT, EventType.SOURCE_TX_EXECUTED),
            sim("ev-sim-bridge", Stage.BRIDGE_DEPOSIT_CREDIT, EventType.DEPOSIT_OBSERVED),
            sim("ev-sim-settle", Stage.NEAR_SETTLEMENT, EventType.INTENT_EVENT_OBSERVED),
            sim("ev-sim-dest", Stage.DESTINATION_CHAIN_DELIVERY, EventType.DESTINATION_TRANSFER_OBSERVED),
        ],
        {"near_rpc": SourceStatus.OK, "evm_rpc": SourceStatus.OK},
    )
    for stage in (
        Stage.SOURCE_CHAIN_DEPOSIT,
        Stage.BRIDGE_DEPOSIT_CREDIT,
        Stage.NEAR_SETTLEMENT,
        Stage.DESTINATION_CHAIN_DELIVERY,
    ):
        assert result.stage(stage).state is not StageState.CONFIRMED, (
            f"{stage} was confirmed from simulated evidence"
        )
    assert result.outcome is not OverallOutcome.SETTLED_VERIFIED
    _assert_no_invariant_violated(result)


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


# Additional: settlement evidence must name the investigated intent, not any intent.


_OTHER_INTENT = "SomeoneElsesIntentHash111111111111111111111"
_OUR_INTENT = "OurIntentHash9999999999999999999999999999"


def _intent_event(item_id: str, hashes: list[str]):
    return ev(
        item_id,
        Stage.NEAR_SETTLEMENT,
        EventType.INTENT_EVENT_OBSERVED,
        Verification.CONFIRMED,
        tx_hash="nearTx",
        details={"intent_hashes": hashes, "standard": "dip4"},
    )


def test_settlement_requires_the_investigated_intent():
    """Logs naming a different intent must not confirm *our* settlement."""
    result = reconcile(
        [_intent_event("ev-other", [_OTHER_INTENT])],
        {"near_rpc": SourceStatus.OK},
        expected_intent_hashes=[_OUR_INTENT],
    )
    stage = result.stage(Stage.NEAR_SETTLEMENT)
    assert stage.state is not StageState.CONFIRMED, (
        "settlement was confirmed from an unrelated intent in the same transaction"
    )
    assert result.outcome is not OverallOutcome.SETTLED_VERIFIED
    assert "different intent" in stage.summary.lower()
    _assert_no_invariant_violated(result)


def test_settlement_confirms_when_investigated_intent_present():
    """The same shape of evidence confirms when it names our intent."""
    result = reconcile(
        [_intent_event("ev-ours", [_OTHER_INTENT, _OUR_INTENT])],
        {"near_rpc": SourceStatus.OK},
        expected_intent_hashes=[_OUR_INTENT],
    )
    assert result.stage(Stage.NEAR_SETTLEMENT).state is StageState.CONFIRMED


def test_settlement_without_expectation_is_backwards_compatible():
    """When no intent expectation is supplied, behaviour is unchanged."""
    result = reconcile(
        [_intent_event("ev-any", [_OTHER_INTENT])],
        {"near_rpc": SourceStatus.OK},
    )
    assert result.stage(Stage.NEAR_SETTLEMENT).state is StageState.CONFIRMED


# Additional: determinism. Identical evidence must produce identical results.


def test_reconciliation_is_deterministic():
    evidence = [
        ev(
            "ev-b",
            Stage.NEAR_SETTLEMENT,
            EventType.INTENT_EVENT_OBSERVED,
            Verification.CONFIRMED,
            tx_hash="nearTx",
            details={"intent_hashes": [_OUR_INTENT], "standard": "dip4"},
        ),
        ev(
            "ev-a",
            Stage.SOURCE_CHAIN_DEPOSIT,
            EventType.SOURCE_TX_EXECUTED,
            Verification.CONFIRMED,
            tx_hash="0xorigin",
        ),
        ev(
            "ev-c",
            Stage.REFUND,
            EventType.REFUND_CLAIMED,
            Verification.REPORTED,
            reported_status="REFUNDED",
        ),
    ]
    statuses = {"oneclick_status": SourceStatus.OK, "near_rpc": SourceStatus.OK}
    first = reconcile(evidence, statuses, expected_intent_hashes=[_OUR_INTENT])
    # Shuffle the input order; the engine sorts internally, so results must match.
    second = reconcile(list(reversed(evidence)), statuses, expected_intent_hashes=[_OUR_INTENT])
    assert first.to_dict() == second.to_dict(), "reconciliation is not deterministic"


# Additional: an unsupported chain yields UNAVAILABLE, never a failure.


def test_unsupported_chain_is_unavailable_not_failure():
    result = reconcile(
        [
            ev(
                "ev-origin-unsupported",
                Stage.SOURCE_CHAIN_DEPOSIT,
                EventType.SOURCE_TX_INCLUDED,
                Verification.UNAVAILABLE,
                details={"reason": "UNSUPPORTED_CHAIN"},
            )
        ],
        {"oneclick_status": SourceStatus.OK, "evm_rpc": SourceStatus.UNSUPPORTED},
    )
    assert result.stage(Stage.SOURCE_CHAIN_DEPOSIT).state is StageState.UNAVAILABLE
    assert result.outcome is not OverallOutcome.FAILED_VERIFIED
    assert result.outcome is not OverallOutcome.FAILED_REPORTED_UNVERIFIED
    _assert_no_invariant_violated(result)


# Additional: a transaction hash alone never establishes a semantic transfer.


def test_hash_alone_is_not_a_transfer():
    """Inclusion and execution of a hash is not the same as an observed transfer."""
    result = reconcile(
        [
            ev(
                "ev-inc",
                Stage.DESTINATION_CHAIN_DELIVERY,
                EventType.DESTINATION_TX_INCLUDED,
                Verification.CONFIRMED,
                tx_hash="0xdest",
            ),
            ev(
                "ev-exec",
                Stage.DESTINATION_CHAIN_DELIVERY,
                EventType.DESTINATION_TX_EXECUTED,
                Verification.CONFIRMED,
                tx_hash="0xdest",
            ),
        ],
        {"evm_rpc": SourceStatus.OK},
    )
    assert result.stage(Stage.DESTINATION_CHAIN_DELIVERY).state is not StageState.CONFIRMED
    assert result.outcome is not OverallOutcome.SETTLED_VERIFIED
    _assert_no_invariant_violated(result)


# Additional: bridge-deposit-credit evidence must name the investigated origin tx.


def _bridge_credit(item_id: str, origin_hashes: list[str]):
    return ev(
        item_id,
        Stage.BRIDGE_DEPOSIT_CREDIT,
        EventType.DEPOSIT_OBSERVED,
        Verification.CONFIRMED,
        tx_hash="nearBridgeTx",
        details={"bridged_from_origin_hashes": origin_hashes, "memo_marker": "BRIDGED_FROM"},
    )


def test_bridge_credit_requires_the_investigated_origin_tx():
    """A bridge credit naming another deposit's origin tx must not confirm ours."""
    other = "0x" + "1" * 64
    ours = "0x" + "2" * 64
    result = reconcile(
        [_bridge_credit("ev-bridge-other", [other])],
        {"near_rpc": SourceStatus.OK},
        expected_origin_tx_hashes=[ours],
    )
    stage = result.stage(Stage.BRIDGE_DEPOSIT_CREDIT)
    assert stage.state is not StageState.CONFIRMED, (
        "bridge credit was confirmed from an unrelated deposit's origin transaction"
    )
    assert "different origin" in stage.summary.lower()
    _assert_no_invariant_violated(result)


def test_bridge_credit_confirms_when_origin_tx_matches():
    ours = "0x" + "2" * 64
    result = reconcile(
        [_bridge_credit("ev-bridge-ours", [ours])],
        {"near_rpc": SourceStatus.OK},
        expected_origin_tx_hashes=[ours],
    )
    assert result.stage(Stage.BRIDGE_DEPOSIT_CREDIT).state is StageState.CONFIRMED


def test_bridge_credit_without_expectation_is_backwards_compatible():
    other = "0x" + "1" * 64
    result = reconcile(
        [_bridge_credit("ev-bridge-any", [other])],
        {"near_rpc": SourceStatus.OK},
    )
    assert result.stage(Stage.BRIDGE_DEPOSIT_CREDIT).state is StageState.CONFIRMED


def test_bridge_credit_origin_hash_match_is_case_insensitive():
    """Hex origin hashes differ in case across sources; matching must ignore it.

    The investigated hash and the memo's ``BRIDGED_FROM`` hash come from different
    producers, so one may be checksummed and the other lowercase. A match must not
    depend on case, and the ``0X`` prefix form must be handled too.
    """
    canonical = "0xfca11aa01bce5fc20a6cbeb4ca30e8af994cda47de9bd5fa53a9ca4295ba01d2"
    for observed in (canonical.upper(), "0X" + canonical[2:].upper()):
        result = reconcile(
            [_bridge_credit("ev-bridge-case", [observed])],
            {"near_rpc": SourceStatus.OK},
            expected_origin_tx_hashes=[canonical],
        )
        assert result.stage(Stage.BRIDGE_DEPOSIT_CREDIT).state is StageState.CONFIRMED, (
            f"case-differing origin hash {observed!r} failed to match the investigated hash"
        )


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
    "contradictory_refund": [
        ev(
            "ev-refund-contradiction",
            Stage.REFUND,
            EventType.REFUND_TX_CONFIRMED,
            Verification.CONTRADICTORY,
            tx_hash="377b55cbc30363d991838b4803c8c83b231d0193e4b31f8e527728520469721f",
            chain="btc",
            details={"reason": "TXID_BYTES_MISMATCH"},
        )
    ],
    "contradictory_refund_alongside_confirmed_payout": [
        ev(
            "ev-refund-contradiction",
            Stage.REFUND,
            EventType.REFUND_TX_CONFIRMED,
            Verification.CONTRADICTORY,
            tx_hash="377b55cbc30363d991838b4803c8c83b231d0193e4b31f8e527728520469721f",
            chain="btc",
            details={"reason": "TXID_BYTES_MISMATCH"},
        ),
        ev(
            "ev-refund-ok",
            Stage.REFUND,
            EventType.REFUND_TX_CONFIRMED,
            Verification.CONFIRMED,
            tx_hash="9a80de61146553e809f2e57a7b789ae5e64de7aa67fa06009881eac638051226",
            chain="btc",
        ),
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


# --- State-transition invariants (Phase 3 audit) ----------------------------
#
# These fail if the engine permits an invalid transition: a state that must never
# be produced from the given evidence.


def test_reported_never_becomes_confirmed_from_a_favourable_status_alone():
    """A favourable upstream status must never, by itself, confirm any stage."""
    evidence = [
        ev(
            "ev-claim",
            Stage.NEAR_SETTLEMENT,
            EventType.SETTLEMENT_CLAIMED,
            Verification.REPORTED,
            reported_status="SUCCESS",
        ),
        ev(
            "ev-claim2",
            Stage.SOURCE_CHAIN_DEPOSIT,
            EventType.UPSTREAM_STATUS,
            Verification.REPORTED,
            reported_status="SUCCESS",
        ),
    ]
    result = reconcile(evidence, {"oneclick_status": SourceStatus.OK})
    assert result.stage(Stage.NEAR_SETTLEMENT).state is not StageState.CONFIRMED
    assert result.stage(Stage.SOURCE_CHAIN_DEPOSIT).state is not StageState.CONFIRMED
    assert result.outcome is not OverallOutcome.SETTLED_VERIFIED


def test_unavailable_never_becomes_confirmed_without_new_evidence():
    """An unavailable source alone can never confirm a stage."""
    result = reconcile(
        [
            ev(
                "ev-refund-unavailable",
                Stage.REFUND,
                EventType.REFUND_TX_CONFIRMED,
                Verification.UNAVAILABLE,
                source="btc_rpc",
                chain="btc",
            )
        ],
        {"oneclick_status": SourceStatus.TIMEOUT, "btc_rpc": SourceStatus.TIMEOUT},
    )
    assert result.stage(Stage.REFUND).state is not StageState.CONFIRMED
    assert result.outcome is not OverallOutcome.REFUND_VERIFIED


def test_incomplete_search_never_becomes_a_unique_candidate_confirmation():
    """INCOMPLETE evidence must never be read as a confirmed refund."""
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
            )
        ],
        {"oneclick_status": SourceStatus.OK, "btc_rpc": SourceStatus.OK},
    )
    assert result.stage(Stage.REFUND).state is not StageState.CONFIRMED
    assert result.outcome is not OverallOutcome.REFUND_VERIFIED


def test_contradictory_evidence_is_not_silently_downgraded_to_a_note():
    """A contradiction must surface as a contradiction, not a passing note."""
    result = reconcile(
        [
            ev(
                "ev-refund-contradiction",
                Stage.REFUND,
                EventType.REFUND_TX_CONFIRMED,
                Verification.CONTRADICTORY,
                source="btc_rpc",
                chain="btc",
                tx_hash="b" * 64,
                details={"reason": "TXID_BYTES_MISMATCH"},
            )
        ],
        {"oneclick_status": SourceStatus.OK, "btc_rpc": SourceStatus.OK},
    )
    assert result.stage(Stage.REFUND).state is StageState.CONTRADICTORY
    assert result.outcome is OverallOutcome.CONTRADICTORY
    assert result.contradictions, "the contradiction must be reported, not hidden"


def test_verified_transaction_is_not_a_verified_refund_without_correlation():
    """A confirmed transaction that is not tied to the refund must not confirm REFUND.

    Only a REFUND_TX_CONFIRMED item with a tx hash confirms REFUND. A confirmed
    source-chain transaction is not refund evidence.
    """
    result = reconcile(
        [
            ev(
                "ev-source-exec",
                Stage.SOURCE_CHAIN_DEPOSIT,
                EventType.SOURCE_TX_EXECUTED,
                Verification.CONFIRMED,
                tx_hash="0xorigin",
                chain="eth",
            )
        ],
        {"oneclick_status": SourceStatus.OK, "evm_rpc": SourceStatus.OK},
    )
    assert result.stage(Stage.REFUND).state is not StageState.CONFIRMED
    assert result.outcome is not OverallOutcome.REFUND_VERIFIED


def test_missing_refund_hash_is_never_fabricated():
    """A reported refund with no tx hash must not produce a tx hash anywhere."""
    claim = ev(
        "ev-refund-claim",
        Stage.REFUND,
        EventType.REFUND_CLAIMED,
        Verification.REPORTED,
        reported_status="REFUNDED",
        details={"refunded_amount": "11746"},
    )
    assert claim.tx_hash is None
    result = reconcile([claim], {"oneclick_status": SourceStatus.OK})
    assert result.stage(Stage.REFUND).state is StageState.REPORTED
    assert result.outcome is OverallOutcome.REFUND_REPORTED_UNVERIFIED
    assert result.last_confirmed_stage is None


# 12. A confirmed revert never confirms a stage.


def test_reverted_origin_transaction_is_never_confirmed():
    """A confirmed REVERTED origin tx must not confirm the deposit stage."""
    result = reconcile(
        [
            ev(
                "ev-origin-included",
                Stage.SOURCE_CHAIN_DEPOSIT,
                EventType.SOURCE_TX_INCLUDED,
                Verification.CONFIRMED,
                source="evm_rpc",
                reported_status="REVERTED",
                tx_hash="0xreverted",
                chain="eth",
                details={"execution_succeeded": False},
            ),
            ev(
                "ev-origin-executed",
                Stage.SOURCE_CHAIN_DEPOSIT,
                EventType.SOURCE_TX_EXECUTED,
                Verification.CONFIRMED,
                source="evm_rpc",
                reported_status="REVERTED",
                tx_hash="0xreverted",
                chain="eth",
                details={"execution_succeeded": False},
            ),
        ],
        {"evm_rpc": SourceStatus.OK},
    )
    assert result.stage(Stage.SOURCE_CHAIN_DEPOSIT).state is not StageState.CONFIRMED
    assert result.stage(Stage.SOURCE_CHAIN_DEPOSIT).state is StageState.CONTRADICTORY
    assert result.safety["reverted_execution_never_confirms"] is True
    _assert_no_invariant_violated(result)


def test_reverted_destination_transaction_is_never_confirmed():
    result = reconcile(
        [
            ev(
                "ev-dest-executed",
                Stage.DESTINATION_CHAIN_DELIVERY,
                EventType.DESTINATION_TX_EXECUTED,
                Verification.CONFIRMED,
                source="evm_rpc",
                reported_status="REVERTED",
                tx_hash="0xreverted",
                chain="base",
                details={"execution_succeeded": False},
            ),
        ],
        {"evm_rpc": SourceStatus.OK},
    )
    assert result.stage(Stage.DESTINATION_CHAIN_DELIVERY).state is not StageState.CONFIRMED
    _assert_no_invariant_violated(result)


def test_a_successful_origin_transaction_still_confirms():
    """The revert rule must not weaken an ordinary successful deposit."""
    result = reconcile(
        [
            ev(
                "ev-origin-executed",
                Stage.SOURCE_CHAIN_DEPOSIT,
                EventType.SOURCE_TX_EXECUTED,
                Verification.CONFIRMED,
                source="evm_rpc",
                reported_status="SUCCESS",
                tx_hash="0xok",
                chain="eth",
                details={"execution_succeeded": True},
            ),
        ],
        {"evm_rpc": SourceStatus.OK},
    )
    assert result.stage(Stage.SOURCE_CHAIN_DEPOSIT).state is StageState.CONFIRMED


def test_reported_revert_is_not_treated_as_contradiction():
    """Only a *confirmed* revert is decisive; a reported-only one is not."""
    result = reconcile(
        [
            ev(
                "ev-origin-executed",
                Stage.SOURCE_CHAIN_DEPOSIT,
                EventType.SOURCE_TX_EXECUTED,
                Verification.REPORTED,
                source="oneclick_status",
                reported_status="REVERTED",
                details={"execution_succeeded": False},
            ),
        ],
        {"oneclick_status": SourceStatus.OK},
    )
    assert result.stage(Stage.SOURCE_CHAIN_DEPOSIT).state is StageState.REPORTED
