"""Tests for the deterministic attack scenarios and the settlement assurance view.

The attack scenarios are the security track's evidence: each runs against the
real controls and asserts the expected outcome. The settlement tests assert the
honesty rule that a provider's success is never independent proof.
"""

from __future__ import annotations

import pytest

from tracesettle.model import (
    OverallOutcome,
    ReconciliationResult,
    SourceStatus,
    Stage,
    StageAssessment,
    StageState,
)
from tracesettle.near.attacks import (
    SCENARIOS,
    SIMULATION_NOTE,
    run_all,
    run_scenario,
    scenario_catalog,
)
from tracesettle.near.settlement import (
    AssuranceLevel,
    settlement_assurance_from_result,
)

# --- attack scenarios -------------------------------------------------------


def test_every_scenario_is_registered():
    assert set(SCENARIOS) == set("ABCDEFGHI")


def test_every_scenario_passes():
    results = run_all()
    assert len(results) == 9
    for result in results:
        assert result.passed, f"scenario {result.scenario_id} failed: {result.observed}"


def test_scenario_a_allows_a_legitimate_payment():
    result = run_scenario("A")
    assert result.passed
    assert "ALLOW" in result.observed


def test_scenario_b_blocks_an_injected_destination():
    result = run_scenario("B")
    assert result.passed
    assert result.observed == "BLOCK"


def test_scenario_c_refuses_a_changed_destination():
    result = run_scenario("C")
    assert result.passed
    assert "WRONG_PARAMETERS" in result.observed


def test_scenario_d_requires_approval_then_blocks():
    result = run_scenario("D")
    assert result.passed
    assert result.evidence["over_threshold"] == "REQUIRE_APPROVAL"
    assert result.evidence["over_limit"] == "BLOCK"


def test_scenario_e_blocks_an_unauthorised_identity():
    result = run_scenario("E")
    assert result.passed
    assert result.observed == "BLOCK"


def test_scenario_f_refuses_a_replay_and_runs_the_executor_once():
    result = run_scenario("F")
    assert result.passed
    assert result.evidence["signer_state"] == "REPLAYED"
    assert result.evidence["executor_executions"] == 1


def test_scenario_g_blocks_an_operation_outside_the_key_scope():
    result = run_scenario("G")
    assert result.passed
    assert "ACCESS_KEY_SCOPE_REJECTED" in result.evidence["findings"]


def test_scenario_h_rejects_a_native_tx_and_states_the_scope_gap():
    result = run_scenario("H")
    assert result.passed
    assert "POLICY_SCOPE_REJECTED" in result.evidence["findings"]
    assert "destinations" in result.evidence["non_applicable_controls"]


def test_scenario_i_is_unknown_or_unavailable():
    result = run_scenario("I")
    assert result.passed
    assert result.observed in {"UNKNOWN", "UNAVAILABLE"}


def test_every_scenario_is_labelled_simulated():
    for result in run_all():
        assert result.simulated is True
        assert result.to_dict()["simulated"] is True


def test_no_scenario_reaches_the_executor_except_the_allowed_ones():
    """The refusal scenarios must provably never call the executor."""
    for result in run_all():
        executions = result.evidence.get("executor_executions")
        if executions is None:
            continue
        if result.scenario_id in {"A", "F"}:
            assert executions >= 1
        else:
            assert executions == 0, f"scenario {result.scenario_id} reached the executor"


def test_scenarios_are_deterministic():
    """Identical inputs must produce identical outcomes on every run."""
    first = [(r.scenario_id, r.observed) for r in run_all()]
    second = [(r.scenario_id, r.observed) for r in run_all()]
    assert first == second


def test_scenario_catalog_is_machine_readable():
    catalog = scenario_catalog()
    assert len(catalog) == 9
    assert all("id" in entry for entry in catalog)


def test_unknown_scenario_is_rejected():
    with pytest.raises(KeyError):
        run_scenario("Z")


def test_simulation_note_states_it_is_simulated():
    assert "simulat" in SIMULATION_NOTE.lower()
    assert "no" in SIMULATION_NOTE.lower()


# --- settlement assurance ---------------------------------------------------


def _result(outcome, stages, *, source_statuses=None):
    return ReconciliationResult(
        stages=tuple(
            StageAssessment(stage=stage, state=state, summary=f"{stage.value} {state.value}")
            for stage, state in stages
        ),
        last_confirmed_stage=None,
        outcome=outcome,
        summary="test",
        source_statuses=source_statuses or {},
    )


def test_a_verified_settlement_is_verified():
    result = _result(
        OverallOutcome.SETTLED_VERIFIED,
        [
            (Stage.SOURCE_CHAIN_DEPOSIT, StageState.CONFIRMED),
            (Stage.BRIDGE_DEPOSIT_CREDIT, StageState.CONFIRMED),
            (Stage.NEAR_SETTLEMENT, StageState.CONFIRMED),
            (Stage.DESTINATION_CHAIN_DELIVERY, StageState.CONFIRMED),
        ],
    )
    assurance = settlement_assurance_from_result(result)
    assert assurance.level is AssuranceLevel.VERIFIED
    assert assurance.independently_verified is True


def test_a_provider_claim_without_evidence_is_not_verified():
    """The mission's rule: provider success is a claim, never proof."""
    result = _result(
        OverallOutcome.SETTLED_REPORTED_ONLY,
        [
            (Stage.SOURCE_CHAIN_DEPOSIT, StageState.CONFIRMED),
            (Stage.NEAR_SETTLEMENT, StageState.REPORTED),
            (Stage.DESTINATION_CHAIN_DELIVERY, StageState.REPORTED),
        ],
    )
    assurance = settlement_assurance_from_result(result, provider_reported_success=True)
    assert assurance.level is AssuranceLevel.REPORTED_ONLY
    assert assurance.independently_verified is False
    assert assurance.provider_claimed_success is True
    assert any("REPORTED" in limitation for limitation in assurance.limitations)


def test_a_provider_claim_with_no_evidence_is_unknown():
    result = _result(
        OverallOutcome.UNKNOWN,
        [
            (Stage.SOURCE_CHAIN_DEPOSIT, StageState.MISSING),
            (Stage.NEAR_SETTLEMENT, StageState.MISSING),
            (Stage.DESTINATION_CHAIN_DELIVERY, StageState.MISSING),
        ],
    )
    assurance = settlement_assurance_from_result(result, provider_reported_success=True)
    assert assurance.level is AssuranceLevel.UNKNOWN
    assert assurance.independently_verified is False


def test_a_source_outage_is_unavailable_not_unknown():
    result = _result(
        OverallOutcome.UNKNOWN,
        [
            (Stage.SOURCE_CHAIN_DEPOSIT, StageState.UNAVAILABLE),
            (Stage.NEAR_SETTLEMENT, StageState.UNAVAILABLE),
        ],
        source_statuses={"oneclick_status": SourceStatus.TIMEOUT.value},
    )
    assurance = settlement_assurance_from_result(result)
    assert assurance.level is AssuranceLevel.UNAVAILABLE


def test_a_contradiction_is_contradictory():
    from tracesettle.model import Contradiction

    result = ReconciliationResult(
        stages=(),
        last_confirmed_stage=None,
        outcome=OverallOutcome.CONTRADICTORY,
        summary="conflict",
        contradictions=(Contradiction(description="two sources disagree", evidence_ids=("ev-1",)),),
    )
    assurance = settlement_assurance_from_result(result)
    assert assurance.level is AssuranceLevel.CONTRADICTORY
    assert assurance.conflicting_evidence == ("two sources disagree",)


def test_partial_settlement_is_reported_as_partial():
    result = _result(
        OverallOutcome.DELIVERY_UNVERIFIED,
        [
            (Stage.NEAR_SETTLEMENT, StageState.CONFIRMED),
            (Stage.DESTINATION_CHAIN_DELIVERY, StageState.MISSING),
        ],
    )
    assurance = settlement_assurance_from_result(result)
    assert assurance.partial_settlement is True
    assert assurance.independently_verified is False


def test_the_assurance_view_maps_every_near_stage():
    result = _result(OverallOutcome.UNKNOWN, [])
    assurance = settlement_assurance_from_result(result)
    names = {stage.name for stage in assurance.stages}
    assert {
        "deposit_address",
        "source_chain_transaction",
        "deposit_confirmation",
        "intent_execution",
        "destination_transaction",
        "destination_receipt",
        "refund",
    } <= names


def test_the_assurance_view_carries_the_engine_result():
    result = _result(OverallOutcome.UNKNOWN, [])
    assurance = settlement_assurance_from_result(result)
    assert assurance.engine["outcome"] == "UNKNOWN"


def test_assurance_dict_is_serializable():
    result = _result(OverallOutcome.UNKNOWN, [])
    assurance = settlement_assurance_from_result(result)
    data = assurance.to_dict()
    assert data["level"] == "UNKNOWN"
    assert isinstance(data["stages"], list)


# --- amount-based partial settlement ----------------------------------------


def _delivered_result():
    return _result(
        OverallOutcome.SETTLED_VERIFIED,
        [
            (Stage.SOURCE_CHAIN_DEPOSIT, StageState.CONFIRMED),
            (Stage.BRIDGE_DEPOSIT_CREDIT, StageState.CONFIRMED),
            (Stage.NEAR_SETTLEMENT, StageState.CONFIRMED),
            (Stage.DESTINATION_CHAIN_DELIVERY, StageState.CONFIRMED),
        ],
    )


def test_a_confirmed_shortfall_is_partial_and_not_verified():
    assurance = settlement_assurance_from_result(
        _delivered_result(), expected_amount_out="1000000", observed_amount_out="990000"
    )
    assert assurance.level is AssuranceLevel.PARTIAL
    assert assurance.independently_verified is False
    assert assurance.partial_settlement is True
    assert assurance.shortfall == "10000"
    assert assurance.expected_amount_out == "1000000"
    assert assurance.observed_amount_out == "990000"


def test_a_full_delivery_stays_verified():
    assurance = settlement_assurance_from_result(
        _delivered_result(), expected_amount_out="1000000", observed_amount_out="1000000"
    )
    assert assurance.level is AssuranceLevel.VERIFIED
    assert assurance.independently_verified is True
    assert assurance.shortfall == "0"


def test_an_over_delivery_is_not_a_shortfall():
    assurance = settlement_assurance_from_result(
        _delivered_result(), expected_amount_out="1000000", observed_amount_out="1000001"
    )
    assert assurance.level is AssuranceLevel.VERIFIED
    assert assurance.shortfall == "0"


def test_a_shortfall_without_a_confirmed_delivery_is_not_partial():
    """A lower amount against an unconfirmed delivery is unverified, not partial."""
    result = _result(
        OverallOutcome.SETTLED_REPORTED_ONLY,
        [
            (Stage.NEAR_SETTLEMENT, StageState.REPORTED),
            (Stage.DESTINATION_CHAIN_DELIVERY, StageState.REPORTED),
        ],
    )
    assurance = settlement_assurance_from_result(
        result, expected_amount_out="1000000", observed_amount_out="900000"
    )
    assert assurance.level is not AssuranceLevel.PARTIAL
    assert assurance.independently_verified is False
    assert any("not independently confirmed" in limitation for limitation in assurance.limitations)


def test_a_malformed_amount_is_never_turned_into_a_numeric_claim():
    for expected, observed in [("abc", "100"), ("100", "x"), ("0", "100"), ("100", None)]:
        assurance = settlement_assurance_from_result(
            _delivered_result(), expected_amount_out=expected, observed_amount_out=observed
        )
        assert assurance.shortfall is None
        assert assurance.expected_amount_out is None


def test_a_contradiction_is_not_masked_by_a_shortfall():
    from tracesettle.model import Contradiction

    result = ReconciliationResult(
        stages=(
            StageAssessment(
                stage=Stage.DESTINATION_CHAIN_DELIVERY,
                state=StageState.CONFIRMED,
                summary="confirmed",
            ),
        ),
        last_confirmed_stage=None,
        outcome=OverallOutcome.CONTRADICTORY,
        summary="conflict",
        contradictions=(Contradiction(description="sources disagree", evidence_ids=("ev-1",)),),
    )
    assurance = settlement_assurance_from_result(
        result, expected_amount_out="1000000", observed_amount_out="900000"
    )
    assert assurance.level is AssuranceLevel.CONTRADICTORY
