"""Tests for the agent-side authorization wrapper.

These assert the pre-execution boundary: the wrapper inspects the real
transaction parameters, the NEAR Intents policy scope and the access-key scope,
and refuses (or holds, or asks for approval) before anything can be signed.

No network call is made and no transaction is broadcast. The only substitution
is the simulated executor, and "refused" is asserted as "the executor was never
called".
"""

from __future__ import annotations

import json
import pathlib

from tracesettle.guard.authorization import AuthorizationAuthority, InMemoryReplayStore
from tracesettle.guard.service import GuardService
from tracesettle.guard.signer import ReferenceSigner, SimulatedExecutor
from tracesettle.near.access_keys import parse_access_key
from tracesettle.near.agent_wrapper import (
    AGENT_DECISION_OUTCOMES,
    AgentAuthorizationWrapper,
    AgentTransaction,
    WrapperOutcome,
)
from tracesettle.near.attacks import (
    APPROVED_DESTINATION,
    APPROVED_DESTINATION_2,
    ATTACKER_DESTINATION,
    DEMO_KEY,
    near_demo_policy,
)
from tracesettle.near.policy import PolicyAdapter, PolicyScope

FIXTURE_DIR = pathlib.Path(__file__).resolve().parent / "fixtures" / "near"


def load(name: str) -> dict:
    return json.loads((FIXTURE_DIR / name).read_text())


def in_force_policy():
    return PolicyAdapter.from_fixture(load("policy_in_force.json"))


def scoped_key():
    return parse_access_key(load("access_keys.json")["keys"]["function_call_scoped"])


def full_access_key():
    return parse_access_key(load("access_keys.json")["keys"]["full_access"])


class _CountingExecutor(SimulatedExecutor):
    def __init__(self) -> None:
        super().__init__()
        self.calls = 0

    def execute(self, request, authorization_id):  # noqa: ANN001
        self.calls += 1
        return super().execute(request, authorization_id)


def make_world(*, policy_read=None, access_key=None):
    executor = _CountingExecutor()
    authority = AuthorizationAuthority(
        key=DEMO_KEY, key_id="test", ephemeral=False, replay_store=InMemoryReplayStore()
    )
    service = GuardService(policy=near_demo_policy(), authority=authority)
    service._signer = ReferenceSigner(authority, executor=executor)  # noqa: SLF001
    wrapper = AgentAuthorizationWrapper(
        service,
        policy_read=policy_read if policy_read is not None else in_force_policy(),
        access_key=access_key,
    )
    return service, wrapper, executor


def legit(**overrides) -> AgentTransaction:
    base = dict(
        service_id="treasury-agent",
        operation="WITHDRAWAL",
        chain="base",
        asset="USDC",
        amount="1250.50",
        destination=APPROVED_DESTINATION,
        scope=PolicyScope.INTENTS,
        policy_action="withdraw",
        request_id="t-legit",
    )
    base.update(overrides)
    return AgentTransaction(**base)


def test_all_five_outcomes_are_defined():
    assert set(AGENT_DECISION_OUTCOMES) == {
        "ALLOW",
        "REQUIRE_APPROVAL",
        "BLOCK",
        "HOLD",
        "UNKNOWN",
    }


def test_a_legitimate_intents_withdrawal_is_allowed_and_executes():
    service, wrapper, executor = make_world(access_key=scoped_key())
    decision = wrapper.evaluate(legit())
    assert decision.outcome is WrapperOutcome.ALLOW
    assert decision.permits_signing is True
    submission = wrapper.submit(legit(), decision.authorization)
    assert submission.executed is True
    assert executor.calls == 1


def test_an_unapproved_destination_is_blocked_and_never_reaches_the_executor():
    service, wrapper, executor = make_world(access_key=scoped_key())
    decision = wrapper.evaluate(legit(destination=ATTACKER_DESTINATION))
    assert decision.outcome is WrapperOutcome.BLOCK
    assert decision.permits_signing is False
    assert executor.calls == 0


def test_a_changed_destination_on_a_genuine_token_is_refused_by_parameter_binding():
    """Scenario C: both destinations are approved, so the *binding* refuses."""
    service, wrapper, executor = make_world(access_key=scoped_key())
    decision = wrapper.evaluate(legit())
    token = decision.authorization
    submission = wrapper.submit(legit(destination=APPROVED_DESTINATION_2), token)
    assert submission.outcome is WrapperOutcome.BLOCK
    assert submission.sign_result.state.value == "WRONG_PARAMETERS"
    assert executor.calls == 0


def test_a_replayed_token_is_refused_and_the_executor_runs_once():
    service, wrapper, executor = make_world(access_key=scoped_key())
    decision = wrapper.evaluate(legit())
    token = decision.authorization
    first = wrapper.submit(legit(), token)
    second = wrapper.submit(legit(), token)
    assert first.executed is True
    assert second.outcome is WrapperOutcome.BLOCK
    assert second.sign_result.state.value == "REPLAYED"
    assert executor.calls == 1


def test_an_unregistered_identity_is_blocked():
    service, wrapper, executor = make_world(access_key=scoped_key())
    decision = wrapper.evaluate(legit(service_id="rogue-agent"))
    assert decision.outcome is WrapperOutcome.BLOCK
    assert executor.calls == 0


def test_an_amount_above_the_threshold_requires_approval():
    service, wrapper, executor = make_world(access_key=scoped_key())
    decision = wrapper.evaluate(legit(amount="7500"))
    assert decision.outcome is WrapperOutcome.REQUIRE_APPROVAL
    assert decision.permits_signing is False


def test_an_amount_above_the_hard_limit_is_blocked():
    service, wrapper, executor = make_world(access_key=scoped_key())
    decision = wrapper.evaluate(legit(amount="50000"))
    assert decision.outcome is WrapperOutcome.BLOCK


# --- policy scope -----------------------------------------------------------


def test_a_policy_that_is_not_in_force_requires_approval():
    read = PolicyAdapter.from_fixture(load("policy_not_applied.json"))
    service, wrapper, executor = make_world(policy_read=read)
    decision = wrapper.evaluate(legit())
    assert decision.outcome is WrapperOutcome.REQUIRE_APPROVAL
    codes = {f.code for f in decision.findings}
    assert "POLICY_NOT_IN_FORCE" in codes


def test_a_frozen_agent_is_blocked():
    raw = load("policy_in_force.json")
    raw["frozen"] = True
    read = PolicyAdapter.from_fixture(raw)
    service, wrapper, executor = make_world(policy_read=read)
    decision = wrapper.evaluate(legit())
    assert decision.outcome is WrapperOutcome.BLOCK
    assert "AGENT_FROZEN" in {f.code for f in decision.findings}


def test_a_disabled_action_is_blocked_by_the_policy():
    raw = load("policy_in_force.json")
    raw["actions"] = ["swap"]
    read = PolicyAdapter.from_fixture(raw)
    service, wrapper, executor = make_world(policy_read=read)
    decision = wrapper.evaluate(legit())
    assert decision.outcome is WrapperOutcome.BLOCK
    assert "POLICY_ACTION_DENIED" in {f.code for f in decision.findings}


def test_a_destination_outside_the_policy_list_is_blocked():
    raw = load("policy_in_force.json")
    read = PolicyAdapter.from_fixture(raw)
    service, wrapper, executor = make_world(policy_read=read)
    decision = wrapper.evaluate(legit(destination=ATTACKER_DESTINATION))
    assert decision.outcome is WrapperOutcome.BLOCK
    assert "POLICY_DESTINATION_DENIED" in {f.code for f in decision.findings}


def test_a_native_transfer_with_the_switch_off_is_a_scope_rejection():
    service, wrapper, executor = make_world(policy_read=in_force_policy(), access_key=scoped_key())
    tx = legit(
        operation="TRANSFER",
        chain="near",
        asset="NEAR",
        amount="5",
        destination=APPROVED_DESTINATION,
        scope=PolicyScope.NATIVE_NEAR,
        policy_action="transfer",
        transfers_near=True,
        metadata={"native_method": "transfer"},
    )
    decision = wrapper.evaluate(tx)
    assert decision.outcome is WrapperOutcome.BLOCK
    assert "POLICY_SCOPE_REJECTED" in {f.code for f in decision.findings}


def test_a_native_request_states_the_scope_gap_even_when_the_switch_is_on():
    read = PolicyAdapter.from_fixture(load("policy_native_transfer.json"))
    # No access key: this test isolates the policy scope behaviour.
    service, wrapper, executor = make_world(policy_read=read, access_key=None)
    tx = legit(
        operation="TRANSFER",
        chain="near",
        asset="NEAR",
        amount="5",
        destination=APPROVED_DESTINATION,
        scope=PolicyScope.NATIVE_NEAR,
        policy_action="transfer",
        transfers_near=True,
        metadata={"native_method": "transfer"},
    )
    decision = wrapper.evaluate(tx)
    assert decision.outcome is WrapperOutcome.ALLOW
    assert "destinations" in decision.non_applicable_controls
    assert any("native" in limitation.lower() for limitation in decision.limitations)
    assert "NATIVE_NOT_COVERED_BY_INTENTS_POLICY" in {f.code for f in decision.findings}


def test_an_unreadable_policy_holds_a_native_request():
    """A native request is fenced only by the switch; unreadable -> HOLD."""
    read = PolicyAdapter().read_policy("demo-agent.near")  # UNCONFIGURED
    # No access key: this test isolates the policy availability behaviour.
    service, wrapper, executor = make_world(policy_read=read, access_key=None)
    tx = legit(
        operation="TRANSFER",
        chain="near",
        asset="NEAR",
        amount="5",
        destination=APPROVED_DESTINATION,
        scope=PolicyScope.NATIVE_NEAR,
        policy_action="transfer",
        transfers_near=True,
        metadata={"native_method": "transfer"},
    )
    decision = wrapper.evaluate(tx)
    assert decision.outcome is WrapperOutcome.HOLD
    assert decision.permits_signing is False


def test_an_unreadable_policy_requires_approval_for_an_intents_request():
    read = PolicyAdapter().read_policy("demo-agent.near")
    service, wrapper, executor = make_world(policy_read=read, access_key=scoped_key())
    decision = wrapper.evaluate(legit())
    assert decision.outcome is WrapperOutcome.REQUIRE_APPROVAL


# --- access key -------------------------------------------------------------


def test_a_full_access_key_forces_review():
    service, wrapper, executor = make_world(access_key=full_access_key())
    decision = wrapper.evaluate(legit())
    assert decision.outcome is WrapperOutcome.REQUIRE_APPROVAL
    assert "ACCESS_KEY_FULL_ACCESS" in {f.code for f in decision.findings}


def test_a_function_call_key_cannot_sign_a_native_near_transfer():
    """Scenario G: the key's scope refuses the transfer."""
    service, wrapper, executor = make_world(policy_read=in_force_policy(), access_key=scoped_key())
    tx = legit(
        operation="TRANSFER",
        chain="near",
        asset="NEAR",
        amount="5",
        destination=APPROVED_DESTINATION,
        scope=PolicyScope.NATIVE_NEAR,
        policy_action="transfer",
        transfers_near=True,
        request_id="key-scope",
    )
    decision = wrapper.evaluate(tx)
    assert decision.outcome is WrapperOutcome.BLOCK
    assert "ACCESS_KEY_SCOPE_REJECTED" in {f.code for f in decision.findings}


def test_the_key_check_does_not_fence_an_intents_request():
    """On the Intents path the wallet provider signs, not this key."""
    service, wrapper, executor = make_world(access_key=scoped_key())
    decision = wrapper.evaluate(legit())
    assert decision.outcome is WrapperOutcome.ALLOW


# --- determinism and honesty ------------------------------------------------


def test_identical_inputs_produce_an_identical_decision():
    _, wrapper_a, _ = make_world(access_key=scoped_key())
    _, wrapper_b, _ = make_world(access_key=scoped_key())
    a = wrapper_a.evaluate(legit())
    b = wrapper_b.evaluate(legit())
    assert a.outcome is b.outcome
    assert [f.code for f in a.findings] == [f.code for f in b.findings]


def test_an_invalid_amount_fails_safe_to_unknown():
    service, wrapper, executor = make_world(access_key=scoped_key())
    decision = wrapper.evaluate(legit(amount="not-a-number"))
    assert decision.outcome is WrapperOutcome.UNKNOWN
    assert decision.permits_signing is False


def test_a_client_asserted_approval_flag_is_reported_not_honoured():
    service, wrapper, executor = make_world(access_key=scoped_key())
    decision = wrapper.evaluate(legit(asserted_approval_fields=("approved", "skip_checks")))
    # The guard's own control turns an asserted approval into a review, never an allow.
    assert decision.outcome in {WrapperOutcome.REQUIRE_APPROVAL, WrapperOutcome.BLOCK}
    assert decision.permits_signing is False


def test_a_decision_never_claims_a_real_transaction():
    service, wrapper, executor = make_world(access_key=scoped_key())
    decision = wrapper.evaluate(legit())
    data = decision.to_dict()
    assert data["simulated"] is True


def test_submit_refuses_when_the_wrapper_did_not_allow():
    service, wrapper, executor = make_world(access_key=scoped_key())
    submission = wrapper.submit(legit(destination=ATTACKER_DESTINATION), None)
    assert submission.outcome is WrapperOutcome.BLOCK
    assert submission.sign_result is None
    assert executor.calls == 0


def test_outcome_severity_is_ordered_so_unknown_is_strictest():
    order = [
        WrapperOutcome.ALLOW,
        WrapperOutcome.REQUIRE_APPROVAL,
        WrapperOutcome.HOLD,
        WrapperOutcome.BLOCK,
        WrapperOutcome.UNKNOWN,
    ]
    severities = [o.severity for o in order]
    assert severities == sorted(severities)


def test_only_allow_permits_signing():
    for outcome in WrapperOutcome:
        assert outcome.permits_signing is (outcome is WrapperOutcome.ALLOW)
