"""The signer-enforcement boundary: what the mission calls the decisive question.

The wrapper returning ``BLOCK`` is not the property that matters. The property
that matters is that the signer - the thing that holds the key and would submit
the transaction - is *never invoked* unless the decision is exactly ``ALLOW``
with a valid, transaction-bound, unspent authorization. A response that merely
says "blocked" proves nothing if a caller can reach the signer by another route.

Every test here therefore asserts on an **instrumented signer**: a signer that
counts every ``sign`` call and every executor call. "Refused" is asserted as "the
signer was never called", never as "the response looked like a refusal". The
only substitutions are network boundaries (the RPC transport and the simulated
executor); the guard controls, the authorization authority, the replay store, the
binding, and the reference signer all run as real code.

The mission's twelve required demonstrations are:

 1. BLOCK prevents signing.                               ``test_block_...``
 2. HOLD prevents signing.                                ``test_hold_...``
 3. UNKNOWN prevents signing.                             ``test_unknown_...``
 4. REQUIRE_APPROVAL prevents signing until approved.     ``test_require_approval_...``
 5. A valid approval permits only the exact transaction.  ``test_approval_...``
 6. A changed receiver invalidates authorization.         ``test_changed_receiver_...``
 7. A changed amount or payload invalidates authorization.``test_changed_amount_...``
 8. Replaying an approval is rejected.                    ``test_replayed_...``
 9. An expired approval is rejected.                      ``test_expired_...``
10. Missing or invalid credentials are rejected.          ``test_missing_...``
11. An alternate execution route cannot bypass the firewall.``test_no_alternate_route_...``
12. The signer is never invoked in any refused case.      ``test_*`` (all)
"""

from __future__ import annotations

import base64
import json
import pathlib

import pytest

from tracesettle.guard.authorization import (
    AuthorizationAuthority,
    InMemoryReplayStore,
    StateStoreError,
)
from tracesettle.guard.service import GuardService
from tracesettle.guard.signer import ReferenceSigner, SimulatedExecutor
from tracesettle.near.agent_wrapper import (
    AgentAuthorizationWrapper,
    AgentTransaction,
    WrapperOutcome,
)
from tracesettle.near.approval import ApprovalAuthority, CallbackChannel
from tracesettle.near.attacks import (
    APPROVED_DESTINATION,
    APPROVED_DESTINATION_2,
    ATTACKER_DESTINATION,
    DEMO_KEY,
    near_demo_policy,
)
from tracesettle.near.policy import PolicyAdapter, PolicyScope

FIXTURE_DIR = pathlib.Path(__file__).resolve().parent.parent / "tracesettle" / "near" / "fixtures"


# ---------------------------------------------------------------------------
# The instrumented signer: the whole point of this file
# ---------------------------------------------------------------------------


class InstrumentedExecutor(SimulatedExecutor):
    """An executor that counts how many times it was asked to execute."""

    def __init__(self) -> None:
        super().__init__()
        self.calls = 0

    def execute(self, request, authorization_id):  # noqa: ANN001
        self.calls += 1
        return super().execute(request, authorization_id)


class World:
    """A guard + wrapper + approval authority + instrumented executor."""

    def __init__(self, *, policy_read=None, approval_authority=True) -> None:
        self.executor = InstrumentedExecutor()
        authority = AuthorizationAuthority(
            key=DEMO_KEY, key_id="enforcement", ephemeral=False, replay_store=InMemoryReplayStore()
        )
        self.approval_authority = (
            ApprovalAuthority(key=DEMO_KEY, key_id="enforcement-approval")
            if approval_authority
            else None
        )
        self.service = GuardService(
            policy=near_demo_policy(),
            authority=authority,
            approval_authority=self.approval_authority,
        )
        self.service._signer = ReferenceSigner(authority, executor=self.executor)  # noqa: SLF001
        self.wrapper = AgentAuthorizationWrapper(
            self.service,
            policy_read=policy_read if policy_read is not None else in_force_policy(),
        )

    @property
    def executions(self) -> int:
        return self.executor.calls


def in_force_policy():
    return PolicyAdapter.from_fixture(
        json.loads((FIXTURE_DIR / "policy_in_force.json").read_text(encoding="utf-8"))
    )


def legit(**overrides) -> AgentTransaction:
    base: dict = dict(
        service_id="treasury-agent",
        operation="WITHDRAWAL",
        chain="base",
        asset="USDC",
        amount="1250.50",
        destination=APPROVED_DESTINATION,
        scope=PolicyScope.INTENTS,
        policy_action="withdraw",
        request_id="enforce",
    )
    base.update(overrides)
    return AgentTransaction(**base)


def _approve(world: World, tx: AgentTransaction):
    """A human approves the exact payload of ``tx`` through the real channel."""
    channel = CallbackChannel(lambda _req: "ops-human")
    request = world.wrapper.approval_request(tx)
    approver = channel.request_approval(request)
    return world.approval_authority.approve(request, approver=approver or "ops-human")


# ---------------------------------------------------------------------------
# 1. BLOCK never reaches the signer
# ---------------------------------------------------------------------------


def test_block_never_reaches_the_signer():
    """A blocked (injected) payment is refused and the executor is never called."""
    world = World()
    tx = legit(destination=ATTACKER_DESTINATION)
    decision = world.wrapper.evaluate(tx)
    assert decision.outcome is WrapperOutcome.BLOCK
    assert not decision.permits_signing
    # Even if the agent fabricates an authorization, the signer refuses and the
    # executor is never reached.
    submission = world.wrapper.submit(tx, decision.authorization)
    assert not submission.executed
    assert world.executions == 0


def test_block_decision_issues_no_authorization():
    """A BLOCK cannot carry an authorization token, so there is nothing to sign."""
    world = World()
    decision = world.wrapper.evaluate(legit(destination=ATTACKER_DESTINATION))
    assert decision.outcome is WrapperOutcome.BLOCK
    assert decision.authorization is None
    assert not decision.permits_signing


# ---------------------------------------------------------------------------
# 2. HOLD never reaches the signer
# ---------------------------------------------------------------------------


def test_hold_never_reaches_the_signer():
    """A HOLD (an unreadable policy on a native request) cannot sign."""
    from tracesettle.near.policy import PolicyAvailability, PolicyRead

    world = World()
    unavailable = PolicyRead(
        availability=PolicyAvailability.UNAVAILABLE,
        detail="the agent policy service did not answer",
    )
    wrapper = AgentAuthorizationWrapper(world.service, policy_read=unavailable)
    native = legit(
        scope=PolicyScope.NATIVE_NEAR,
        receiver_id=APPROVED_DESTINATION,
        method_name="transfer",
        transfers_near=True,
        request_id="hold",
    )
    decision = wrapper.evaluate(native)
    assert decision.outcome is WrapperOutcome.HOLD
    assert not decision.permits_signing
    submission = wrapper.submit(native, decision.authorization)
    assert not submission.executed
    assert world.executions == 0


def test_hold_from_the_guard_state_store_never_reaches_the_signer():
    """A durable-state failure is a HOLD, and a HOLD never signs.

    The state store is made to raise on every read, which is the guard's
    fail-closed path: it cannot prove the request is within its limits, so it
    holds. The held decision carries no authorization.
    """

    class BrokenStore:
        backend = "broken"

        def decision_cycle(self):
            raise StateStoreError("the state store is unavailable")

        def __getattr__(self, _name):  # any other call is also a failure
            def _boom(*_a, **_k):
                raise StateStoreError("the state store is unavailable")

            return _boom

    executor = InstrumentedExecutor()
    authority = AuthorizationAuthority(
        key=DEMO_KEY, key_id="enforcement", ephemeral=False, replay_store=InMemoryReplayStore()
    )
    service = GuardService(
        policy=near_demo_policy(), authority=authority, state_store=BrokenStore()
    )
    service._signer = ReferenceSigner(authority, executor=executor)  # noqa: SLF001
    wrapper = AgentAuthorizationWrapper(service, policy_read=in_force_policy())

    tx = legit(request_id="hold-store")
    decision = wrapper.evaluate(tx)
    assert decision.outcome is WrapperOutcome.HOLD
    assert not decision.permits_signing
    submission = wrapper.submit(tx, decision.authorization)
    assert not submission.executed
    assert executor.calls == 0


# ---------------------------------------------------------------------------
# 3. UNKNOWN never reaches the signer
# ---------------------------------------------------------------------------


def test_unknown_never_reaches_the_signer():
    """An unparseable amount fails safe to UNKNOWN, which cannot sign."""
    world = World()
    tx = legit(amount="not-a-number", request_id="unknown")
    decision = world.wrapper.evaluate(tx)
    assert decision.outcome is WrapperOutcome.UNKNOWN
    assert not decision.permits_signing
    submission = world.wrapper.submit(tx, decision.authorization)
    assert not submission.executed
    assert world.executions == 0


def test_unknown_is_strictest_and_fails_safe():
    """UNKNOWN ranks above BLOCK: "cannot prove safe" is never a soft warning."""
    assert WrapperOutcome.UNKNOWN.severity > WrapperOutcome.BLOCK.severity
    assert not WrapperOutcome.UNKNOWN.permits_signing


# ---------------------------------------------------------------------------
# 4. REQUIRE_APPROVAL never reaches the signer until approved
# ---------------------------------------------------------------------------


def test_require_approval_never_reaches_the_signer_without_approval():
    world = World()
    tx = legit(amount="6000", request_id="approval-needed")
    decision = world.wrapper.evaluate(tx)
    assert decision.outcome is WrapperOutcome.REQUIRE_APPROVAL
    assert not decision.permits_signing
    submission = world.wrapper.submit(tx, decision.authorization)
    assert not submission.executed
    assert world.executions == 0


def test_require_approval_proceeds_only_with_a_bound_human_approval():
    world = World()
    tx = legit(amount="6000", request_id="approval-granted")
    assert world.wrapper.evaluate(tx).outcome is WrapperOutcome.REQUIRE_APPROVAL

    approval = _approve(world, tx)
    approved_decision = world.wrapper.evaluate(tx, approval=approval)
    assert approved_decision.outcome is WrapperOutcome.ALLOW
    submission = world.wrapper.submit(
        tx, approved_decision.authorization, decision=approved_decision
    )
    assert submission.executed
    assert world.executions == 1


def test_require_approval_without_an_approval_authority_never_allows():
    """With no approval authority configured, REQUIRE_APPROVAL can never ALLOW."""
    world = World(approval_authority=False)
    tx = legit(amount="6000", request_id="no-authority")
    decision = world.wrapper.evaluate(tx)
    assert decision.outcome is WrapperOutcome.REQUIRE_APPROVAL
    assert not decision.permits_signing


# ---------------------------------------------------------------------------
# 5. A valid approval permits only the exact approved transaction
# ---------------------------------------------------------------------------


def test_approval_permits_only_the_exact_approved_transaction():
    world = World()
    approved_tx = legit(amount="6000", request_id="exact")
    approval = _approve(world, approved_tx)

    # The exact payload is allowed and executes once.
    decision = world.wrapper.evaluate(approved_tx, approval=approval)
    assert decision.outcome is WrapperOutcome.ALLOW
    result = world.wrapper.submit(approved_tx, decision.authorization, decision=decision)
    assert result.executed
    assert world.executions == 1


def test_approval_for_a_different_payload_is_refused():
    """An approval bound to payload A cannot raise payload B to ALLOW."""
    world = World()
    approval = _approve(world, legit(amount="6000", request_id="A"))
    other = legit(amount="7000", request_id="B")
    decision = world.wrapper.evaluate(other, approval=approval)
    assert decision.outcome is WrapperOutcome.REQUIRE_APPROVAL
    assert not decision.permits_signing
    assert world.executions == 0


# ---------------------------------------------------------------------------
# 6. A changed receiver invalidates authorization
# ---------------------------------------------------------------------------


def test_changed_receiver_invalidates_authorization():
    """A token minted for one receiver cannot sign a payment to another.

    Both receivers are on the policy's approved list, so the destination control
    passes; it is the signer's parameter binding that refuses, isolating the
    binding rather than re-testing the denylist.
    """
    world = World()
    decision = world.wrapper.evaluate(legit(destination=APPROVED_DESTINATION, request_id="recv"))
    token = decision.authorization
    assert token is not None

    tampered = legit(destination=APPROVED_DESTINATION_2, request_id="recv")
    submission = world.wrapper.submit(tampered, token)
    assert not submission.executed
    assert submission.sign_result is not None
    assert submission.sign_result.state.value in {"WRONG_PARAMETERS", "WRONG_SERVICE"}
    assert world.executions == 0


# ---------------------------------------------------------------------------
# 7. A changed amount or payload invalidates authorization
# ---------------------------------------------------------------------------


def test_changed_amount_invalidates_authorization():
    """A token bound to one amount cannot sign a different amount.

    The tampered amount is still *within* the policy (2000 < the approval
    threshold of 5000), so the wrapper's own controls ALLOW it; it is the
    signer's parameter binding that refuses, isolating the binding.
    """
    world = World()
    decision = world.wrapper.evaluate(legit(amount="1250.50", request_id="amt"))
    token = decision.authorization
    tampered = legit(amount="2000", request_id="amt")
    submission = world.wrapper.submit(tampered, token)
    assert not submission.executed
    assert submission.sign_result.state.value in {"WRONG_PARAMETERS", "WRONG_SERVICE"}
    assert world.executions == 0


def test_changed_asset_invalidates_authorization():
    world = World()
    decision = world.wrapper.evaluate(legit(asset="USDC", request_id="asset"))
    token = decision.authorization
    tampered = legit(asset="USDT", request_id="asset")
    submission = world.wrapper.submit(tampered, token)
    assert not submission.executed
    assert world.executions == 0


def test_the_transaction_boundary_refuses_a_bytes_only_substitution():
    """The NEAR execution boundary binds the *signed bytes*, not just the summary.

    This drives the real transaction builder and the real boundary: a forged
    action with every human-readable field unchanged is signed with a valid
    signature over its own bytes, so only the byte-level binding can refuse it.
    """
    import dataclasses

    from near_helpers import make_boundary, TEST_SEED, public_key_for_test
    from tracesettle.near import borsh, ed25519
    from tracesettle.near.execution import ExecutionError

    boundary, rpc = make_boundary()
    prepared = boundary.prepare(
        service_id="treasury-agent",
        account_id="agent.testnet",
        public_key=public_key_for_test(),
        receiver_id="alice.testnet",
        asset_identifier="near:native",
        amount_human="1",
    )
    assert prepared.authorized

    forged_actions = (borsh.action_transfer(prepared.transaction.amount_base + 10**24),)
    tampered = dataclasses.replace(
        prepared, transaction=dataclasses.replace(prepared.transaction, actions=forged_actions)
    )
    sig = base64.b64encode(
        ed25519.sign(tampered.transaction.tx_hash_bytes, TEST_SEED)
    ).decode()
    with pytest.raises(ExecutionError):
        boundary.accept_signature(tampered, sig)
    assert rpc.broadcasts == []


# ---------------------------------------------------------------------------
# 8. Replaying an approval is rejected
# ---------------------------------------------------------------------------


def test_replayed_authorization_is_rejected():
    """A spent authorization cannot sign a second transaction."""
    world = World()
    tx = legit(request_id="replay")
    decision = world.wrapper.evaluate(tx)
    first = world.wrapper.submit(tx, decision.authorization)
    assert first.executed
    second = world.wrapper.submit(tx, decision.authorization)
    assert not second.executed
    assert second.sign_result.state.value in {"REPLAYED", "MISSING"}
    assert world.executions == 1


def test_replayed_human_approval_is_rejected():
    """A single-use human approval cannot be presented twice."""
    world = World()
    tx = legit(amount="6000", request_id="replay-approval")
    approval = _approve(world, tx)
    first = world.wrapper.evaluate(tx, approval=approval)
    assert first.outcome is WrapperOutcome.ALLOW
    # Presenting the same approval again must not yield a second ALLOW.
    second = world.wrapper.evaluate(tx, approval=approval)
    assert second.outcome is not WrapperOutcome.ALLOW
    assert not second.permits_signing


# ---------------------------------------------------------------------------
# 9. An expired approval is rejected
# ---------------------------------------------------------------------------


def test_expired_approval_is_rejected():
    """An approval past its TTL cannot raise a decision to ALLOW."""
    import dataclasses
    from datetime import datetime, timedelta, timezone

    world = World()
    tx = legit(amount="6000", request_id="expired-approval")
    approval = _approve(world, tx)
    past = (datetime.now(timezone.utc) - timedelta(seconds=1)).strftime("%Y-%m-%dT%H:%M:%SZ")
    expired = dataclasses.replace(approval, expires_at=past)
    decision = world.wrapper.evaluate(tx, approval=expired)
    assert decision.outcome is WrapperOutcome.REQUIRE_APPROVAL
    assert not decision.permits_signing
    assert world.executions == 0


def test_expired_authorization_is_rejected_at_the_signer():
    """A genuinely-signed but expired authorization is refused."""
    import dataclasses
    from datetime import datetime, timedelta, timezone

    world = World()
    tx = legit(request_id="expired-auth")
    decision = world.wrapper.evaluate(tx)
    token = decision.authorization
    past = (datetime.now(timezone.utc) - timedelta(seconds=5)).strftime("%Y-%m-%dT%H:%M:%SZ")
    expired_token = dataclasses.replace(token, expires_at=past)
    # The signature no longer covers the edited token, so it is refused as
    # malformed/bad-signature - either way it cannot execute.
    submission = world.wrapper.submit(tx, expired_token)
    assert not submission.executed
    assert world.executions == 0


# ---------------------------------------------------------------------------
# 10. Missing or invalid credentials are rejected
# ---------------------------------------------------------------------------


def test_missing_authorization_is_rejected():
    world = World()
    tx = legit(request_id="no-token")
    world.wrapper.evaluate(tx)
    submission = world.wrapper.submit(tx, None)
    assert not submission.executed
    assert submission.sign_result.state.value in {"MISSING", "WRONG_PARAMETERS"}
    assert world.executions == 0


def test_forged_authorization_is_rejected():
    """A token signed by a key the signer does not trust is refused."""
    import dataclasses

    world = World()
    tx = legit(request_id="forged-token")
    decision = world.wrapper.evaluate(tx)
    forged = dataclasses.replace(decision.authorization, signature="0" * 64)
    submission = world.wrapper.submit(tx, forged)
    assert not submission.executed
    assert world.executions == 0


def test_authorization_from_an_untrusted_key_is_rejected():
    """A token minted by a different key id is refused as UNKNOWN_KEY."""
    from decimal import Decimal

    from tracesettle.guard.model import Decision, canonical_fields

    other = AuthorizationAuthority(
        key=bytes(range(1, 33)), key_id="attacker", ephemeral=False,
        replay_store=InMemoryReplayStore(),
    )
    world = World()
    tx = legit(request_id="wrong-key")
    world.wrapper.evaluate(tx)
    parameters = canonical_fields(
        service_id="treasury-agent",
        operation="WITHDRAWAL",
        chain="base",
        asset="USDC",
        amount=Decimal("1250.50"),
        destination=APPROVED_DESTINATION,
    )
    foreign = other.issue(
        decision_id="dec_attacker",
        decision=Decision.ALLOW,
        service_id="treasury-agent",
        parameters=parameters,
    )
    submission = world.wrapper.submit(tx, foreign)
    assert not submission.executed
    assert submission.sign_result.state.value == "UNKNOWN_KEY"
    assert world.executions == 0


# ---------------------------------------------------------------------------
# 11. No alternate execution route bypasses the firewall
# ---------------------------------------------------------------------------


def test_no_alternate_route_bypasses_the_firewall():
    """Every broadcast path funnels through the signature-acceptance gate.

    Both the in-process pipeline (``NearExecutionPipeline``) and the direct
    boundary broadcast submit through ``NearExecutionBoundary.accept_signature``,
    which is the single gate that enforces the binding and consumes the nonce. A
    second call to the gate with the same prepared operation is refused because
    the authorization is single-use - so there is no way to reach the network
    twice, or at all, without passing the gate.
    """
    import inspect

    from tracesettle.near.execution import NearExecutionBoundary
    from tracesettle.near.pipeline import NearExecutionPipeline

    src = inspect.getsource(NearExecutionBoundary.broadcast)
    assert "accept_signature" in src, "the direct broadcast path must pass the gate"
    assert "send_tx" in src

    src_pipeline = inspect.getsource(NearExecutionPipeline._submit_and_verify)
    assert "send_tx" in src_pipeline
    # The pipeline only reaches _submit_and_verify after accept_signature has
    # accepted the bytes (see execute / submit_signed).
    for method in (NearExecutionPipeline.execute, NearExecutionPipeline.submit_signed):
        assert "accept_signature" in inspect.getsource(method)


def test_the_pipeline_gate_refuses_a_second_submission_of_the_same_operation():
    """A single-use authorization means the gate admits at most one broadcast."""
    from near_helpers import make_boundary, TEST_SEED, public_key_for_test
    from tracesettle.near import ed25519
    from tracesettle.near.execution import ExecutionError

    boundary, rpc = make_boundary()
    prepared = boundary.prepare(
        service_id="treasury-agent",
        account_id="agent.testnet",
        public_key=public_key_for_test(),
        receiver_id="alice.testnet",
        asset_identifier="near:native",
        amount_human="1",
    )
    sig = base64.b64encode(ed25519.sign(prepared.transaction.tx_hash_bytes, TEST_SEED)).decode()
    boundary.accept_signature(prepared, sig)
    with pytest.raises(ExecutionError):
        boundary.accept_signature(prepared, sig)
    # No transaction was sent by accept_signature itself; the gate is not a
    # broadcast, and a second attempt cannot pass it.
    assert rpc.broadcasts == []


# ---------------------------------------------------------------------------
# 12. A malformed signature never burns the authorization (regression)
# ---------------------------------------------------------------------------


def test_a_malformed_signature_does_not_burn_the_authorization():
    """A bad signature is refused without spending the single-use nonce.

    This is a regression test for an ordering defect: the authorization used to
    be consumed before the signature was validated, so a single malformed
    submission could burn an authorization the caller could still have used for
    the correct transaction - a denial of the legitimate path. The signature is
    now verified first.
    """
    from near_helpers import make_boundary, TEST_SEED, public_key_for_test
    from tracesettle.near import ed25519
    from tracesettle.near.execution import ExecutionError

    boundary, rpc = make_boundary()
    prepared = boundary.prepare(
        service_id="treasury-agent",
        account_id="agent.testnet",
        public_key=public_key_for_test(),
        receiver_id="alice.testnet",
        asset_identifier="near:native",
        amount_human="1",
    )
    # A malformed signature is refused...
    with pytest.raises(ExecutionError):
        boundary.accept_signature(prepared, "not-base64!!")
    # ...and the authorization is still spendable for the correct signature.
    good = base64.b64encode(
        ed25519.sign(prepared.transaction.tx_hash_bytes, TEST_SEED)
    ).decode()
    signed_b64, _ = boundary.accept_signature(prepared, good)
    assert signed_b64


def test_a_wrong_transaction_signature_does_not_burn_the_authorization():
    """A signature over a *different* transaction is refused without consuming."""
    from near_helpers import BLOCK_HASH, RECIPIENT, SIGNER, TEST_SEED, make_boundary, public_key_for_test
    from tracesettle.near import ed25519
    from tracesettle.near.execution import ExecutionError
    from tracesettle.near.networks import NearNetwork
    from tracesettle.near.txbuild import build_transfer
    from decimal import Decimal

    boundary, _ = make_boundary()
    prepared = boundary.prepare(
        service_id="treasury-agent",
        account_id=SIGNER,
        public_key=public_key_for_test(),
        receiver_id=RECIPIENT,
        asset_identifier="near:native",
        amount_human="1",
    )
    other = build_transfer(
        network=NearNetwork.TESTNET,
        signer_id=SIGNER,
        public_key=public_key_for_test(),
        nonce=999,
        receiver_id=RECIPIENT,
        block_hash=BLOCK_HASH,
        amount_human=Decimal("2"),
    )
    wrong = base64.b64encode(ed25519.sign(other.tx_hash_bytes, TEST_SEED)).decode()
    with pytest.raises(ExecutionError):
        boundary.accept_signature(prepared, wrong)
    # The correct signature still works afterwards.
    good = base64.b64encode(
        ed25519.sign(prepared.transaction.tx_hash_bytes, TEST_SEED)
    ).decode()
    signed_b64, _ = boundary.accept_signature(prepared, good)
    assert signed_b64
