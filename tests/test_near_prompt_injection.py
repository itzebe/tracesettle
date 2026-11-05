"""Prompt-injection demonstration and wrapper-integration tests.

The demonstration runs the real guard controls, the real authorization
authority, the real replay store and the real reference signer. The only
substitution is the executor, which records what it was asked to do and never
touches a chain, so "blocked" is provable as "the executor was never called".
"""

from __future__ import annotations

from tracesettle.near.agent_wrapper import WrapperOutcome
from tracesettle.near.attacks import (
    APPROVED_DESTINATION,
    APPROVED_DESTINATION_2,
    ATTACKER_DESTINATION,
)
from tracesettle.near.counterparty import CounterpartyIntelligence, CounterpartyOutcome
from tracesettle.near.prompt_injection import (
    BEHAVIOURS,
    _InjectionWorld,
    _legit_tx,
    run_all_behaviours,
    run_behaviour,
    run_prompt_injection,
)
from tracesettle.near.rpc import RpcResult
from tracesettle.model import SourceStatus


def test_prompt_injection_is_blocked_and_never_signed():
    audit = run_prompt_injection()
    assert audit.blocked
    assert audit.authorization_result == "BLOCK"
    assert audit.signed is False
    assert audit.broadcast_occurred is False
    assert audit.signing_refused is True


def test_prompt_injection_records_the_full_audit_trail():
    audit = run_prompt_injection()
    assert audit.agent_identity == "treasury-agent"
    assert audit.actual_receiver == ATTACKER_DESTINATION
    assert audit.payload_fingerprint
    assert any("UNAPPROVED_DESTINATION" in r or "DENIED" in r for r in audit.rejection_reasons)
    assert "ignore all previous instructions" in audit.injection_text


def test_prompt_injection_audit_serializes():
    d = run_prompt_injection().to_dict()
    assert d["authorization_result"] == "BLOCK"
    assert isinstance(d["findings"], list)
    assert d["simulated"] is True


def test_all_required_behaviours_hold():
    results = run_all_behaviours()
    assert [r.name for r in results] == ["ALLOW", "WARN", "BLOCK", "TAMPER", "REPLAY", "FAILURE"]
    failed = [r.name for r in results if not r.held]
    assert failed == [], f"behaviours that did not hold: {failed}"


def test_each_behaviour_is_individually_reproducible():
    for name in BEHAVIOURS:
        result = run_behaviour(name)
        assert result.held, f"{name}: {result.observed} :: {result.detail}"


def test_behaviour_registry_rejects_unknown_name():
    import pytest

    with pytest.raises(KeyError):
        run_behaviour("nope")


def test_counterparty_review_raises_the_wrapper_to_require_approval():
    world = _InjectionWorld()
    read = CounterpartyIntelligence(_FakeRpc("contract"), chain="near").read(APPROVED_DESTINATION)
    assert read.outcome is CounterpartyOutcome.REVIEW
    decision = world.wrapper.evaluate(_legit_tx(), counterparty=read)
    assert decision.outcome is WrapperOutcome.REQUIRE_APPROVAL


def test_counterparty_block_blocks_the_wrapper():
    world = _InjectionWorld()
    read = CounterpartyIntelligence(_FakeRpc("missing"), chain="near").read(APPROVED_DESTINATION)
    assert read.outcome is CounterpartyOutcome.BLOCK
    decision = world.wrapper.evaluate(_legit_tx(), counterparty=read)
    assert decision.outcome is WrapperOutcome.BLOCK


def test_counterparty_unknown_fails_safe():
    world = _InjectionWorld()
    read = CounterpartyIntelligence(_FakeRpc("timeout"), chain="near").read(APPROVED_DESTINATION)
    assert read.outcome is CounterpartyOutcome.UNKNOWN
    decision = world.wrapper.evaluate(_legit_tx(), counterparty=read)
    assert decision.outcome is WrapperOutcome.UNKNOWN
    assert not decision.permits_signing


def test_no_counterparty_read_is_inert():
    world = _InjectionWorld()
    decision = world.wrapper.evaluate(_legit_tx())
    assert decision.outcome is WrapperOutcome.ALLOW


def test_counterparty_never_weakens_a_guard_block():
    # A CLEAR counterparty read must not soften a destination the guard refuses.
    world = _InjectionWorld()
    read = CounterpartyIntelligence(_FakeRpc("user"), chain="near").read(APPROVED_DESTINATION)
    assert read.outcome is CounterpartyOutcome.CLEAR
    decision = world.wrapper.evaluate(_legit_tx(destination=ATTACKER_DESTINATION), counterparty=read)
    assert decision.outcome is WrapperOutcome.BLOCK


def test_approval_request_binds_to_the_payload_fingerprint():
    world = _InjectionWorld()
    tx = _legit_tx(amount="6000")
    request = world.wrapper.approval_request(tx)
    expected = world.service.approval_payload_fingerprint(tx.to_request())
    assert request.payload_fingerprint == expected
    assert request.service_id == "treasury-agent"


def test_reused_decision_cannot_smuggle_a_tampered_transaction():
    # Even when a caller passes a decision, the signer re-derives the binding
    # from the transaction it is asked to sign, so a tampered payload is refused.
    world = _InjectionWorld()
    approved = _legit_tx()
    decision = world.wrapper.evaluate(approved)
    tampered = _legit_tx(destination=APPROVED_DESTINATION_2)
    submission = world.wrapper.submit(tampered, decision.authorization, decision=decision)
    assert not submission.executed
    assert submission.sign_result is not None
    assert submission.sign_result.state.value == "WRONG_PARAMETERS"


class _FakeRpc:
    """A NEAR RPC stand-in for the counterparty reader (network boundary only)."""

    def __init__(self, mode: str) -> None:
        self.mode = mode

    def view_account(self, account_id: str) -> RpcResult:
        if self.mode == "missing":
            return RpcResult(SourceStatus.NOT_FOUND, error="UNKNOWN_ACCOUNT")
        if self.mode == "timeout":
            return RpcResult(SourceStatus.TIMEOUT, error="timeout")
        if self.mode == "contract":
            return RpcResult(SourceStatus.OK, {"code_hash": "abc", "block_height": 1_900_000})
        return RpcResult(SourceStatus.OK, {"code_hash": "1" * 32, "block_height": 1_900_000})

    def block_hash(self, *, finality: str = "final") -> RpcResult:
        return RpcResult(SourceStatus.OK, {"height": 2_000_000})
