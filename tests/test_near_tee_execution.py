"""The TEE trust boundary: attestation is enforced, not merely displayed.

Every test here drives the real execution boundary, the real guard, the real
Borsh serializer and the real :class:`TeeExecutionAuthorizer`. The only
substitutions are the RPC transport (``FakeNearRpc``) and the attestation
transport (``FakeTeeProvider``) - network boundaries, not logic mocks. The
refusal assertions inspect the RPC transport's recorded submissions, so "nothing
was broadcast" is proven by the absence of bytes, not by a flag.
"""

from __future__ import annotations

import base64
from datetime import datetime, timedelta, timezone

import pytest

from near_helpers import (
    RECIPIENT,
    SIGNER,
    FakeTeeProvider,
    make_tee_boundary,
)
from tracesettle.near import ed25519
from tracesettle.near.execution import ExecutionError
from tracesettle.near.tee_execution import (
    ExecutionState,
    ExecutionRecordStore,
    IllegalTransition,
    TeeExecutionAuthorizer,
    TeeExecutionError,
    can_transition,
    execution_digest,
    is_terminal,
    measurement_fingerprint,
)
from tracesettle.near.tee import AttestationStatus


def _prepare(boundary, **overrides):
    kwargs = dict(
        service_id="treasury-agent",
        account_id=SIGNER,
        public_key="ed25519:" + "A" * 43,
        receiver_id=RECIPIENT,
        asset_identifier="near:native",
        amount_human="1",
    )
    kwargs.update(overrides)
    return boundary.prepare(**kwargs)


def _public_key():
    from near_helpers import public_key_for_test

    return public_key_for_test()


def _sign(boundary, prepared, seed):
    raw = ed25519.sign(prepared.transaction.tx_hash_bytes, seed)
    return base64.b64encode(raw).decode("ascii")


# --- the state machine ----------------------------------------------------


def test_tee_gate_cannot_be_skipped_because_signing_only_follows_tee_verified():
    assert can_transition(ExecutionState.TEE_VERIFIED, ExecutionState.SIGNING_PENDING)
    # There is no edge from any pre-TEE state straight to signing.
    for state in (
        ExecutionState.RECEIVED,
        ExecutionState.AUTHORIZATION_PENDING,
        ExecutionState.AUTHORIZED,
        ExecutionState.TEE_VERIFICATION_PENDING,
    ):
        assert not can_transition(state, ExecutionState.SIGNING_PENDING), state


def test_no_state_jumps_straight_to_a_success_state():
    for state in (
        ExecutionState.RECEIVED,
        ExecutionState.AUTHORIZATION_PENDING,
        ExecutionState.AUTHORIZED,
        ExecutionState.TEE_VERIFICATION_PENDING,
        ExecutionState.TEE_VERIFIED,
        ExecutionState.SIGNING_PENDING,
        ExecutionState.SIGNED,
    ):
        assert not can_transition(state, ExecutionState.SETTLEMENT_VERIFIED), state


def test_terminal_states_are_final():
    for state in (
        ExecutionState.SETTLEMENT_VERIFIED,
        ExecutionState.REJECTED,
        ExecutionState.EXPIRED,
        ExecutionState.TEE_VERIFICATION_FAILED,
        ExecutionState.SIGNING_FAILED,
        ExecutionState.SUBMISSION_FAILED,
        ExecutionState.SETTLEMENT_FAILED,
        ExecutionState.SETTLEMENT_UNKNOWN,
    ):
        assert is_terminal(state), state
    assert not is_terminal(ExecutionState.TEE_VERIFIED)


# --- the enforcement point ------------------------------------------------


def test_a_transaction_cannot_be_signed_without_a_bound_attestation():
    boundary, rpc, authorizer, provider = make_tee_boundary()
    prepared = _prepare(boundary, public_key=_public_key())
    assert prepared.authorized
    assert prepared.execution_id is not None
    # No attestation has been requested, so the gate refuses before consuming the
    # authorization and long before any broadcast.
    with pytest.raises(ExecutionError, match="TEE"):
        boundary.accept_signature(prepared, _sign(boundary, prepared, bytes(range(32))))
    assert rpc.broadcasts == []
    record = authorizer.get(prepared.execution_id)
    assert record.state == ExecutionState.AUTHORIZED


def test_a_verified_attestation_lets_the_signature_through_and_records_the_lifecycle():
    boundary, rpc, authorizer, provider = make_tee_boundary()
    prepared = _prepare(boundary, public_key=_public_key())
    record = boundary.verify_tee_attestation(prepared)
    assert record.tee_verified
    assert provider.calls == 1
    signature = _sign(boundary, prepared, bytes(range(32)))
    executed = boundary.broadcast(prepared, signature)
    assert executed.tx_hash
    assert len(rpc.broadcasts) == 1
    final = authorizer.get(prepared.execution_id)
    assert final.state in (
        ExecutionState.SETTLEMENT_VERIFIED,
        ExecutionState.SETTLEMENT_UNKNOWN,
        ExecutionState.SETTLEMENT_FAILED,
    )
    states = [h["state"] for h in final.history]
    assert ExecutionState.SIGNING_PENDING in states
    assert ExecutionState.SIGNED in states
    assert ExecutionState.SUBMITTED in states


def test_a_failed_attestation_refuses_and_records_the_failure():
    provider = FakeTeeProvider(verified=False)
    boundary, rpc, authorizer, provider = make_tee_boundary(provider=provider)
    prepared = _prepare(boundary, public_key=_public_key())
    with pytest.raises(ExecutionError):
        boundary.verify_tee_attestation(prepared)
    record = authorizer.get(prepared.execution_id)
    assert record.state == ExecutionState.TEE_VERIFICATION_FAILED
    with pytest.raises(ExecutionError):
        boundary.accept_signature(prepared, _sign(boundary, prepared, bytes(range(32))))
    assert rpc.broadcasts == []


def test_an_attestation_for_a_different_nonce_is_refused():
    provider = FakeTeeProvider(nonce_override="00" * 32)
    boundary, rpc, authorizer, provider = make_tee_boundary(provider=provider)
    prepared = _prepare(boundary, public_key=_public_key())
    with pytest.raises(ExecutionError, match="nonce"):
        boundary.verify_tee_attestation(prepared)
    assert authorizer.get(prepared.execution_id).state == ExecutionState.TEE_VERIFICATION_FAILED


def test_a_pinned_measurement_that_does_not_match_is_refused():
    provider = FakeTeeProvider(measurement={"rt_mr0": "bb" * 48})
    boundary, rpc, authorizer, provider = make_tee_boundary(
        provider=provider, expected_measurement="cc" * 32
    )
    prepared = _prepare(boundary, public_key=_public_key())
    with pytest.raises(ExecutionError, match="measurement"):
        boundary.verify_tee_attestation(prepared)


def test_a_matching_pinned_measurement_is_accepted():
    measurement = {"rt_mr0": "bb" * 48}
    pinned = measurement_fingerprint(measurement)
    provider = FakeTeeProvider(measurement=measurement)
    boundary, rpc, authorizer, provider = make_tee_boundary(
        provider=provider, expected_measurement=pinned
    )
    prepared = _prepare(boundary, public_key=_public_key())
    record = boundary.verify_tee_attestation(prepared)
    assert record.tee_verified
    assert record.tee_binding.measurement_pinned is True


# --- parameter substitution ----------------------------------------------


def test_substituting_the_signed_amount_after_attestation_is_refused():
    import dataclasses

    from tracesettle.near import borsh

    boundary, rpc, authorizer, provider = make_tee_boundary()
    prepared = _prepare(boundary, public_key=_public_key())
    boundary.verify_tee_attestation(prepared)
    # The attacker swaps the encoded transfer action for a larger one while
    # leaving every descriptive field (including amount_base, which the guard
    # binding is derived from) unchanged. Only the TEE digest - which commits to
    # the exact signed bytes - notices, so this is precisely the substitution the
    # TEE gate exists to catch.
    original = prepared.transaction
    forged = dataclasses.replace(
        original, actions=(borsh.action_transfer(original.amount_base * 5),)
    )
    assert forged.unsigned_bytes() != original.unsigned_bytes()
    prepared.transaction = forged
    with pytest.raises(ExecutionError, match="does not match the authorized execution"):
        boundary.accept_signature(prepared, _sign(boundary, prepared, bytes(range(32))))
    assert rpc.broadcasts == []


def test_substituting_the_receiver_is_refused_by_the_authorization_binding():
    import dataclasses

    boundary, rpc, authorizer, provider = make_tee_boundary()
    prepared = _prepare(boundary, public_key=_public_key())
    boundary.verify_tee_attestation(prepared)
    prepared.transaction = dataclasses.replace(
        prepared.transaction, receiver_id="attacker.testnet"
    )
    with pytest.raises(ExecutionError):
        boundary.accept_signature(prepared, _sign(boundary, prepared, bytes(range(32))))
    assert rpc.broadcasts == []


def test_an_expired_execution_is_refused_and_marked_expired():
    boundary, rpc, authorizer, provider = make_tee_boundary()
    prepared = _prepare(boundary, public_key=_public_key())
    boundary.verify_tee_attestation(prepared)
    record = authorizer.get(prepared.execution_id)
    record.expires_at = (
        datetime.now(timezone.utc) - timedelta(seconds=5)
    ).strftime("%Y-%m-%dT%H:%M:%SZ")
    authorizer.store.put(record)
    with pytest.raises(ExecutionError, match="expired"):
        boundary.accept_signature(prepared, _sign(boundary, prepared, bytes(range(32))))
    assert authorizer.get(prepared.execution_id).state == ExecutionState.EXPIRED
    assert rpc.broadcasts == []


def test_the_same_authorization_cannot_be_signed_twice():
    boundary, rpc, authorizer, provider = make_tee_boundary()
    prepared = _prepare(boundary, public_key=_public_key())
    boundary.verify_tee_attestation(prepared)
    signature = _sign(boundary, prepared, bytes(range(32)))
    boundary.accept_signature(prepared, signature)
    # A second attempt is refused: the nonce is spent and the record is terminal.
    with pytest.raises(ExecutionError):
        boundary.accept_signature(prepared, signature)


def test_an_unknown_execution_id_is_refused():
    boundary, rpc, authorizer, provider = make_tee_boundary()
    prepared = _prepare(boundary, public_key=_public_key())
    prepared.execution_id = "exec_does_not_exist"
    with pytest.raises(ExecutionError, match="unknown execution"):
        boundary.accept_signature(prepared, _sign(boundary, prepared, bytes(range(32))))


def test_a_missing_execution_id_is_refused():
    boundary, rpc, authorizer, provider = make_tee_boundary()
    prepared = _prepare(boundary, public_key=_public_key())
    boundary.verify_tee_attestation(prepared)
    prepared.execution_id = None
    with pytest.raises(ExecutionError, match="no execution record"):
        boundary.accept_signature(prepared, _sign(boundary, prepared, bytes(range(32))))


# --- honest scope ---------------------------------------------------------


def test_verification_without_a_provider_refuses_rather_than_claiming_protection():
    from near_helpers import make_guard
    from tracesettle.near.execution import NearExecutionBoundary
    from tracesettle.near.networks import NETWORKS, NearNetwork
    from near_helpers import FakeNearRpc

    config = NETWORKS[NearNetwork.TESTNET]
    boundary = NearExecutionBoundary(make_guard(), config, rpc=FakeNearRpc(config))
    prepared = _prepare(boundary, public_key=_public_key())
    assert prepared.execution_id is None  # no gate, no record
    with pytest.raises(ExecutionError, match="not available"):
        boundary.verify_tee_attestation(prepared)


def test_without_the_gate_the_boundary_is_unchanged():
    from near_helpers import make_boundary

    boundary, rpc = make_boundary()
    assert boundary.tee_authorizer is None
    assert boundary.tee_required is False
    prepared = _prepare(boundary, public_key=_public_key())
    assert prepared.execution_id is None
    signature = _sign(boundary, prepared, bytes(range(32)))
    executed = boundary.broadcast(prepared, signature)
    assert executed.tx_hash
    assert len(rpc.broadcasts) == 1


# --- the authorizer in isolation -----------------------------------------


def _authorizer(**kwargs):
    return TeeExecutionAuthorizer(store=ExecutionRecordStore(), **kwargs)


def _make_record(authorizer, *, digest="ab" * 32, nonce="11" * 32, service="svc"):
    return authorizer.create(
        service_id=service,
        network="testnet",
        transaction_digest=digest,
        signer_id="agent.testnet",
        receiver_id="alice.testnet",
        operation="WITHDRAWAL",
        asset="NEAR:NATIVE",
        amount="1",
        destination="alice.testnet",
        authorization_id="auth1",
        authorization_nonce=nonce,
        policy_version="1",
    )


def test_execution_digest_changes_when_any_bound_field_changes():
    base = dict(
        execution_id="e1",
        network="testnet",
        transaction_digest="ab" * 32,
        service_id="svc",
        authorization_nonce="11" * 32,
        policy_version="1",
    )
    digest = execution_digest(**base)
    for field, value in (
        ("execution_id", "e2"),
        ("network", "mainnet"),
        ("transaction_digest", "cd" * 32),
        ("service_id", "svc2"),
        ("authorization_nonce", "22" * 32),
        ("policy_version", "2"),
    ):
        changed = dict(base)
        changed[field] = value
        assert execution_digest(**changed) != digest, field


def test_enforce_refuses_a_substituted_transaction_digest():
    authorizer = _authorizer()
    record = _make_record(authorizer)
    authorizer.bind_attestation(
        record.execution_id,
        FakeTeeProvider().attest(bytes.fromhex(record.authorization_nonce)),
        expected_nonce=record.authorization_nonce,
        expected_transaction_digest=record.transaction_digest,
    )
    with pytest.raises(TeeExecutionError, match="does not match"):
        authorizer.enforce(record.execution_id, transaction_digest="cd" * 32)


def test_bind_attestation_rejects_a_mismatched_expected_digest():
    authorizer = _authorizer()
    record = _make_record(authorizer)
    with pytest.raises(TeeExecutionError, match="different transaction digest"):
        authorizer.bind_attestation(
            record.execution_id,
            FakeTeeProvider().attest(bytes.fromhex(record.authorization_nonce)),
            expected_nonce=record.authorization_nonce,
            expected_transaction_digest="cd" * 32,
        )
    assert authorizer.get(record.execution_id).state == ExecutionState.TEE_VERIFICATION_FAILED


def test_an_illegal_transition_raises():
    authorizer = _authorizer()
    record = _make_record(authorizer)
    with pytest.raises(IllegalTransition):
        authorizer.record_state(record.execution_id, ExecutionState.SETTLEMENT_VERIFIED)
    with pytest.raises(IllegalTransition):
        authorizer.record_state(record.execution_id, ExecutionState.SIGNED)


def test_a_terminal_record_cannot_be_promoted():
    authorizer = _authorizer()
    record = _make_record(authorizer)
    authorizer.record_state(record.execution_id, ExecutionState.REJECTED)
    with pytest.raises(IllegalTransition):
        authorizer.record_state(record.execution_id, ExecutionState.SETTLEMENT_VERIFIED)


# --- durability -----------------------------------------------------------


def test_the_execution_record_survives_a_restart(tmp_path):
    path = str(tmp_path / "exec.db")
    store = ExecutionRecordStore(path)
    authorizer = TeeExecutionAuthorizer(store=store)
    record = _make_record(authorizer)
    authorizer.bind_attestation(
        record.execution_id,
        FakeTeeProvider().attest(bytes.fromhex(record.authorization_nonce)),
        expected_nonce=record.authorization_nonce,
        expected_transaction_digest=record.transaction_digest,
    )
    store.close()

    # A fresh store on the same file: the record and its TEE binding are there.
    reopened = ExecutionRecordStore(path)
    fresh = TeeExecutionAuthorizer(store=reopened)
    loaded = fresh.get(record.execution_id)
    assert loaded is not None
    assert loaded.tee_verified
    assert loaded.state == ExecutionState.TEE_VERIFIED
    assert fresh.enforce(record.execution_id, transaction_digest=record.transaction_digest)
    reopened.close()


def test_the_store_reports_its_backend_honestly(tmp_path):
    assert ExecutionRecordStore().backend == "in-memory"
    store = ExecutionRecordStore(str(tmp_path / "e.db"))
    assert store.backend == "sqlite"
    store.close()


def test_attestation_status_enum_is_used_for_the_verdict():
    # A guard against a future edit that compares the wrong string.
    authorizer = _authorizer()
    record = _make_record(authorizer)
    assert AttestationStatus.VERIFIED.value == "VERIFIED"
    bound = authorizer.bind_attestation(
        record.execution_id,
        FakeTeeProvider().attest(bytes.fromhex(record.authorization_nonce)),
        expected_nonce=record.authorization_nonce,
        expected_transaction_digest=record.transaction_digest,
    )
    assert bound.tee_binding.status == AttestationStatus.VERIFIED.value
