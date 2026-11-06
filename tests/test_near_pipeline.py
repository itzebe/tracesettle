"""The real NEAR execution pipeline: sign, submit, verify - and recover.

Every test drives the real transaction builder, the real guard, the real TEE
authorizer, the real settlement verifier, and the real durable ledger. The only
substitution is the RPC transport (``FakeNearRpc``) and, where relevant, the
attestation provider (``FakeTeeProvider``) - both are network boundaries, not
logic mocks. "Nothing was signed/broadcast" is asserted by inspecting the
transport's recorded submissions and the signer's call count.
"""

from __future__ import annotations

import base64

import pytest

from near_helpers import (
    RECIPIENT,
    SIGNER,
    TEST_SEED,
    FakeTeeProvider,
    make_boundary,
    make_guard,
    make_tee_boundary,
    near_policy,
    result_for,
)
from tracesettle.model import SourceStatus
from tracesettle.near import ed25519
from tracesettle.near.execution import ExecutionError
from tracesettle.near.ledger import SubmissionLedger, SubmissionState
from tracesettle.near.pipeline import (
    LocalKeySigner,
    NearExecutionPipeline,
    SigningError,
)
from tracesettle.near.networks import NearNetwork
from tracesettle.near.verify import SettlementState


class CountingSigner:
    """A signer that records every message it was asked to sign."""

    def __init__(self, public_key: str, *, fail: bool = False):
        self._public_key = public_key
        self.calls = 0
        self.fail = fail

    @property
    def public_key(self) -> str:
        return self._public_key

    def sign(self, message: bytes) -> bytes:
        self.calls += 1
        if self.fail:
            raise RuntimeError("signer unavailable")
        from tracesettle.near import ed25519

        return ed25519.sign(message, TEST_SEED)


def _prepare(boundary, **overrides):
    kwargs = dict(
        service_id="treasury-agent",
        account_id=SIGNER,
        public_key="ed25519:" + _pub(),
        receiver_id=RECIPIENT,
        asset_identifier="near:native",
        amount_human="1",
    )
    kwargs.update(overrides)
    return boundary.prepare(**kwargs)


def _pub() -> str:
    from near_helpers import public_key_for_test

    return public_key_for_test().split(":", 1)[1]


def _pipeline(boundary, ledger=None):
    return NearExecutionPipeline(boundary, ledger=ledger or SubmissionLedger())


# -- happy path ---------------------------------------------------------------


def test_pipeline_settles_and_persists_a_verified_transaction():
    boundary, rpc = make_boundary()
    pipeline = _pipeline(boundary)
    prepared = _prepare(boundary)
    rpc.send_result = result_for(prepared.transaction, finality="FINAL")
    rpc.tx_status_result = result_for(prepared.transaction, finality="FINAL")

    signer = CountingSigner(prepared.transaction.public_key)
    result = pipeline.execute(prepared, signer)

    assert result.state == SubmissionState.SETTLED
    assert result.settlement_state == SettlementState.VERIFIED.value
    assert result.tx_hash == prepared.transaction.tx_hash
    assert signer.calls == 1
    assert len(rpc.broadcasts) == 1
    record = pipeline.ledger.get(prepared.transaction.tx_hash)
    assert record is not None and record.state == SubmissionState.SETTLED


def test_pipeline_is_idempotent_on_the_idempotency_key():
    boundary, rpc = make_boundary()
    pipeline = _pipeline(boundary)
    prepared = _prepare(boundary)
    rpc.send_result = result_for(prepared.transaction, finality="FINAL")
    rpc.tx_status_result = result_for(prepared.transaction, finality="FINAL")

    signer = CountingSigner(prepared.transaction.public_key)
    first = pipeline.execute(prepared, signer, idempotency_key="op-1")
    assert signer.calls == 1 and len(rpc.broadcasts) == 1

    # A second, separately-prepared operation with the same key must not re-sign
    # or re-broadcast: the recorded result is returned.
    prepared2 = _prepare(boundary)
    rpc.send_result = result_for(prepared2.transaction, finality="FINAL")
    second = pipeline.execute(prepared2, signer, idempotency_key="op-1")

    assert second.recovered is True
    assert signer.calls == 1, "a duplicate request must not sign again"
    assert len(rpc.broadcasts) == 1, "a duplicate request must not broadcast again"
    assert second.tx_hash == first.tx_hash


# -- TEE gate ----------------------------------------------------------------


def test_tee_gate_refuses_to_sign_without_an_attestation():
    boundary, rpc, authorizer, provider = make_tee_boundary()
    pipeline = _pipeline(boundary)
    prepared = _prepare(boundary)
    rpc.send_result = result_for(prepared.transaction, finality="FINAL")

    signer = CountingSigner(prepared.transaction.public_key)
    # No attestation was requested, so the record is not TEE-verified.
    with pytest.raises(SigningError):
        pipeline.execute(prepared, signer)

    assert signer.calls == 0, "no signature may be produced without the gate"
    assert rpc.broadcasts == [], "nothing may be broadcast"


def test_tee_gate_refuses_an_unverified_attestation():
    provider = FakeTeeProvider(verified=False)
    boundary, rpc, authorizer, _ = make_tee_boundary(provider=provider)
    pipeline = _pipeline(boundary)
    prepared = _prepare(boundary)
    with pytest.raises(ExecutionError):
        boundary.verify_tee_attestation(prepared)
    signer = CountingSigner(prepared.transaction.public_key)
    with pytest.raises(SigningError):
        pipeline.execute(prepared, signer)
    assert signer.calls == 0 and rpc.broadcasts == []


def test_tee_gate_accepts_a_bound_attestation_and_settles():
    boundary, rpc, authorizer, provider = make_tee_boundary()
    pipeline = _pipeline(boundary)
    prepared = _prepare(boundary)
    boundary.verify_tee_attestation(prepared)
    rpc.send_result = result_for(prepared.transaction, finality="FINAL")
    rpc.tx_status_result = result_for(prepared.transaction, finality="FINAL")

    signer = CountingSigner(prepared.transaction.public_key)
    result = pipeline.execute(prepared, signer)
    assert result.state == SubmissionState.SETTLED
    assert signer.calls == 1 and len(rpc.broadcasts) == 1


# -- authorization + binding --------------------------------------------------


def test_pipeline_refuses_an_unauthorized_operation():
    policy = near_policy(approved=frozenset({"someone-else.testnet"}))
    boundary, rpc = make_boundary(make_guard(policy))
    pipeline = _pipeline(boundary)
    prepared = _prepare(boundary)  # receiver not approved -> BLOCK
    signer = CountingSigner(prepared.transaction.public_key)
    with pytest.raises(SigningError):
        pipeline.execute(prepared, signer)
    assert signer.calls == 0 and rpc.broadcasts == []


def test_pipeline_refuses_a_signer_failure_without_broadcasting():
    boundary, rpc = make_boundary()
    pipeline = _pipeline(boundary)
    prepared = _prepare(boundary)
    signer = CountingSigner(prepared.transaction.public_key, fail=True)
    with pytest.raises(SigningError):
        pipeline.execute(prepared, signer)
    assert rpc.broadcasts == []


def test_local_key_signer_refuses_mainnet():
    with pytest.raises(SigningError):
        LocalKeySigner(TEST_SEED, network=NearNetwork.MAINNET, account_id="a.near")


def test_pipeline_refuses_a_network_mismatch():
    boundary, rpc = make_boundary()
    pipeline = _pipeline(boundary)
    prepared = _prepare(boundary)
    prepared.network = NearNetwork.MAINNET  # tamper: a different network
    signer = CountingSigner(prepared.transaction.public_key)
    with pytest.raises(SigningError):
        pipeline.execute(prepared, signer)
    assert signer.calls == 0 and rpc.broadcasts == []


# -- access-key permission ----------------------------------------------------


def test_prepare_refuses_a_function_call_key_that_cannot_transfer_near():
    boundary, rpc = make_boundary()
    rpc.access_key_permission = {
        "FunctionCall": {"receiver_id": RECIPIENT, "method_names": ["ft_transfer"]}
    }
    with pytest.raises(ExecutionError) as exc:
        _prepare(boundary)
    assert "does not permit" in str(exc.value)


def test_prepare_refuses_a_function_call_key_scoped_to_another_receiver():
    boundary, rpc = make_boundary()
    rpc.access_key_permission = {
        "FunctionCall": {"receiver_id": "other.testnet", "method_names": []}
    }
    with pytest.raises(ExecutionError):
        _prepare(boundary)


def test_prepare_refuses_an_unrecognised_permission():
    boundary, rpc = make_boundary()
    rpc.access_key_permission = {"SomethingBrandNew": {}}
    with pytest.raises(ExecutionError) as exc:
        _prepare(boundary)
    assert "not recognised" in str(exc.value)


def test_prepare_allows_a_full_access_key():
    boundary, rpc = make_boundary()
    rpc.access_key_permission = "FullAccess"
    prepared = _prepare(boundary)
    assert prepared.authorized


def test_prepare_refuses_a_function_call_key_for_a_native_transfer_even_with_matching_receiver():
    # A function-call key can never move native NEAR, even if the receiver
    # matches and the method list is empty (all methods).
    boundary, rpc = make_boundary()
    rpc.access_key_permission = {"FunctionCall": {"receiver_id": RECIPIENT, "method_names": []}}
    with pytest.raises(ExecutionError):
        _prepare(boundary)


# -- unknown outcome + recovery ----------------------------------------------


def test_unknown_submission_outcome_is_recorded_not_treated_as_failure():
    boundary, rpc = make_boundary()
    pipeline = _pipeline(boundary)
    prepared = _prepare(boundary)
    rpc.send_status = SourceStatus.TIMEOUT
    rpc.send_result = None
    rpc.tx_status_status = SourceStatus.NOT_FOUND  # the chain does not know it yet

    signer = CountingSigner(prepared.transaction.public_key)
    result = pipeline.execute(prepared, signer)

    assert result.state == SubmissionState.UNKNOWN
    assert result.state != SubmissionState.FAILED
    record = pipeline.ledger.get(prepared.transaction.tx_hash)
    assert record is not None and record.state == SubmissionState.UNKNOWN
    # It was sent exactly once; an unknown outcome is never blindly retried.
    assert len(rpc.broadcasts) == 1


def test_recovery_resolves_an_unknown_submission_from_the_chain():
    boundary, rpc = make_boundary()
    pipeline = _pipeline(boundary)
    prepared = _prepare(boundary)
    rpc.send_status = SourceStatus.TIMEOUT
    rpc.tx_status_status = SourceStatus.NOT_FOUND
    signer = CountingSigner(prepared.transaction.public_key)
    pipeline.execute(prepared, signer)
    assert len(rpc.broadcasts) == 1

    # The chain now knows the transaction and it is final.
    rpc.tx_status_status = SourceStatus.OK
    rpc.tx_status_result = result_for(prepared.transaction, finality="FINAL")

    resolved = pipeline.resolve_unknown(prepared.transaction.tx_hash, prepared=prepared)
    assert resolved is not None
    assert resolved.settlement_state == SettlementState.VERIFIED.value
    # Recovery never sends anything.
    assert len(rpc.broadcasts) == 1


def test_recovery_leaves_a_still_unknown_submission_pending():
    boundary, rpc = make_boundary()
    pipeline = _pipeline(boundary)
    prepared = _prepare(boundary)
    rpc.send_status = SourceStatus.TIMEOUT
    rpc.tx_status_status = SourceStatus.NOT_FOUND
    signer = CountingSigner(prepared.transaction.public_key)
    pipeline.execute(prepared, signer)

    assert pipeline.recover() == ()
    record = pipeline.ledger.get(prepared.transaction.tx_hash)
    assert record is not None and record.state == SubmissionState.UNKNOWN


def test_recover_never_resubmits():
    boundary, rpc = make_boundary()
    pipeline = _pipeline(boundary)
    prepared = _prepare(boundary)
    rpc.send_status = SourceStatus.TIMEOUT
    rpc.tx_status_status = SourceStatus.NOT_FOUND
    signer = CountingSigner(prepared.transaction.public_key)
    pipeline.execute(prepared, signer)
    broadcasts = len(rpc.broadcasts)

    pipeline.recover()
    pipeline.recover()
    assert len(rpc.broadcasts) == broadcasts, "recovery must never send"


def test_resume_signed_resends_the_identical_bytes_only_for_a_signed_record():
    boundary, rpc = make_boundary()
    ledger = SubmissionLedger()
    pipeline = _pipeline(boundary, ledger)
    prepared = _prepare(boundary)
    # Record a SIGNED-but-never-sent submission.
    from tracesettle.near.ledger import SubmissionRecord

    signed = base64.b64encode(prepared.transaction.signed_bytes(bytes(64))).decode()
    record = SubmissionRecord(
        tx_hash=prepared.transaction.tx_hash,
        state=SubmissionState.SIGNED,
        network="testnet",
        signer_id=SIGNER,
        receiver_id=RECIPIENT,
        amount_base=str(prepared.transaction.amount_base),
        destination=RECIPIENT,
        signed_b64=signed,
    )
    ledger.put(record)
    rpc.send_result = result_for(prepared.transaction, finality="FINAL")
    rpc.tx_status_result = result_for(prepared.transaction, finality="FINAL")

    result = pipeline.resume_signed(prepared.transaction.tx_hash)
    assert result is not None
    assert rpc.broadcasts == [signed], "the identical recorded bytes are re-sent"

    # Once the record is SETTLED it is no longer resumable.
    assert pipeline.resume_signed(prepared.transaction.tx_hash) is None


def test_resume_signed_ignores_a_non_signed_record():
    boundary, rpc = make_boundary()
    pipeline = _pipeline(boundary)
    prepared = _prepare(boundary)
    rpc.send_result = result_for(prepared.transaction, finality="FINAL")
    rpc.tx_status_result = result_for(prepared.transaction, finality="FINAL")
    pipeline.execute(prepared, CountingSigner(prepared.transaction.public_key))
    before = len(rpc.broadcasts)
    # The record is SETTLED now, not SIGNED.
    assert pipeline.resume_signed(prepared.transaction.tx_hash) is None
    assert len(rpc.broadcasts) == before


# -- finality polling ---------------------------------------------------------


def test_pending_then_final_is_polled_to_a_verified_settlement():
    boundary, rpc = make_boundary()
    pipeline = _pipeline(boundary)
    prepared = _prepare(boundary)
    rpc.send_result = result_for(prepared.transaction, finality="EXECUTED_OPTIMISTIC")
    rpc.tx_status_result = result_for(prepared.transaction, finality="FINAL")

    signer = CountingSigner(prepared.transaction.public_key)
    result = pipeline.execute(prepared, signer, attempts=4, delay=0.0)
    assert result.settlement_state == SettlementState.VERIFIED.value
    assert result.state == SubmissionState.SETTLED


def test_still_pending_after_polling_is_never_inflated_to_verified():
    boundary, rpc = make_boundary()
    pipeline = _pipeline(boundary)
    prepared = _prepare(boundary)
    rpc.send_result = result_for(prepared.transaction, finality="EXECUTED_OPTIMISTIC")
    rpc.tx_status_result = result_for(prepared.transaction, finality="EXECUTED_OPTIMISTIC")

    signer = CountingSigner(prepared.transaction.public_key)
    result = pipeline.execute(prepared, signer, attempts=2, delay=0.0)
    assert result.settlement_state == SettlementState.PENDING.value
    assert result.state == SubmissionState.UNKNOWN
    assert result.state != SubmissionState.SETTLED


# -- settlement assurance -----------------------------------------------------


def test_provider_success_with_a_wrong_receiver_is_not_verified():
    boundary, rpc = make_boundary()
    pipeline = _pipeline(boundary)
    prepared = _prepare(boundary)
    # A "successful" record whose receiver is not the authorized one.
    rpc.send_result = result_for(
        prepared.transaction, finality="FINAL", receiver="attacker.testnet"
    )
    rpc.tx_status_result = rpc.send_result

    signer = CountingSigner(prepared.transaction.public_key)
    result = pipeline.execute(prepared, signer)
    assert result.settlement_state != SettlementState.VERIFIED.value
    assert result.state != SubmissionState.SETTLED


def test_onchain_failure_is_recorded_as_failed():
    boundary, rpc = make_boundary()
    pipeline = _pipeline(boundary)
    prepared = _prepare(boundary)
    rpc.send_result = result_for(prepared.transaction, status_kind="failure", finality="FINAL")
    rpc.tx_status_result = rpc.send_result

    signer = CountingSigner(prepared.transaction.public_key)
    result = pipeline.execute(prepared, signer)
    assert result.settlement_state == SettlementState.FAILED.value
    assert result.state == SubmissionState.FAILED


# -- ledger durability --------------------------------------------------------


def test_ledger_persists_across_instances(tmp_path):
    path = str(tmp_path / "ledger.db")
    ledger = SubmissionLedger(path)
    boundary, rpc = make_boundary()
    pipeline = _pipeline(boundary, ledger)
    prepared = _prepare(boundary)
    rpc.send_result = result_for(prepared.transaction, finality="FINAL")
    rpc.tx_status_result = result_for(prepared.transaction, finality="FINAL")
    pipeline.execute(prepared, CountingSigner(prepared.transaction.public_key))
    ledger.close()

    reopened = SubmissionLedger(path)
    record = reopened.get(prepared.transaction.tx_hash)
    assert record is not None
    assert record.state == SubmissionState.SETTLED
    assert record.idempotency_key == ""
    reopened.close()


def test_ledger_fails_closed_on_an_unopenable_path(tmp_path):
    # A directory is not a database file; opening must raise, not silently
    # fall back to memory.
    bad = tmp_path / "a-directory"
    bad.mkdir()
    with pytest.raises(Exception):
        SubmissionLedger(str(bad))


def test_idempotency_survives_a_restart(tmp_path):
    path = str(tmp_path / "ledger.db")
    ledger = SubmissionLedger(path)
    boundary, rpc = make_boundary()
    pipeline = _pipeline(boundary, ledger)
    prepared = _prepare(boundary)
    rpc.send_result = result_for(prepared.transaction, finality="FINAL")
    rpc.tx_status_result = result_for(prepared.transaction, finality="FINAL")
    pipeline.execute(prepared, CountingSigner(prepared.transaction.public_key), idempotency_key="k1")
    ledger.close()

    reopened = SubmissionLedger(path)
    record = reopened.get_by_idempotency("k1")
    assert record is not None and record.state == SubmissionState.SETTLED
    reopened.close()


def test_ledger_backend_is_reported_honestly(tmp_path):
    assert SubmissionLedger().backend == "in-memory"
    ledger = SubmissionLedger(str(tmp_path / "l.db"))
    assert ledger.backend == "sqlite"
    ledger.close()


# -- client-signed (wallet) submission ---------------------------------------


def _client_signature(prepared):
    return base64.b64encode(
        ed25519.sign(prepared.transaction.tx_hash_bytes, TEST_SEED)
    ).decode()


def test_submit_signed_broadcasts_a_client_signature_and_settles():

    boundary, rpc = make_boundary()
    pipeline = _pipeline(boundary)
    prepared = _prepare(boundary)
    rpc.send_result = result_for(prepared.transaction, finality="FINAL")
    rpc.tx_status_result = result_for(prepared.transaction, finality="FINAL")

    result = pipeline.submit_signed(prepared, _client_signature(prepared))
    assert result.state == SubmissionState.SETTLED
    assert result.settlement_state == SettlementState.VERIFIED.value
    assert len(rpc.broadcasts) == 1
    assert pipeline.ledger.get(prepared.transaction.tx_hash) is not None


def test_submit_signed_refuses_a_signature_that_does_not_verify():
    boundary, rpc = make_boundary()
    pipeline = _pipeline(boundary)
    prepared = _prepare(boundary)
    bad = base64.b64encode(bytes(64)).decode()
    with pytest.raises(ExecutionError):
        pipeline.submit_signed(prepared, bad)
    assert rpc.broadcasts == [], "an invalid signature must never be broadcast"


def test_submit_signed_is_idempotent():
    boundary, rpc = make_boundary()
    pipeline = _pipeline(boundary)
    prepared = _prepare(boundary)
    rpc.send_result = result_for(prepared.transaction, finality="FINAL")
    rpc.tx_status_result = result_for(prepared.transaction, finality="FINAL")
    signature = _client_signature(prepared)

    first = pipeline.submit_signed(prepared, signature, idempotency_key="w-1")
    assert len(rpc.broadcasts) == 1
    second = pipeline.submit_signed(prepared, signature, idempotency_key="w-1")
    assert second.recovered is True
    assert len(rpc.broadcasts) == 1, "a duplicate wallet submission must not re-broadcast"
    assert second.tx_hash == first.tx_hash
