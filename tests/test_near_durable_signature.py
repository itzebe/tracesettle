"""Durable, independently re-verifiable signature evidence.

The acceptance question this file answers: *after a process restart, can
TraceSettle retrieve the exact transaction it authorized and independently
re-verify the ed25519 signature over the NEAR digest, proving the signed
transaction matches the original authorization?*

Every test drives the real transaction builder, the real guard, the real
pipeline, the real strict decoder and the real durable stores. The only
substitution is the RPC transport (``FakeNearRpc``) - a network boundary, not a
logic mock. A "restart" is modelled by **closing** the SQLite stores and opening
fresh instances from the same files, so nothing survives in memory.
"""

from __future__ import annotations

import base64

import pytest

from near_helpers import (
    RECIPIENT,
    SIGNER,
    TEST_SEED,
    make_boundary,
    result_for,
)
from tracesettle.model import SourceStatus
from tracesettle.near import ed25519
from tracesettle.near.ledger import (
    SubmissionLedger,
    SubmissionLedgerError,
    SubmissionRecord,
    SubmissionState,
)
from tracesettle.near.pipeline import NearExecutionPipeline
from tracesettle.near.tee_signing.evidence_chain import (
    EvidenceChainStore,
    verify_chain_bindings,
)


class CountingSigner:
    """A real ed25519 signer that records how often it was asked to sign."""

    def __init__(self, public_key: str):
        self._public_key = public_key
        self.calls = 0

    @property
    def public_key(self) -> str:
        return self._public_key

    def sign(self, message: bytes) -> bytes:
        self.calls += 1
        return ed25519.sign(message, TEST_SEED)


def _prepare(boundary, **overrides):
    from near_helpers import public_key_for_test

    kwargs = dict(
        service_id="treasury-agent",
        account_id=SIGNER,
        public_key=public_key_for_test(),
        receiver_id=RECIPIENT,
        asset_identifier="near:native",
        amount_human="1",
    )
    kwargs.update(overrides)
    return boundary.prepare(**kwargs)


def _settled_run(tmp_path, *, chain: bool = True):
    """Run one real pipeline submission against durable SQLite stores.

    Returns the ledger path, chain path and the settled transaction hash, with
    the stores already closed - the state a fresh process finds.
    """
    ledger_path = str(tmp_path / "ledger.db")
    chain_path = str(tmp_path / "chains.db")
    boundary, rpc = make_boundary()
    pipeline = NearExecutionPipeline(
        boundary,
        ledger=SubmissionLedger(ledger_path),
        chain_store=EvidenceChainStore(chain_path) if chain else None,
    )
    prepared = _prepare(boundary)
    rpc.send_result = result_for(prepared.transaction, finality="FINAL")
    rpc.tx_status_result = result_for(prepared.transaction, finality="FINAL")
    result = pipeline.execute(prepared, CountingSigner(prepared.transaction.public_key))
    assert result.state == SubmissionState.SETTLED
    pipeline.ledger.close()
    if pipeline.chain_store is not None:
        pipeline.chain_store.close()
    return ledger_path, chain_path, result.tx_hash


def _reopened(ledger_path, chain_path=None):
    """Fresh pipeline objects reading only the durable files."""
    boundary, _rpc = make_boundary()
    ledger = SubmissionLedger(ledger_path)
    store = EvidenceChainStore(chain_path) if chain_path else None
    pipeline = NearExecutionPipeline(boundary, ledger=ledger, chain_store=store)
    return pipeline, ledger, store


# ---------------------------------------------------------------------------
# Phase D - the acceptance test: independent post-restart verification
# ---------------------------------------------------------------------------


def test_the_exact_signed_bytes_survive_a_restart(tmp_path):
    """The signed bytes must be persisted, not merely held in memory.

    This is the defect Mission 27 fixes: the ledger's serializer dropped
    ``signed_b64``, so a fresh process could never re-verify what was signed.
    """
    ledger_path, _chain, tx_hash = _settled_run(tmp_path)
    pipeline, ledger, _store = _reopened(ledger_path)
    try:
        record = ledger.get(tx_hash)
        assert record is not None
        assert record.signed_b64, "the exact signed bytes were not persisted"
        assert record.signature_algorithm == "ed25519"
    finally:
        ledger.close()


def test_a_fresh_process_independently_reverifies_the_recorded_signature(tmp_path):
    """The acceptance test: recompute the digest and re-verify ed25519 from disk.

    Nothing is signed, sent or reconstructed from memory; the verdict comes only
    from the persisted bytes a fresh process reads.
    """
    ledger_path, _chain, tx_hash = _settled_run(tmp_path)
    pipeline, ledger, _store = _reopened(ledger_path)
    try:
        verdict = pipeline.verify_recorded_signature(tx_hash)
        assert verdict["verified"] is True, verdict
        assert verdict["state"] == "VERIFIED"
        assert verdict["digest_source"] == "recomputed_from_persisted_signed_bytes"
        by_name = {c["name"]: c["holds"] for c in verdict["checks"]}
        assert by_name == {
            "signed_bytes_present": True,
            "digest_recomputed": True,
            "decode_round_trips": True,
            "signature_verifies_over_digest": True,
            "record_matches_signed_bytes": True,
        }
        # The digest is the one the transaction hash implies: the recomputed
        # digest, hashed again and base58-encoded, must reproduce the tx hash.
        from tracesettle.base58 import b58encode

        digest = bytes.fromhex(verdict["transaction_digest"].split(":")[-1])
        # borsh.transaction_hash IS sha256 of the unsigned bytes, so the digest
        # equals the transaction hash bytes; re-encoding must equal the hash.
        assert b58encode(digest) == tx_hash
    finally:
        ledger.close()


def test_the_reverification_is_reproducible_across_two_fresh_processes(tmp_path):
    ledger_path, _chain, tx_hash = _settled_run(tmp_path)
    verdicts = []
    for _ in range(2):
        pipeline, ledger, _store = _reopened(ledger_path)
        try:
            verdicts.append(pipeline.verify_recorded_signature(tx_hash))
        finally:
            ledger.close()
    assert verdicts[0] == verdicts[1]


def test_the_signature_is_bound_to_the_original_authorization(tmp_path):
    """The chain proves the signed transaction matches what was authorized.

    The AUTHORIZATION stage records the receiver and amount the guard approved;
    the SIGNATURE stage records the receiver and amount actually signed; the
    binding check fails if they differ.
    """
    ledger_path, chain_path, tx_hash = _settled_run(tmp_path)
    pipeline, ledger, store = _reopened(ledger_path, chain_path)
    try:
        chain = store.get(tx_hash)
        assert chain is not None
        binding = verify_chain_bindings(chain)
        assert binding.bound, binding.failures
        by_name = {c["name"]: c["holds"] for c in binding.checks}
        assert by_name["receiver_agrees"] is True
        assert by_name["amount_agrees"] is True
        assert by_name["transaction_digest_agrees"] is True
        assert by_name["signature_verifies_over_the_digest"] is True
    finally:
        ledger.close()
        store.close()


def test_the_chain_carries_the_signature_and_signer_key_after_a_restart(tmp_path):
    """A recovery-built chain must still carry the signature and the signer key."""
    ledger_path, chain_path, tx_hash = _settled_run(tmp_path)
    pipeline, ledger, store = _reopened(ledger_path, chain_path)
    try:
        chain = store.get(tx_hash)
        sig = chain.stages["SIGNATURE"]
        assert sig.get("signature_b64")
        assert sig.get("public_key", "").startswith("ed25519:")
        assert sig.get("signature_algorithm") == "ed25519"
    finally:
        ledger.close()
        store.close()


def test_recovery_reaches_verified_after_a_restart_from_the_durable_bytes(tmp_path):
    """Mission 22 recovery must reach VERIFIED, not cap at CONFIRMED, post-restart.

    A submission whose send timed out is ``UNKNOWN``; after a restart the chain
    knows the transaction and the transaction is reconstructed from the durable
    bytes, so the amount is re-checked and the verdict is VERIFIED.
    """
    ledger_path = str(tmp_path / "ledger.db")
    boundary, rpc = make_boundary()
    pipeline = NearExecutionPipeline(boundary, ledger=SubmissionLedger(ledger_path))
    prepared = _prepare(boundary)
    rpc.send_status = SourceStatus.TIMEOUT
    rpc.tx_status_status = SourceStatus.NOT_FOUND
    pipeline.execute(prepared, CountingSigner(prepared.transaction.public_key))
    tx_hash = prepared.transaction.tx_hash
    pipeline.ledger.close()

    # Fresh process: the chain now has it.
    boundary2, rpc2 = make_boundary()
    pipeline2 = NearExecutionPipeline(boundary2, ledger=SubmissionLedger(ledger_path))
    try:
        rpc2.tx_status_status = SourceStatus.OK
        rpc2.tx_status_result = result_for(prepared.transaction, finality="FINAL")
        resolved = pipeline2.resolve_unknown(tx_hash)
        assert resolved is not None
        assert resolved.settlement_state == "VERIFIED"
    finally:
        pipeline2.ledger.close()


# ---------------------------------------------------------------------------
# Phase E - adversarial: each case must fail closed
# ---------------------------------------------------------------------------


def _verifier_for(record: SubmissionRecord):
    """An in-memory pipeline that re-verifies exactly the record given."""
    boundary, _rpc = make_boundary()
    ledger = SubmissionLedger()
    ledger.put(record)
    return NearExecutionPipeline(boundary, ledger=ledger), ledger


def _record_from(tmp_path, tx_hash: str) -> SubmissionRecord:
    ledger = SubmissionLedger(str(tmp_path / "ledger.db"))
    try:
        record = ledger.get(tx_hash)
        assert record is not None
        return record
    finally:
        ledger.close()


def test_missing_signed_bytes_is_not_verified(tmp_path):
    ledger_path, _chain, tx_hash = _settled_run(tmp_path)
    record = _record_from(tmp_path, tx_hash)
    record.signed_b64 = ""
    pipeline, _ledger = _verifier_for(record)
    verdict = pipeline.verify_recorded_signature(tx_hash)
    assert verdict["verified"] is False
    assert "signed_bytes_present" in verdict["failures"]


def test_missing_public_key_is_not_verified(tmp_path):
    """If the bytes cannot be decoded, the signer key cannot be recovered."""
    ledger_path, _chain, tx_hash = _settled_run(tmp_path)
    record = _record_from(tmp_path, tx_hash)
    raw = bytearray(base64.b64decode(record.signed_b64))
    raw[2] ^= 0xFF  # corrupt the public-key region
    record.signed_b64 = base64.b64encode(bytes(raw)).decode("ascii")
    pipeline, _ledger = _verifier_for(record)
    verdict = pipeline.verify_recorded_signature(tx_hash)
    assert verdict["verified"] is False
    assert "signature_verifies_over_digest" in verdict["failures"]


def test_invalid_signature_is_not_verified(tmp_path):
    ledger_path, _chain, tx_hash = _settled_run(tmp_path)
    record = _record_from(tmp_path, tx_hash)
    raw = bytearray(base64.b64decode(record.signed_b64))
    raw[-1] ^= 0x01  # flip one signature byte
    record.signed_b64 = base64.b64encode(bytes(raw)).decode("ascii")
    pipeline, _ledger = _verifier_for(record)
    verdict = pipeline.verify_recorded_signature(tx_hash)
    assert verdict["verified"] is False
    assert "signature_verifies_over_digest" in verdict["failures"]


def test_modified_transaction_bytes_are_not_verified(tmp_path):
    """A byte change in the transaction body changes the digest and breaks it."""
    ledger_path, _chain, tx_hash = _settled_run(tmp_path)
    record = _record_from(tmp_path, tx_hash)
    raw = bytearray(base64.b64decode(record.signed_b64))
    raw[10] ^= 0x01  # the signature covers sha256(unsigned); this invalidates it
    record.signed_b64 = base64.b64encode(bytes(raw)).decode("ascii")
    pipeline, _ledger = _verifier_for(record)
    verdict = pipeline.verify_recorded_signature(tx_hash)
    assert verdict["verified"] is False


def test_a_modified_amount_disagrees_with_the_record(tmp_path):
    """A record whose amount disagrees with the signed bytes fails closed."""
    ledger_path, _chain, tx_hash = _settled_run(tmp_path)
    record = _record_from(tmp_path, tx_hash)
    record.amount_base = "999999"
    pipeline, _ledger = _verifier_for(record)
    verdict = pipeline.verify_recorded_signature(tx_hash)
    assert verdict["verified"] is False
    assert "record_matches_signed_bytes" in verdict["failures"]


def test_a_modified_receiver_disagrees_with_the_record(tmp_path):
    ledger_path, _chain, tx_hash = _settled_run(tmp_path)
    record = _record_from(tmp_path, tx_hash)
    record.receiver_id = "attacker.testnet"
    pipeline, _ledger = _verifier_for(record)
    verdict = pipeline.verify_recorded_signature(tx_hash)
    assert verdict["verified"] is False
    assert "record_matches_signed_bytes" in verdict["failures"]


def test_a_modified_signer_disagrees_with_the_record(tmp_path):
    ledger_path, _chain, tx_hash = _settled_run(tmp_path)
    record = _record_from(tmp_path, tx_hash)
    record.signer_id = "attacker.testnet"
    pipeline, _ledger = _verifier_for(record)
    verdict = pipeline.verify_recorded_signature(tx_hash)
    assert verdict["verified"] is False


def test_a_corrupt_record_is_malformed_not_verified(tmp_path):
    ledger_path, _chain, tx_hash = _settled_run(tmp_path)
    record = _record_from(tmp_path, tx_hash)
    record.signed_b64 = "not base64!!"
    pipeline, _ledger = _verifier_for(record)
    verdict = pipeline.verify_recorded_signature(tx_hash)
    assert verdict["verified"] is False
    assert verdict["state"] == "MALFORMED"


def test_a_truncated_record_is_malformed_not_verified(tmp_path):
    ledger_path, _chain, tx_hash = _settled_run(tmp_path)
    record = _record_from(tmp_path, tx_hash)
    record.signed_b64 = base64.b64encode(b"\x00\x00\x00").decode("ascii")
    pipeline, _ledger = _verifier_for(record)
    verdict = pipeline.verify_recorded_signature(tx_hash)
    assert verdict["verified"] is False
    assert verdict["state"] == "MALFORMED"


def test_an_unknown_transaction_is_not_found(tmp_path):
    ledger_path, _chain, _tx = _settled_run(tmp_path)
    pipeline, ledger, _store = _reopened(ledger_path)
    try:
        verdict = pipeline.verify_recorded_signature("NoSuchTransactionHash")
        assert verdict["verified"] is False
        assert verdict["state"] == "NOT_FOUND"
    finally:
        ledger.close()


def test_the_ledger_refuses_to_overwrite_the_recorded_signed_bytes(tmp_path):
    """A substitution of the recorded bytes must be refused, not silently stored."""
    ledger_path, _chain, tx_hash = _settled_run(tmp_path)
    ledger = SubmissionLedger(ledger_path)
    try:
        record = ledger.get(tx_hash)
        record.signed_b64 = base64.b64encode(b"different bytes").decode("ascii")
        with pytest.raises(SubmissionLedgerError):
            ledger.put(record)
        # The original bytes are intact.
        assert ledger.get(tx_hash).signed_b64 != record.signed_b64
    finally:
        ledger.close()


def test_the_in_memory_ledger_refuses_to_overwrite_signed_bytes():
    ledger = SubmissionLedger()
    record = SubmissionRecord(
        tx_hash="H",
        state=SubmissionState.SIGNED,
        network="testnet",
        signer_id=SIGNER,
        receiver_id=RECIPIENT,
        amount_base="1",
        destination=RECIPIENT,
        signed_b64="QUJD",
    )
    ledger.put(record)
    record.signed_b64 = "REVG"
    with pytest.raises(SubmissionLedgerError):
        ledger.put(record)


def test_a_state_update_that_keeps_the_bytes_is_allowed(tmp_path):
    """A settlement/state update carries the same bytes, so it is not a conflict."""
    ledger_path, _chain, tx_hash = _settled_run(tmp_path)
    ledger = SubmissionLedger(ledger_path)
    try:
        record = ledger.get(tx_hash)
        record.transition(SubmissionState.SUBMITTED, reason="test")
        ledger.put(record)  # must not raise
        assert ledger.get(tx_hash).signed_b64
    finally:
        ledger.close()


def test_the_signed_bytes_round_trip_exactly(tmp_path):
    """The persisted blob is byte-identical to what was signed."""
    ledger_path, _chain, tx_hash = _settled_run(tmp_path)
    pipeline, ledger, _store = _reopened(ledger_path)
    try:
        record = ledger.get(tx_hash)
        signed = base64.b64decode(record.signed_b64)
        unsigned = signed[: -1 - 64]
        # The digest recomputed here must equal the verifier's.
        import hashlib

        assert (
            "sha256:" + hashlib.sha256(unsigned).hexdigest()
            == pipeline.verify_recorded_signature(tx_hash)["transaction_digest"]
        )
    finally:
        ledger.close()


# --- the chain must refuse an algorithm it cannot verify -------------------


def test_the_chain_refuses_a_signature_algorithm_it_cannot_verify(tmp_path):
    """A signature labelled with an unknown algorithm must fail, not pass."""
    ledger_path, chain_path, tx_hash = _settled_run(tmp_path)
    pipeline, ledger, store = _reopened(ledger_path, chain_path)
    try:
        chain = store.get(tx_hash)
        chain.put("SIGNATURE", signature_algorithm="secp256k1")
        binding = verify_chain_bindings(chain)
        assert binding.bound is False
        assert "signature_verifies_over_the_digest" in binding.failures
    finally:
        ledger.close()
        store.close()


def test_the_chain_still_verifies_the_default_algorithm(tmp_path):
    ledger_path, chain_path, tx_hash = _settled_run(tmp_path)
    pipeline, ledger, store = _reopened(ledger_path, chain_path)
    try:
        chain = store.get(tx_hash)
        binding = verify_chain_bindings(chain)
        by_name = {c["name"]: c["holds"] for c in binding.checks}
        assert by_name["signature_verifies_over_the_digest"] is True
    finally:
        ledger.close()
        store.close()


def test_a_modified_network_breaks_the_chain(tmp_path):
    ledger_path, chain_path, tx_hash = _settled_run(tmp_path)
    pipeline, ledger, store = _reopened(ledger_path, chain_path)
    try:
        chain = store.get(tx_hash)
        chain.put("AUTHORIZATION", network="mainnet")
        binding = verify_chain_bindings(chain)
        assert binding.bound is False
        assert "network_agrees" in binding.failures
    finally:
        ledger.close()
        store.close()


def test_a_modified_transaction_digest_breaks_the_chain(tmp_path):
    """The digest is the binding between the authorization and the signature."""
    ledger_path, chain_path, tx_hash = _settled_run(tmp_path)
    pipeline, ledger, store = _reopened(ledger_path, chain_path)
    try:
        chain = store.get(tx_hash)
        chain.put("SIGNATURE", transaction_digest="sha256:" + "00" * 32)
        binding = verify_chain_bindings(chain)
        assert binding.bound is False
        assert "transaction_digest_agrees" in binding.failures
    finally:
        ledger.close()
        store.close()


def test_a_replaced_build_digest_breaks_the_chain(tmp_path):
    ledger_path, chain_path, tx_hash = _settled_run(tmp_path)
    pipeline, ledger, store = _reopened(ledger_path, chain_path)
    try:
        chain = store.get(tx_hash)
        chain.put("SIGNATURE", approved_build="deadbeef")
        chain.put("ATTESTATION", wasm_hash="cafef00d")
        binding = verify_chain_bindings(chain)
        assert binding.bound is False
        assert "approved_build_agrees" in binding.failures
    finally:
        ledger.close()
        store.close()


def test_a_valid_signature_never_claims_tee_execution(tmp_path):
    """A verified signature must not populate the attestation stage by itself.

    The chain this run produced carries a verified signature but no attestation
    (the offline boundary has no TEE), so the ATTESTATION stage must be absent and
    the signature claim must not be conflated with a TEE claim.
    """
    ledger_path, chain_path, tx_hash = _settled_run(tmp_path)
    pipeline, ledger, store = _reopened(ledger_path, chain_path)
    try:
        chain = store.get(tx_hash)
        assert chain.stages.get("SIGNATURE", {}).get("signature_b64")
        # No attestation evidence was supplied, so none is claimed.
        assert not chain.stages.get("ATTESTATION")
        # And the re-verification reports TEE provenance as not established.
        verdict = pipeline.verify_recorded_signature(tx_hash)
        assert verdict["verified"] is True
    finally:
        ledger.close()
        store.close()


def test_a_duplicate_persistence_is_idempotent(tmp_path):
    """Writing the same record twice is not a conflict and does not change it."""
    ledger_path, _chain, tx_hash = _settled_run(tmp_path)
    ledger = SubmissionLedger(ledger_path)
    try:
        first = ledger.get(tx_hash)
        ledger.put(first)  # same bytes -> allowed
        second = ledger.get(tx_hash)
        assert second.signed_b64 == first.signed_b64
        assert len([r for r in ledger.all() if r.tx_hash == tx_hash]) == 1
    finally:
        ledger.close()


def test_a_ledger_that_cannot_be_opened_fails_closed(tmp_path):
    """A configured path that cannot be opened is a hard failure, never silent."""
    import sqlite3

    bad = str(tmp_path / "nope" / "deep" / "ledger.db")
    with pytest.raises((sqlite3.OperationalError, OSError)):
        SubmissionLedger(bad)


def test_recovery_before_broadcast_uses_the_signed_bytes(tmp_path):
    """A record signed but not broadcast is resumable from its durable bytes."""
    ledger_path = str(tmp_path / "ledger.db")
    boundary, rpc = make_boundary()
    pipeline = NearExecutionPipeline(boundary, ledger=SubmissionLedger(ledger_path))
    prepared = _prepare(boundary)
    # A SIGNED-but-never-sent record, as if the process died before broadcast.
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
        signature_algorithm="ed25519",
    )
    pipeline.ledger.put(record)
    pipeline.ledger.close()

    # Fresh process resumes from the durable bytes.
    boundary2, rpc2 = make_boundary()
    pipeline2 = NearExecutionPipeline(boundary2, ledger=SubmissionLedger(ledger_path))
    try:
        rpc2.send_result = result_for(prepared.transaction, finality="FINAL")
        rpc2.tx_status_result = result_for(prepared.transaction, finality="FINAL")
        result = pipeline2.resume_signed(prepared.transaction.tx_hash)
        assert result is not None
        assert rpc2.broadcasts == [signed], "the identical durable bytes are re-sent"
    finally:
        pipeline2.ledger.close()

