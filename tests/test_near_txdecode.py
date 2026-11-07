"""The strict ``SignedTransaction`` decoder and the recovery it enables.

The decoder is what lets a *recovered* submission (one whose original
``PreparedOperation`` is gone) be verified to the same standard as one still in
memory. These tests drive the real builders, the real ed25519 implementation and
the real pipeline; the only substitution is the RPC transport, as everywhere in
the near suite.

Two properties are load-bearing and each is checked here:

* the decoder is *faithful* - a decoded transaction re-serializes to the exact
  bytes it came from, and a single changed byte is refused;
* recovery is *not weakened* - when the bytes cannot be reconstructed the verdict
  falls back to the honest ``CONFIRMED`` cap rather than claiming ``VERIFIED``.
"""

from __future__ import annotations

import base64

import pytest

from near_helpers import (
    RECIPIENT,
    SIGNER,
    TEST_SEED,
    make_boundary,
    public_key_for_test,
    result_for,
)
from tracesettle.model import SourceStatus
from tracesettle.near import ed25519, txbuild, txdecode
from tracesettle.near.assets import resolve_asset
from tracesettle.near.ledger import SubmissionLedger, SubmissionState
from tracesettle.near.networks import NearNetwork
from tracesettle.near.pipeline import NearExecutionPipeline
from tracesettle.near.txdecode import TransactionDecodeError
from tracesettle.near.verify import SettlementState


class CountingSigner:
    def __init__(self, public_key: str):
        self._public_key = public_key
        self.calls = 0

    @property
    def public_key(self) -> str:
        return self._public_key

    def sign(self, message: bytes) -> bytes:
        self.calls += 1
        return ed25519.sign(message, TEST_SEED)


def _native_transaction(*, amount: str = "1"):
    return txbuild.build_transfer(
        network=NearNetwork.TESTNET,
        signer_id=SIGNER,
        public_key=public_key_for_test(),
        nonce=42,
        receiver_id=RECIPIENT,
        block_hash="11111111111111111111111111111111",
        amount_human=amount,
    )


def _signed(tx):
    signature = ed25519.sign(tx.tx_hash_bytes, TEST_SEED)
    return tx.signed_bytes(signature)


# -- decoder faithfulness -----------------------------------------------------


def test_decoder_round_trips_a_native_transfer():
    tx = _native_transaction(amount="0.5")
    decoded = txdecode.decode_signed_transaction(_signed(tx), network=NearNetwork.TESTNET)

    assert decoded.operation == txbuild.OP_TRANSFER
    assert decoded.amount_base == tx.amount_base
    assert decoded.destination == RECIPIENT
    assert decoded.signer_id == SIGNER
    assert decoded.nonce == 42
    assert decoded.tx_hash == tx.tx_hash
    # The rebuilt transaction is byte-for-byte the one that was signed.
    assert decoded.to_transaction().unsigned_bytes() == tx.unsigned_bytes()
    assert decoded.to_transaction().tx_hash == tx.tx_hash


def test_decoder_round_trips_an_ft_transfer():
    asset = resolve_asset(NearNetwork.TESTNET, "usdc.fakes.testnet")
    tx = txbuild.build_ft_transfer(
        network=NearNetwork.TESTNET,
        signer_id=SIGNER,
        public_key=public_key_for_test(),
        nonce=7,
        block_hash="11111111111111111111111111111111",
        asset=asset,
        receiver_id=RECIPIENT,
        amount_human="12.5",
    )
    decoded = txdecode.decode_signed_transaction(_signed(tx), network=NearNetwork.TESTNET)

    assert decoded.operation == txbuild.OP_FT_TRANSFER
    assert decoded.amount_base == tx.amount_base
    assert decoded.destination == RECIPIENT  # the recipient, not the contract
    assert decoded.receiver_id == asset.contract  # the contract is the tx receiver
    assert decoded.asset.identifier == asset.identifier
    assert decoded.to_transaction().unsigned_bytes() == tx.unsigned_bytes()


def test_decoder_refuses_a_changed_byte():
    tx = _native_transaction()
    raw = bytearray(_signed(tx))
    raw[40] ^= 0x01  # flip a bit inside the encoded amount
    with pytest.raises(TransactionDecodeError):
        txdecode.decode_signed_transaction(bytes(raw), network=NearNetwork.TESTNET)


def test_decoder_refuses_a_signature_that_does_not_verify():
    tx = _native_transaction()
    raw = bytearray(_signed(tx))
    raw[-1] ^= 0x01  # corrupt the signature, not the body
    with pytest.raises(TransactionDecodeError):
        txdecode.decode_signed_transaction(bytes(raw), network=NearNetwork.TESTNET)


def test_decoder_refuses_trailing_bytes():
    tx = _native_transaction()
    with pytest.raises(TransactionDecodeError):
        txdecode.decode_signed_transaction(_signed(tx) + b"\x00", network=NearNetwork.TESTNET)


def test_decoder_refuses_an_empty_blob():
    with pytest.raises(TransactionDecodeError):
        txdecode.decode_signed_transaction(b"", network=NearNetwork.TESTNET)


def test_decoder_refuses_a_non_base64_stored_blob():
    with pytest.raises(TransactionDecodeError):
        txdecode.decode_signed_b64("not base64!!!", network=NearNetwork.TESTNET)


def test_decode_is_network_scoped_for_the_asset_registry():
    # A testnet contract is not a registered asset on mainnet, so the decode still
    # succeeds (the bytes are valid) but the operation is not described, which the
    # pipeline treats as "cannot reconstruct".
    asset = resolve_asset(NearNetwork.TESTNET, "usdc.fakes.testnet")
    tx = txbuild.build_ft_transfer(
        network=NearNetwork.TESTNET,
        signer_id=SIGNER,
        public_key=public_key_for_test(),
        nonce=7,
        block_hash="11111111111111111111111111111111",
        asset=asset,
        receiver_id=RECIPIENT,
        amount_human="1",
    )
    decoded = txdecode.decode_signed_transaction(_signed(tx), network=NearNetwork.MAINNET)
    assert decoded.operation == "UNKNOWN"
    assert decoded.notes  # it says why, rather than guessing


# -- recovery upgraded to the same standard ----------------------------------


def _unknown_record_pipeline(boundary):
    """Drive one submission to an ``UNKNOWN`` outcome with the bytes recorded."""
    pipeline = NearExecutionPipeline(boundary, ledger=SubmissionLedger())
    prepared = boundary.prepare(
        service_id="treasury-agent",
        account_id=SIGNER,
        public_key=public_key_for_test(),
        receiver_id=RECIPIENT,
        asset_identifier="near:native",
        amount_human="1",
    )
    return pipeline, prepared


def test_recovery_without_the_original_transaction_reconstructs_from_bytes():
    boundary, rpc = make_boundary()
    pipeline, prepared = _unknown_record_pipeline(boundary)
    rpc.send_status = SourceStatus.TIMEOUT
    rpc.tx_status_status = SourceStatus.NOT_FOUND
    pipeline.execute(prepared, CountingSigner(prepared.transaction.public_key))

    record = pipeline.ledger.get(prepared.transaction.tx_hash)
    assert record is not None and record.state == SubmissionState.UNKNOWN

    # The chain now knows it and it is final. Recovery is asked *without* the
    # original transaction - the situation after a restart.
    rpc.tx_status_status = SourceStatus.OK
    rpc.tx_status_result = result_for(prepared.transaction, finality="FINAL")

    resolved = pipeline.resolve_unknown(prepared.transaction.tx_hash)
    assert resolved is not None
    # Reconstructed from the durable bytes, so the amount is re-checked: VERIFIED,
    # not merely CONFIRMED.
    assert resolved.settlement_state == SettlementState.VERIFIED.value


def test_recovery_falls_back_when_the_recorded_bytes_are_tampered():
    boundary, rpc = make_boundary()
    pipeline, prepared = _unknown_record_pipeline(boundary)
    rpc.send_status = SourceStatus.TIMEOUT
    rpc.tx_status_status = SourceStatus.NOT_FOUND
    pipeline.execute(prepared, CountingSigner(prepared.transaction.public_key))

    # Corrupt the stored bytes: they no longer decode, so recovery must not claim
    # the stronger verdict.
    record = pipeline.ledger.get(prepared.transaction.tx_hash)
    raw = bytearray(base64.b64decode(record.signed_b64))
    raw[40] ^= 0x01
    record.signed_b64 = base64.b64encode(bytes(raw)).decode("ascii")
    pipeline.ledger.put(record)

    rpc.tx_status_status = SourceStatus.OK
    rpc.tx_status_result = result_for(prepared.transaction, finality="FINAL")

    resolved = pipeline.resolve_unknown(prepared.transaction.tx_hash)
    assert resolved is not None
    assert resolved.settlement_state == SettlementState.CONFIRMED.value
    assert resolved.settlement_state != SettlementState.VERIFIED.value


def test_recovery_falls_back_when_the_record_disagrees_with_the_bytes():
    boundary, rpc = make_boundary()
    pipeline, prepared = _unknown_record_pipeline(boundary)
    rpc.send_status = SourceStatus.TIMEOUT
    rpc.tx_status_status = SourceStatus.NOT_FOUND
    pipeline.execute(prepared, CountingSigner(prepared.transaction.public_key))

    # The bytes are valid, but the record claims a different amount. The
    # cross-check must refuse to reconstruct rather than trust either side.
    record = pipeline.ledger.get(prepared.transaction.tx_hash)
    record.amount_base = "999"
    pipeline.ledger.put(record)

    rpc.tx_status_status = SourceStatus.OK
    rpc.tx_status_result = result_for(prepared.transaction, finality="FINAL")

    resolved = pipeline.resolve_unknown(prepared.transaction.tx_hash)
    assert resolved is not None
    assert resolved.settlement_state != SettlementState.VERIFIED.value


def test_recovery_without_stored_bytes_keeps_the_weaker_check():
    boundary, rpc = make_boundary()
    pipeline, prepared = _unknown_record_pipeline(boundary)
    rpc.send_status = SourceStatus.TIMEOUT
    rpc.tx_status_status = SourceStatus.NOT_FOUND
    pipeline.execute(prepared, CountingSigner(prepared.transaction.public_key))

    record = pipeline.ledger.get(prepared.transaction.tx_hash)
    record.signed_b64 = ""
    pipeline.ledger.put(record)

    rpc.tx_status_status = SourceStatus.OK
    rpc.tx_status_result = result_for(prepared.transaction, finality="FINAL")

    resolved = pipeline.resolve_unknown(prepared.transaction.tx_hash)
    assert resolved is not None
    assert resolved.settlement_state == SettlementState.CONFIRMED.value


def test_recovery_reconstructing_never_resubmits():
    boundary, rpc = make_boundary()
    pipeline, prepared = _unknown_record_pipeline(boundary)
    rpc.send_status = SourceStatus.TIMEOUT
    rpc.tx_status_status = SourceStatus.NOT_FOUND
    pipeline.execute(prepared, CountingSigner(prepared.transaction.public_key))
    broadcasts = len(rpc.broadcasts)

    rpc.tx_status_status = SourceStatus.OK
    rpc.tx_status_result = result_for(prepared.transaction, finality="FINAL")
    pipeline.recover()
    pipeline.recover()

    assert len(rpc.broadcasts) == broadcasts, "recovery must never send"
