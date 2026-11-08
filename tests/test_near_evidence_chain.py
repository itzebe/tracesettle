"""The authorization-to-settlement evidence chain.

Each test changes one thing a real attacker would change — the receiver, the
amount, the digest, the signer, the network, the settlement transaction — and
asserts the chain binding catches it. A chain with a contradiction must never
report ``bound``.
"""

from __future__ import annotations


import pytest

from tracesettle.near.tee_signing.evidence_chain import (
    EvidenceChainError,
    EvidenceChainStore,
    build_evidence_chain,
    verify_chain_bindings,
)

DIGEST = "sha256:" + "a" * 64
BUILD = "sha256:" + "b" * 64


def _chain(**overrides):
    kwargs = dict(
        transaction_digest=DIGEST,
        network="testnet",
        tx_hash="HASH1",
        authorization={
            "id": "auth-1",
            "decision": "ALLOW",
            "network": "testnet",
            "transaction_digest": DIGEST,
            "receiver_account": "recipient.testnet",
            "amount_base": "1000",
        },
        transaction={
            "signer_id": "signer.testnet",
            "public_key": "ed25519:KEY",
            "receiver_id": "recipient.testnet",
            "amount_base": "1000",
            "network": "testnet",
            "transaction_digest": DIGEST,
        },
        signing={
            "provider": "outlayer",
            "public_key": "ed25519:KEY",
            "approved_build": BUILD,
            "transaction_digest": DIGEST,
            "receiver_account": "recipient.testnet",
            "amount_base": "1000",
            "signature_verified": True,
            "tx_hash": "HASH1",
        },
        attestation={
            "level": "INDEPENDENTLY_VERIFIED",
            "verified": True,
            "quote_verified": True,
            "wasm_hash": "b" * 64,
            "transaction_hash": "HASH1",
        },
        submission={"tx_hash": "HASH1", "state": "SUBMITTED"},
        settlement={
            "state": "SETTLED",
            "tx_hash": "HASH1",
            "receiver": "recipient.testnet",
            "amount_base": "1000",
            "all_checks_passed": True,
        },
    )
    kwargs.update(overrides)
    return build_evidence_chain(**kwargs)


def test_a_consistent_chain_is_bound():
    chain = _chain()
    binding = verify_chain_bindings(chain)
    assert binding.bound, binding.failures
    assert binding.failures == []
    # Every binding check ran.
    names = {c["name"] for c in binding.checks}
    assert {
        "transaction_digest_agrees",
        "network_agrees",
        "receiver_agrees",
        "amount_agrees",
        "signer_public_key_agrees",
        "approved_build_agrees",
        "broadcast_hash_agrees",
    } <= names


def test_a_substituted_receiver_breaks_the_chain():
    chain = _chain()
    chain.stages["SIGNATURE"]["receiver_account"] = "attacker.testnet"
    binding = verify_chain_bindings(chain)
    assert not binding.bound
    assert "receiver_agrees" in binding.failures


def test_a_substituted_amount_breaks_the_chain():
    chain = _chain()
    chain.stages["SIGNATURE"]["amount_base"] = "999999"
    binding = verify_chain_bindings(chain)
    assert not binding.bound
    assert "amount_agrees" in binding.failures


def test_a_substituted_digest_breaks_the_chain():
    chain = _chain()
    chain.stages["TEE_EXECUTION"]["transaction_digest"] = "sha256:" + "c" * 64
    binding = verify_chain_bindings(chain)
    assert not binding.bound
    assert "transaction_digest_agrees" in binding.failures


def test_a_different_network_breaks_the_chain():
    chain = _chain()
    chain.stages["AUTHORIZATION"]["network"] = "mainnet"
    binding = verify_chain_bindings(chain)
    assert not binding.bound
    assert "network_agrees" in binding.failures


def test_a_settlement_for_another_transaction_breaks_the_chain():
    chain = _chain()
    chain.stages["SETTLEMENT"]["tx_hash"] = "OTHERTX"
    binding = verify_chain_bindings(chain)
    assert not binding.bound
    assert "broadcast_hash_agrees" in binding.failures


def test_a_different_signer_breaks_the_chain():
    chain = _chain()
    chain.stages["SIGNATURE"]["public_key"] = "ed25519:OTHERKEY"
    binding = verify_chain_bindings(chain)
    assert not binding.bound
    assert "signer_public_key_agrees" in binding.failures


def test_a_different_approved_build_breaks_the_chain():
    chain = _chain()
    chain.stages["ATTESTATION"]["wasm_hash"] = "d" * 64
    binding = verify_chain_bindings(chain)
    assert not binding.bound
    assert "approved_build_agrees" in binding.failures


def test_an_absent_stage_is_not_a_contradiction():
    # A chain built right after authorization has no settlement yet; that is
    # incomplete, not contradictory.
    chain = build_evidence_chain(
        transaction_digest=DIGEST,
        network="testnet",
        authorization={
            "id": "auth-1",
            "network": "testnet",
            "transaction_digest": DIGEST,
            "receiver_account": "recipient.testnet",
            "amount_base": "1000",
        },
    )
    binding = verify_chain_bindings(chain)
    assert binding.bound


def test_the_chain_digest_changes_when_a_fact_changes():
    chain = _chain()
    before = chain.digest()
    chain.stages["SETTLEMENT"]["state"] = "FAILED"
    assert chain.digest() != before


def test_building_a_chain_drops_unknown_fields():
    # Only named facts are copied into a stage, so a caller cannot smuggle an
    # arbitrary (or secret) field into the record.
    chain = build_evidence_chain(
        transaction_digest=DIGEST,
        signing={"private_key": "leaked", "public_key": "ed25519:KEY"},
    )
    assert "leaked" not in chain.to_json()
    assert chain.stages["SIGNATURE"]["public_key"] == "ed25519:KEY"


def test_a_forced_secret_field_is_refused_at_verification():
    # The structural guard: if a secret field is ever present in the serialised
    # chain, assembling/verifying it raises rather than persisting it.
    from tracesettle.near.tee_signing.evidence_chain import _reject_secrets

    chain = _chain()
    chain.stages["SIGNATURE"]["private_key"] = "leaked"
    with pytest.raises(EvidenceChainError):
        _reject_secrets(chain)


def test_the_store_round_trips_a_chain(tmp_path):
    store = EvidenceChainStore(str(tmp_path / "chains.db"))
    try:
        chain = _chain()
        store.put(chain)
        loaded = store.get("HASH1")
        assert loaded is not None
        assert loaded.digest() == chain.digest()
        assert verify_chain_bindings(loaded).bound
    finally:
        store.close()


def test_the_store_is_in_memory_without_a_path():
    store = EvidenceChainStore()
    assert store.backend == "in-memory"
    chain = _chain()
    store.put(chain)
    assert store.get("HASH1") is not None


def test_a_stage_order_is_fixed_so_the_digest_is_stable():
    chain = _chain()
    canonical = chain.canonical()
    assert list(canonical["stages"]) == [
        "AUTHORIZATION",
        "PREPARED_TRANSACTION",
        "TEE_EXECUTION",
        "ATTESTATION",
        "SIGNATURE",
        "BROADCAST",
        "FINALITY",
        "SETTLEMENT",
    ]


def test_an_unknown_stage_is_refused():
    chain = _chain()
    with pytest.raises(EvidenceChainError):
        chain.put("NOT_A_STAGE", x=1)


def test_the_authorization_stage_records_the_bound_parameters():
    # The authorization's own receiver/amount must be in the chain, or a later
    # stage could only be compared to another later stage, never to what was
    # actually authorized.
    from tracesettle.near.tee_signing.evidence_chain import build_evidence_chain

    digest = "sha256:" + "a" * 64
    chain = build_evidence_chain(
        transaction_digest=digest,
        authorization={
            "network": "testnet",
            "transaction_digest": digest,
            "receiver_account": "r.testnet",
            "amount_base": "1000",
        },
    )
    assert chain.stages["AUTHORIZATION"]["receiver_account"] == "r.testnet"
    assert chain.stages["AUTHORIZATION"]["amount_base"] == "1000"


def test_the_authorization_binding_is_what_a_substituted_receiver_breaks():
    # Only the AUTHORIZATION and SIGNATURE stages are present: the check must be
    # authorization-vs-signature, not signature-vs-signature.
    from tracesettle.near.tee_signing.evidence_chain import build_evidence_chain

    digest = "sha256:" + "a" * 64
    chain = build_evidence_chain(
        transaction_digest=digest,
        authorization={
            "network": "testnet",
            "transaction_digest": digest,
            "receiver_account": "r.testnet",
            "amount_base": "1000",
        },
        signing={"receiver_account": "attacker.testnet", "tx_hash": "HASH1"},
    )
    binding = verify_chain_bindings(chain)
    assert not binding.bound
    assert "receiver_agrees" in binding.failures


def test_the_unsigned_bytes_are_recovered_with_the_shared_boundary():
    from tracesettle.near.txbuild import SIGNATURE_TRAILER_LEN, NearTransaction

    unsigned = b"a-transaction"
    signed = unsigned + b"\x00" + b"\x11" * 64
    assert NearTransaction.unsigned_from_signed(signed) == unsigned
    assert SIGNATURE_TRAILER_LEN == 65
    # A one-byte arithmetic error would drop a byte of the transaction and change
    # the digest; assert the length is exact, not merely close.
    assert len(NearTransaction.unsigned_from_signed(signed)) == len(unsigned)


# --- the real Mission 25 capture binds --------------------------------------


def _chain_from_real_capture():
    """Assemble the chain from the shipped on-chain TEE run, inventing nothing."""
    import json
    import pathlib

    path = pathlib.Path(__file__).resolve().parents[1] / "tracesettle" / "near" / "fixtures" / "onchain_tee_run.json"
    run = json.loads(path.read_text(encoding="utf-8"))
    sign = run["sign_transaction"]["output"]
    settle = run["settlement"]
    digest = sign["transaction_digest"]
    return build_evidence_chain(
        transaction_digest=digest,
        authorization={
            "id": sign["authorization_id"], "decision": "ALLOW",
            "transaction_digest": digest, "network": sign["network"],
            "receiver_account": sign["receiver_id"], "amount_base": sign["amount_base"],
        },
        transaction={
            "signer_id": sign["signer_id"], "public_key": sign["public_key"],
            "receiver_id": sign["receiver_id"], "amount_base": sign["amount_base"],
            "network": sign["network"], "transaction_digest": digest,
        },
        signing={
            "provider": "outlayer:signing-keys-onchain",
            "execution_id": settle["tx_hash"],
            "public_key": sign["public_key"], "approved_build": sign["approved_build"],
            "network": sign["network"], "transaction_digest": digest,
            "signature_b64": sign["signature"], "receiver_account": sign["receiver_id"],
            "amount_base": sign["amount_base"],
            "signature_verified": sign["signature_verified_in_guest"],
            "tx_hash": sign["tx_hash"],
        },
        submission={"tx_hash": settle["tx_hash"]},
        settlement={"tx_hash": settle["tx_hash"], "amount_base": str(settle["amount_yocto"])},
        network=sign["network"], tx_hash=sign["tx_hash"],
    )


def test_the_real_mission25_capture_produces_a_bound_chain():
    """The live run's own numbers must assemble into one bound chain.

    This is not a synthetic vector: every value comes from the shipped capture of
    the 2026-11-07 on-chain TEE signing run, so a drift in any stage's field name
    or a real inconsistency between the run's layers fails here.
    """
    chain = _chain_from_real_capture()
    binding = verify_chain_bindings(chain)
    assert binding.bound, binding.failures
    names = {c["name"] for c in binding.to_dict()["checks"]}
    assert {
        "transaction_digest_agrees",
        "receiver_agrees",
        "amount_agrees",
        "signer_public_key_agrees",
        "approved_build_agrees",
        "broadcast_hash_agrees",
    } <= names
    assert chain.tx_hash == "F27Erv42DhGhaTqNXPhsf5KXedfQvP3cd1Vbz9aZnQPj"


def test_the_real_chain_breaks_when_the_settlement_is_for_another_transaction():
    """The real capture, with the settlement hash swapped, must not stay bound."""
    chain = _chain_from_real_capture()
    chain.put("SETTLEMENT", tx_hash="someOtherHash")
    binding = verify_chain_bindings(chain)
    assert binding.bound is False
    assert "broadcast_hash_agrees" in binding.failures


# --- the chain re-verifies the signature, not just the strings --------------


def test_the_real_chain_re_verifies_the_signature_over_the_digest():
    """The chain must cryptographically re-check the signature it carries.

    String equality between stages cannot tell a genuine signature from a
    well-formed fake. The real capture's signature must verify against the
    recorded key over the recorded digest, and the check must be named.
    """
    chain = _chain_from_real_capture()
    binding = verify_chain_bindings(chain)
    assert binding.bound, binding.failures
    by_name = {c["name"]: c for c in binding.checks}
    assert by_name["signature_verifies_over_the_digest"]["holds"] is True


def test_a_tampered_signature_breaks_the_chain_even_when_every_string_agrees():
    """A signature that no longer verifies must fail, though every field matches.

    The tamper flips one signature byte only. Every string field is unchanged, so
    a check that compared strings would still report bound; only the ed25519
    re-verification catches it.
    """
    import base64

    chain = _chain_from_real_capture()
    raw = bytearray(base64.b64decode(chain.stages["SIGNATURE"]["signature_b64"]))
    raw[0] ^= 0x01
    chain.put("SIGNATURE", signature_b64=base64.b64encode(bytes(raw)).decode())
    binding = verify_chain_bindings(chain)
    assert binding.bound is False
    assert "signature_verifies_over_the_digest" in binding.failures


def test_a_malformed_signature_field_is_a_failure_not_a_skip():
    """A present-but-unparseable signature must fail, never be skipped."""
    chain = _chain_from_real_capture()
    chain.put("SIGNATURE", signature_b64="not base64!!")
    binding = verify_chain_bindings(chain)
    assert binding.bound is False
    assert "signature_verifies_over_the_digest" in binding.failures


def test_an_absent_signature_is_skipped_not_failed():
    """A chain with no signature stage yet is a limitation, not a contradiction."""
    chain = build_evidence_chain(
        transaction_digest=DIGEST,
        authorization={"transaction_digest": DIGEST, "receiver_account": "r", "amount_base": "1"},
    )
    binding = verify_chain_bindings(chain)
    names = {c["name"] for c in binding.checks}
    assert "signature_verifies_over_the_digest" not in names
    assert binding.bound is True
