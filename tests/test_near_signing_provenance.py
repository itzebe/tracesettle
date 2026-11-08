"""End-to-end proof that a genuine Intel TDX enclave produced a signed transaction.

The fixtures are **real**: the Mission 25 signing run capture and the Intel TDX
attestation OutLayer published for the ``request_execution`` call that produced it,
together with that call's FINAL on-chain result. No network call is made — the real
capture is replayed offline, so every check is the real code path.

The point of these tests is that the decisive link can *fail*: swapping the signed
transaction, changing the digest, re-using an attestation for another execution, or
dropping the attestation must each be refused, and a valid signature alone must
never be promoted to TEE-verified.
"""

from __future__ import annotations

import base64
import copy
import json
from pathlib import Path

import pytest

from tracesettle.near.tee_signing.signing_provenance import (
    LEVEL_NOT_VERIFIED,
    LEVEL_SIGNATURE_VERIFIED,
    LEVEL_TEE_SIGNING_VERIFIED,
    verify_attested_signing,
)

FIXTURES = Path(__file__).resolve().parents[1] / "tracesettle/near/fixtures"
RUN_FIXTURE = FIXTURES / "onchain_tee_run.json"
ATT_FIXTURE = FIXTURES / "onchain_tee_attestation.json"


@pytest.fixture()
def run_record() -> dict:
    return json.loads(RUN_FIXTURE.read_text(encoding="utf-8"))


@pytest.fixture()
def attestation_fixture() -> dict:
    return json.loads(ATT_FIXTURE.read_text(encoding="utf-8"))


def _verify(run: dict, att_fixture: dict, **kwargs):
    # The register-contract approval is an on-chain fact, but this suite is
    # offline and deterministic: replay the approval recorded in the fixture
    # rather than reaching the chain (a rate-limited RPC must not decide a unit
    # test). ``worker_is_approved`` is exercised against the live contract in
    # the opt-in live test and in evidence/mission29.
    if "rpc" not in kwargs and att_fixture.get("worker_approval") is not None:
        from tracesettle.near.tee_signing.outlayer_attestation import RecordedApprovalRpc

        kwargs["rpc"] = RecordedApprovalRpc(att_fixture["worker_approval"])
    return verify_attested_signing(
        run,
        att_fixture["attestation"],
        network="testnet",
        tx_result=att_fixture["tx_result"],
        expected_wasm_sha256=att_fixture["approved_wasm_sha256"],
        **kwargs,
    )


def test_the_real_run_is_tee_signing_verified(run_record, attestation_fixture):
    verdict = _verify(run_record, attestation_fixture)
    assert verdict.level == LEVEL_TEE_SIGNING_VERIFIED
    assert verdict.verified is True
    assert verdict.failures == []
    assert verdict.attestation_verified is True
    assert verdict.attestation_level == "INDEPENDENTLY_VERIFIED"
    # Every link, in order, from the quote to the signature.
    assert [c.name for c in verdict.checks] == [
        "signed_bytes_parse",
        "digest_matches_signed_bytes",
        "tx_hash_is_b58_of_digest",
        "signature_verifies_over_digest",
        "enclave_output_hash_binds_the_receipt",
        "attested_output_is_this_signing_output",
        "attestation_verified",
    ]


def test_the_attested_output_hash_binds_the_signed_transaction(run_record, attestation_fixture):
    """The decisive link: the Intel-signed output_hash equals sha256(receipt output),
    and that output IS the signing output that carries the signed transaction."""
    verdict = _verify(run_record, attestation_fixture)
    assert verdict.enclave_output_hash == verdict.recomputed_output_hash
    by_name = {c.name: c.holds for c in verdict.checks}
    assert by_name["enclave_output_hash_binds_the_receipt"] is True
    assert by_name["attested_output_is_this_signing_output"] is True


def test_a_swapped_signed_transaction_is_refused(run_record, attestation_fixture):
    """A host that swaps the signed transaction changes the enclave output bytes,
    so the attested output_hash no longer matches: the run must be refused."""
    run = copy.deepcopy(run_record)
    signed = bytearray(base64.b64decode(run["sign_transaction"]["output"]["signed_transaction"]))
    signed[-1] ^= 0x01
    run["sign_transaction"]["output"]["signed_transaction"] = base64.b64encode(bytes(signed)).decode()
    verdict = _verify(run, attestation_fixture)
    assert verdict.verified is False
    assert verdict.level != LEVEL_TEE_SIGNING_VERIFIED
    # The signature no longer verifies over the changed bytes, and the output no
    # longer matches the attested hash.
    assert "attested_output_is_this_signing_output" in verdict.failures


def test_a_changed_digest_is_refused(run_record, attestation_fixture):
    run = copy.deepcopy(run_record)
    run["sign_transaction"]["output"]["transaction_digest"] = "sha256:" + "00" * 32
    verdict = _verify(run, attestation_fixture)
    assert verdict.verified is False
    assert "digest_matches_signed_bytes" in verdict.failures


def test_a_different_attestation_for_another_execution_is_refused(run_record, attestation_fixture):
    """A genuine quote from one execution must not vouch for another: the task
    hash is recomputed from the record, so a record that does not match fails."""
    att = copy.deepcopy(attestation_fixture)
    att["attestation"]["transaction_hash"] = "ANOTHERtxhashThatIsNotThisOne1111111111111"
    att["attestation"]["timestamp"] = att["attestation"]["timestamp"] + 1
    verdict = _verify(run_record, att)
    assert verdict.verified is False
    assert verdict.level != LEVEL_TEE_SIGNING_VERIFIED


def test_a_valid_signature_without_attestation_is_only_signature_verified(run_record, attestation_fixture):
    """The signature is genuine for the exact transaction, but if the enclave
    provenance cannot be established the verdict must say exactly that — never
    TEE-verified."""
    att = copy.deepcopy(attestation_fixture)
    raw = bytearray(base64.b64decode(att["attestation"]["tdx_quote"]))
    raw[48 + 520] ^= 0x01  # corrupt the committed task hash inside the quote
    att["attestation"]["tdx_quote"] = base64.b64encode(bytes(raw)).decode()
    verdict = _verify(run_record, att)
    assert verdict.verified is False
    assert verdict.level in (LEVEL_SIGNATURE_VERIFIED, LEVEL_NOT_VERIFIED)
    assert verdict.level != LEVEL_TEE_SIGNING_VERIFIED


def test_no_on_chain_result_cannot_bind_the_enclave_output(run_record, attestation_fixture):
    """Without the on-chain result the enclave output cannot be bound, so the run
    is not TEE-verified."""
    verdict = verify_attested_signing(
        run_record,
        attestation_fixture["attestation"],
        network="testnet",
        tx_result=None,
        expected_wasm_sha256=attestation_fixture["approved_wasm_sha256"],
    )
    assert verdict.verified is False
    assert "enclave_output_is_the_signed_transaction" in verdict.failures


def test_a_different_approved_build_is_refused(run_record, attestation_fixture):
    verdict = verify_attested_signing(
        run_record,
        attestation_fixture["attestation"],
        network="testnet",
        tx_result=attestation_fixture["tx_result"],
        expected_wasm_sha256="00" * 32,
    )
    assert verdict.verified is False
    assert verdict.level != LEVEL_TEE_SIGNING_VERIFIED


def test_a_non_success_signing_output_is_a_structural_error(run_record, attestation_fixture):
    from tracesettle.near.tee_signing.outlayer_attestation import OutLayerAttestationError

    run = copy.deepcopy(run_record)
    run["sign_transaction"]["output"]["status"] = "err"
    with pytest.raises(OutLayerAttestationError):
        _verify(run, attestation_fixture)


def test_a_missing_signing_output_is_a_structural_error(run_record, attestation_fixture):
    from tracesettle.near.tee_signing.outlayer_attestation import OutLayerAttestationError

    run = copy.deepcopy(run_record)
    del run["sign_transaction"]["output"]
    with pytest.raises(OutLayerAttestationError):
        _verify(run, attestation_fixture)


def test_the_verdict_serialises_without_secrets(run_record, attestation_fixture):
    payload = _verify(run_record, attestation_fixture).to_dict()
    text = json.dumps(payload)
    # Public identifiers only: no private key, no seed, no API key.
    for forbidden in ("private", "secret", "seed", "api_key", "mnemonic"):
        assert forbidden not in text.lower()
    assert payload["tee_signing_verified"] is True
