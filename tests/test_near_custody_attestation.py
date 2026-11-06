"""Tests for per-operation custody attestation verification.

Two tiers, kept strictly separate:

* **Real hardware evidence.** ``attestation_nearai_cloud.json`` is a genuine TDX
  quote captured live from the public NEAR AI Cloud gateway. Its signature chain
  verifies to the pinned Intel root for real. Because a real Intel-signed quote
  cannot be minted for an arbitrary custody digest, that fixture is used to prove
  the *refusal* direction: a genuine quote that does not commit to our operation
  is refused (``DISPUTED``), never accepted.

* **Synthetic binding.** A labelled fake verifier echoes the ``report_data`` the
  binding logic demands, so the positive path and every mismatch can be exercised
  deterministically. Nothing here is presented as live TDX evidence; the real
  signature check lives in ``tests/test_near_tdx.py``.

No network call is made.
"""

from __future__ import annotations

import base64
import json
from pathlib import Path

import pytest

from tracesettle.near import custody_attestation as ca
from tracesettle.near import tdx

FIXTURE = (
    Path(__file__).resolve().parent.parent
    / "tracesettle"
    / "near"
    / "fixtures"
    / "attestation_nearai_cloud.json"
)

DIGEST = "a" * 64


@pytest.fixture()
def real_quote() -> dict:
    return json.loads(FIXTURE.read_text(encoding="utf-8"))


def _wallet_key(seed_byte: int = 1) -> tuple[str, str]:
    """A deterministic ed25519 public key (base58) and its raw hex."""
    from tracesettle.near import ed25519

    raw = ed25519.public_key(bytes([seed_byte]) * 32)
    alphabet = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz"
    n = int.from_bytes(raw, "big")
    enc = ""
    while n:
        n, rem = divmod(n, 58)
        enc = alphabet[rem] + enc
    enc = alphabet[0] * (len(raw) - len(raw.lstrip(b"\x00"))) + enc
    return f"ed25519:{enc}", raw.hex()


class _FakeVerification:
    def __init__(self, *, report_data: bytes, verified=True, failures=None, checks=None, measurement=None):
        self.verified = verified
        self.failures = list(failures or [])
        self.checks = dict(checks or {})
        self.report_data = report_data.hex()
        self.measurement = dict(measurement or {"mr_seam": "ab" * 32})
        self.intel_root_fingerprint = "deadbeef"


def _echo_verifier(*, verified=True, corrupt=None, measurement=None):
    """A labelled fake verifier that echoes the binding the caller demanded.

    ``corrupt`` names a check to force false (``nonce_bound`` /
    ``signing_identity_bound``) or a report_data field to break.
    """

    def _verify(raw_quote, *, nonce=None, signing_address=None, event_log=None, now=None, collateral_client=None):
        # Rebuild exactly what the real verifier would find if the quote were
        # genuine and bound to this operation.
        import hashlib

        expected = hashlib.sha256(signing_address or b"").digest() + (nonce or b"\x00" * 32)
        rd = bytearray(expected)
        checks = {"nonce_bound": True, "signing_identity_bound": True}
        if corrupt == "nonce":
            checks["nonce_bound"] = False
            rd[40] ^= 0x01
        elif corrupt == "key":
            checks["signing_identity_bound"] = False
            rd[8] ^= 0x01
        return _FakeVerification(
            report_data=bytes(rd),
            verified=verified,
            checks=checks,
            measurement=measurement,
            failures=[] if verified else ["forced failure"],
        )

    return _verify


# --- real hardware evidence: the refusal direction --------------------------


def test_a_real_quote_for_another_operation_is_refused(real_quote):
    """A genuine Intel-signed quote that does not commit to our operation fails.

    The fixture is real hardware attestation captured from the public NEAR AI
    Cloud gateway; bound to *its own* nonce and signing address it verifies (see
    :func:`test_the_real_fixture_is_genuine_hardware_evidence`). Forced to commit
    to our custody digest and wallet key instead, it must be refused.
    """
    key, _ = _wallet_key()
    evidence = ca.verify_custody_attestation(
        {"intel_quote": real_quote["intel_quote"]},
        custody_digest=DIGEST,
        wallet_public_key=key,
        wallet_account="w",
        network="testnet",
    )
    assert evidence.quote_present is True
    assert evidence.quote_verified is False  # the quote does not bind our digest/key
    assert evidence.operation_bound is False
    assert evidence.state is ca.CustodyEvidenceState.DISPUTED
    assert evidence.tee_attested is False


def test_the_real_fixture_is_genuine_hardware_evidence(real_quote):
    """The same fixture verifies under its own bindings: it is real TDX evidence.

    This is the control that makes the refusal test meaningful - the quote is not
    merely unparseable, it is a valid quote that we correctly refuse to accept for
    an operation it does not commit to.
    """
    verification = tdx.verify_tdx_quote(
        bytes.fromhex(real_quote["intel_quote"]),
        nonce=bytes.fromhex(real_quote["request_nonce"]),
        signing_address=bytes.fromhex(real_quote["signing_address"]),
        tls_cert_fingerprint=bytes.fromhex(real_quote["tls_cert_fingerprint"]),
        event_log=real_quote["event_log"],
    )
    assert verification.verified, verification.failures
    assert verification.intel_root_fingerprint == tdx.INTEL_SGX_ROOT_CA_SHA256


# --- missing / malformed ----------------------------------------------------


def test_no_attestation_is_unavailable_not_verified():
    key, _ = _wallet_key()
    evidence = ca.verify_custody_attestation(
        None, custody_digest=DIGEST, wallet_public_key=key, wallet_account="w", network="testnet"
    )
    assert evidence.state is ca.CustodyEvidenceState.PER_OPERATION_TEE_ATTESTATION_UNAVAILABLE
    assert evidence.tee_attested is False
    assert evidence.quote_verified is False


def test_empty_attestation_is_unavailable():
    key, _ = _wallet_key()
    evidence = ca.verify_custody_attestation(
        {}, custody_digest=DIGEST, wallet_public_key=key, wallet_account="w", network="testnet"
    )
    assert evidence.state is ca.CustodyEvidenceState.PER_OPERATION_TEE_ATTESTATION_UNAVAILABLE


def test_malformed_quote_is_refused_without_verifying():
    key, _ = _wallet_key()
    evidence = ca.verify_custody_attestation(
        {"quote": "not-a-quote"},
        custody_digest=DIGEST,
        wallet_public_key=key,
        wallet_account="w",
        network="testnet",
    )
    assert evidence.quote_present is False
    assert evidence.state is ca.CustodyEvidenceState.INSUFFICIENT_EVIDENCE
    assert evidence.tee_attested is False


def test_non_ed25519_wallet_key_cannot_bind():
    evidence = ca.verify_custody_attestation(
        {"quote": "ab" * 2000},
        custody_digest=DIGEST,
        wallet_public_key="secp256k1:abc",
        wallet_account="w",
        network="testnet",
    )
    assert evidence.state is ca.CustodyEvidenceState.INSUFFICIENT_EVIDENCE
    assert evidence.tee_attested is False


# --- synthetic binding: the positive path and every mismatch ----------------


def test_a_correctly_bound_synthetic_quote_verifies():
    key, _ = _wallet_key()
    evidence = ca.verify_custody_attestation(
        {"quote": "ab" * 2000},
        custody_digest=DIGEST,
        wallet_public_key=key,
        wallet_account="w",
        network="testnet",
        quote_verifier=_echo_verifier(),
    )
    assert evidence.quote_verified is True
    assert evidence.operation_bound is True
    assert evidence.signing_key_bound is True
    assert evidence.tee_attested is True
    assert evidence.state is ca.CustodyEvidenceState.ATTESTATION_VERIFIED


def test_changed_custody_digest_breaks_the_operation_binding():
    key, _ = _wallet_key()
    evidence = ca.verify_custody_attestation(
        {"quote": "ab" * 2000},
        custody_digest="b" * 64,
        wallet_public_key=key,
        wallet_account="w",
        network="testnet",
        quote_verifier=_echo_verifier(corrupt="nonce"),
    )
    assert evidence.operation_bound is False
    assert evidence.state is ca.CustodyEvidenceState.DISPUTED
    assert evidence.tee_attested is False


def test_wrong_signing_key_breaks_the_key_binding():
    key, _ = _wallet_key()
    evidence = ca.verify_custody_attestation(
        {"quote": "ab" * 2000},
        custody_digest=DIGEST,
        wallet_public_key=key,
        wallet_account="w",
        network="testnet",
        quote_verifier=_echo_verifier(corrupt="key"),
    )
    assert evidence.signing_key_bound is False
    assert evidence.state is ca.CustodyEvidenceState.DISPUTED
    assert evidence.tee_attested is False


def test_unverified_quote_is_disputed_even_with_matching_report_data():
    key, _ = _wallet_key()
    evidence = ca.verify_custody_attestation(
        {"quote": "ab" * 2000},
        custody_digest=DIGEST,
        wallet_public_key=key,
        wallet_account="w",
        network="testnet",
        quote_verifier=_echo_verifier(verified=False),
    )
    assert evidence.quote_verified is False
    assert evidence.tee_attested is False
    assert evidence.state is ca.CustodyEvidenceState.DISPUTED


def test_unapproved_measurement_is_refused():
    key, _ = _wallet_key()
    evidence = ca.verify_custody_attestation(
        {"quote": "ab" * 2000},
        custody_digest=DIGEST,
        wallet_public_key=key,
        wallet_account="w",
        network="testnet",
        approved_measurements=[{"mr_seam": "cd" * 32}],
        quote_verifier=_echo_verifier(measurement={"mr_seam": "ab" * 32}),
    )
    assert evidence.measurement_approved is False
    assert evidence.state is ca.CustodyEvidenceState.DISPUTED
    assert evidence.tee_attested is False


def test_approved_measurement_is_recorded_and_verifies():
    key, _ = _wallet_key()
    evidence = ca.verify_custody_attestation(
        {"quote": "ab" * 2000},
        custody_digest=DIGEST,
        wallet_public_key=key,
        wallet_account="w",
        network="testnet",
        approved_measurements=[{"mr_seam": "ab" * 32}],
        quote_verifier=_echo_verifier(measurement={"mr_seam": "ab" * 32}),
    )
    assert evidence.measurement_approved is True
    assert evidence.state is ca.CustodyEvidenceState.ATTESTATION_VERIFIED


def test_no_approved_set_means_approval_is_not_claimed():
    key, _ = _wallet_key()
    evidence = ca.verify_custody_attestation(
        {"quote": "ab" * 2000},
        custody_digest=DIGEST,
        wallet_public_key=key,
        wallet_account="w",
        network="testnet",
        quote_verifier=_echo_verifier(),
    )
    assert evidence.measurement_approved is None
    assert "not checked" in evidence.detail


# --- the commitment itself --------------------------------------------------


def test_operation_commitment_is_stable_and_operation_specific():
    key, _ = _wallet_key()
    a = ca.operation_commitment(custody_digest=DIGEST, wallet_public_key=key)
    b = ca.operation_commitment(custody_digest=DIGEST, wallet_public_key=key)
    c = ca.operation_commitment(custody_digest="c" * 64, wallet_public_key=key)
    assert a == b and a != c


def test_expected_report_data_is_64_bytes_and_key_dependent():
    k1, _ = _wallet_key(1)
    k2, _ = _wallet_key(2)
    rd1 = ca.expected_report_data(custody_digest=DIGEST, wallet_public_key=k1)
    rd2 = ca.expected_report_data(custody_digest=DIGEST, wallet_public_key=k2)
    assert rd1 is not None and len(rd1) == 64
    assert rd1 != rd2


# --- evidence combination: a weaker state never implies a stronger one ------


def _attested() -> ca.CustodyAttestationEvidence:
    return ca.CustodyAttestationEvidence(
        state=ca.CustodyEvidenceState.ATTESTATION_VERIFIED,
        detail="",
        quote_present=True,
        quote_verified=True,
        operation_bound=True,
        signing_key_bound=True,
    )


def _unavailable() -> ca.CustodyAttestationEvidence:
    return ca.CustodyAttestationEvidence(
        state=ca.CustodyEvidenceState.PER_OPERATION_TEE_ATTESTATION_UNAVAILABLE, detail=""
    )


def _disputed() -> ca.CustodyAttestationEvidence:
    return ca.CustodyAttestationEvidence(state=ca.CustodyEvidenceState.DISPUTED, detail="")


@pytest.mark.parametrize(
    "provider,bound,settled,att,expected",
    [
        (True, True, True, _attested(), ca.CustodyEvidenceState.TEE_SIGNING_VERIFIED),
        (False, True, True, _attested(), ca.CustodyEvidenceState.TEE_SIGNING_VERIFIED),
        (True, True, False, _attested(), ca.CustodyEvidenceState.ATTESTATION_VERIFIED),
        (True, True, True, _unavailable(), ca.CustodyEvidenceState.SETTLEMENT_VERIFIED),
        (True, True, False, _unavailable(), ca.CustodyEvidenceState.CUSTODY_BOUND),
        (True, False, False, _unavailable(), ca.CustodyEvidenceState.PER_OPERATION_TEE_ATTESTATION_UNAVAILABLE),
        (True, False, False, _disputed(), ca.CustodyEvidenceState.DISPUTED),
        (True, False, False, ca.CustodyAttestationEvidence(state=ca.CustodyEvidenceState.INSUFFICIENT_EVIDENCE, detail=""), ca.CustodyEvidenceState.PROVIDER_CLAIMED),
        (False, False, False, ca.CustodyAttestationEvidence(state=ca.CustodyEvidenceState.INSUFFICIENT_EVIDENCE, detail=""), ca.CustodyEvidenceState.INSUFFICIENT_EVIDENCE),
    ],
)
def test_combine_evidence_ladder(provider, bound, settled, att, expected):
    assert (
        ca.combine_evidence(
            provider_claimed_success=provider,
            custody_bound=bound,
            settlement_verified=settled,
            attestation=att,
        )
        is expected
    )


def test_provider_success_alone_never_yields_tee_signing_verified():
    state = ca.combine_evidence(
        provider_claimed_success=True,
        custody_bound=False,
        settlement_verified=False,
        attestation=_unavailable(),
    )
    assert state is not ca.CustodyEvidenceState.TEE_SIGNING_VERIFIED
    assert state is not ca.CustodyEvidenceState.SETTLEMENT_VERIFIED


def test_settlement_without_attestation_is_not_tee_signing_verified():
    state = ca.combine_evidence(
        provider_claimed_success=True,
        custody_bound=True,
        settlement_verified=True,
        attestation=_unavailable(),
    )
    assert state is ca.CustodyEvidenceState.SETTLEMENT_VERIFIED


def test_attestation_without_settlement_is_not_tee_signing_verified():
    state = ca.combine_evidence(
        provider_claimed_success=True,
        custody_bound=True,
        settlement_verified=False,
        attestation=_attested(),
    )
    assert state is ca.CustodyEvidenceState.ATTESTATION_VERIFIED


def test_decode_quote_accepts_hex_and_base64():
    raw = b"\x04\x00" + b"\x00" * 2000
    assert ca._decode_quote({"quote": raw.hex()}) == raw
    assert ca._decode_quote({"quote": base64.b64encode(raw).decode()}) == raw
    assert ca._decode_quote({"quote": "!!!"}) is None
