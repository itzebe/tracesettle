"""The real TEE attestation provider and its API route.

The provider fetches a genuine Intel TDX quote from the NEAR AI Cloud gateway and
verifies it locally. These tests substitute only the network transport
(``FakeOpener``) with the captured real quote, so the verifier, the binding logic
and the route are the real code paths.
"""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from conftest import FakeOpener
from tracesettle.httpclient import HttpClient
from tracesettle.near.attestation import (
    TeeAttestationProvider,
    derive_nonce,
    verified_tee_verifier,
)
from tracesettle.near.tee import AttestationStatus, assess_verifiable_execution

FIXTURE = (
    Path(__file__).resolve().parent.parent
    / "tracesettle"
    / "near"
    / "fixtures"
    / "attestation_nearai_cloud.json"
)
ENDPOINT = "cloud-api.near.ai"


@pytest.fixture()
def attestation() -> dict:
    return json.loads(FIXTURE.read_text(encoding="utf-8"))


def _gateway_payload(attestation: dict, nonce_hex: str) -> dict:
    """Rebuild the gateway response shape from the fixture for a specific nonce.

    The captured quote already binds the fixture's nonce; tests that exercise a
    fresh nonce use the fixture nonce so the quote genuinely verifies.
    """
    return {
        "gateway_attestation": {
            "intel_quote": attestation["intel_quote"],
            "request_nonce": nonce_hex,
            "report_data": attestation["report_data"],
            "signing_address": attestation["signing_address"],
            "tls_cert_fingerprint": attestation["tls_cert_fingerprint"],
            "info": {"tcb_info": {"event_log": attestation["event_log"]}},
        }
    }


def _provider_with(opener: FakeOpener) -> TeeAttestationProvider:
    return TeeAttestationProvider(client=HttpClient(opener=opener))


def test_derive_nonce_is_deterministic_with_a_fixed_salt():
    salt = b"\x01" * 32
    a = derive_nonce(transaction_fingerprint="sha256:x", policy_revision="1", salt=salt)
    b = derive_nonce(transaction_fingerprint="sha256:x", policy_revision="1", salt=salt)
    assert a == b and len(a) == 32


def test_derive_nonce_changes_with_the_transaction():
    salt = b"\x02" * 32
    a = derive_nonce(transaction_fingerprint="sha256:x", salt=salt)
    b = derive_nonce(transaction_fingerprint="sha256:y", salt=salt)
    assert a != b


def test_provider_verifies_a_genuine_quote(attestation):
    nonce = bytes.fromhex(attestation["request_nonce"])
    opener = FakeOpener().json("GET", ENDPOINT, _gateway_payload(attestation, nonce.hex()))
    result = _provider_with(opener).attest(nonce)
    assert result.status is AttestationStatus.VERIFIED
    assert result.verified
    assert result.verification["checks"]["root_matches_pinned_intel_root"] is True


def test_provider_rejects_a_wrong_nonce(attestation):
    fixture_nonce = bytes.fromhex(attestation["request_nonce"])
    other = bytes(a ^ 0xFF for a in fixture_nonce)
    # The gateway echoes the request nonce, but the quote still binds the old one.
    opener = FakeOpener().json("GET", ENDPOINT, _gateway_payload(attestation, other.hex()))
    result = _provider_with(opener).attest(other)
    assert result.status is AttestationStatus.UNVERIFIABLE
    assert not result.verified


def test_provider_reports_unverifiable_on_http_error(attestation):
    nonce = bytes.fromhex(attestation["request_nonce"])
    opener = FakeOpener().http_error("GET", ENDPOINT, 503)
    result = _provider_with(opener).attest(nonce)
    assert result.status is AttestationStatus.UNVERIFIABLE
    assert result.fetched is False


def test_provider_reports_unverifiable_when_quote_missing(attestation):
    nonce = bytes.fromhex(attestation["request_nonce"])
    opener = FakeOpener().json("GET", ENDPOINT, {"gateway_attestation": {}})
    result = _provider_with(opener).attest(nonce)
    assert result.status is AttestationStatus.UNVERIFIABLE
    assert result.fetched is True


def test_echoed_fields_must_match_the_verified_quote(attestation):
    nonce = bytes.fromhex(attestation["request_nonce"])
    payload = _gateway_payload(attestation, nonce.hex())
    payload["gateway_attestation"]["report_data"] = "ab" * 64  # tampered echo
    opener = FakeOpener().json("GET", ENDPOINT, payload)
    result = _provider_with(opener).attest(nonce)
    assert result.status is AttestationStatus.UNVERIFIABLE


def test_verified_tee_verifier_adapts_to_the_assessment(attestation):
    nonce = bytes.fromhex(attestation["request_nonce"])
    opener = FakeOpener().json("GET", ENDPOINT, _gateway_payload(attestation, nonce.hex()))
    provider = _provider_with(opener)
    assessment = assess_verifiable_execution(
        "near-ai-cloud", attestation={"nonce": nonce.hex()}, verifier=verified_tee_verifier(provider, nonce)
    )
    assert assessment.claims_protection
    assert assessment.status is AttestationStatus.VERIFIED


def test_a_failed_verification_never_claims_protection(attestation):
    nonce = bytes.fromhex(attestation["request_nonce"])
    opener = FakeOpener().http_error("GET", ENDPOINT, 500)
    provider = _provider_with(opener)
    assessment = assess_verifiable_execution(
        "near-ai-cloud", attestation={"nonce": nonce.hex()}, verifier=verified_tee_verifier(provider, nonce)
    )
    assert not assessment.claims_protection
    assert assessment.status is AttestationStatus.UNVERIFIABLE
