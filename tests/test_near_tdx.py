"""Genuine Intel TDX attestation verification.

These tests exercise the real verifier against a real captured quote (the
fixture is hardware attestation captured live from the public NEAR AI Cloud
gateway). No network call is made: the quote, nonce, signing address, TLS
fingerprint and event log all come from the shipped fixture.

The point of these tests is that the verification is *genuine*: the checks are
real ECDSA-P256 verifications to a pinned Intel root, so a tampered quote, a
wrong nonce, a substituted signing key or a mangled event log all fail.
"""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from tracesettle.near import tdx

FIXTURE = (
    Path(__file__).resolve().parent.parent
    / "tracesettle"
    / "near"
    / "fixtures"
    / "attestation_nearai_cloud.json"
)


@pytest.fixture()
def attestation() -> dict:
    return json.loads(FIXTURE.read_text(encoding="utf-8"))


def _verify(attestation: dict, **overrides):
    raw = overrides.pop("quote", attestation["intel_quote"])
    quote = raw if isinstance(raw, bytes) else bytes.fromhex(raw)
    return tdx.verify_tdx_quote(
        quote,
        nonce=overrides.pop("nonce", bytes.fromhex(attestation["request_nonce"])),
        signing_address=overrides.pop(
            "signing_address", bytes.fromhex(attestation["signing_address"])
        ),
        tls_cert_fingerprint=overrides.pop(
            "tls_cert_fingerprint", bytes.fromhex(attestation["tls_cert_fingerprint"])
        ),
        event_log=overrides.pop("event_log", attestation["event_log"]),
        **overrides,
    )


def test_real_quote_verifies(attestation):
    result = _verify(attestation)
    assert result.verified, result.failures
    assert all(result.checks.values()), result.checks


def test_root_matches_the_pinned_intel_root(attestation):
    result = _verify(attestation)
    assert result.intel_root_fingerprint == tdx.INTEL_SGX_ROOT_CA_SHA256
    assert result.intel_root_fingerprint == tdx.intel_root_fingerprint()


def test_tampered_quote_is_refused(attestation):
    quote = bytearray(bytes.fromhex(attestation["intel_quote"]))
    quote[48 + 520] ^= 0x01  # report_data lives at body offset 520
    result = _verify(attestation, quote=bytes(quote))
    assert not result.verified
    assert any("signature" in f for f in result.failures)


def test_wrong_nonce_is_refused(attestation):
    result = _verify(attestation, nonce=b"\x00" * 32)
    assert not result.verified
    assert "report_data does not bind the supplied nonce" in result.failures


def test_wrong_signing_address_is_refused(attestation):
    result = _verify(attestation, signing_address=b"\x11" * 32)
    assert not result.verified
    assert any("signing address" in f for f in result.failures)


def test_wrong_tls_fingerprint_is_refused(attestation):
    result = _verify(attestation, tls_cert_fingerprint=b"\x22" * 32)
    assert not result.verified


def test_mangled_event_log_is_refused(attestation):
    log = [dict(e) for e in attestation["event_log"]]
    log[0]["digest"] = "00" * 48
    result = _verify(attestation, event_log=log)
    assert not result.verified
    assert "event_log_replays_to_rtmrs" in result.checks
    assert result.checks["event_log_replays_to_rtmrs"] is False


def test_pinned_root_fingerprint_is_stable():
    assert tdx.INTEL_SGX_ROOT_CA_SHA256 == tdx.intel_root_fingerprint()
    assert len(tdx.intel_root_der()) > 500


def test_expired_validity_window_is_refused(attestation):
    # The captured PCK leaf is valid 2026-10-31 .. 2033-10-31; a timestamp past
    # that window is outside it and must be refused.
    result = _verify(attestation, now=2_100_000_000)
    assert not result.verified
    assert result.checks["pck_leaf_within_validity"] is False


def test_non_tdx_quote_is_rejected():
    with pytest.raises(tdx.TdxQuoteError):
        tdx.parse_quote(b"\x04\x00" + b"\x00" * 400)


def test_replay_event_log_is_deterministic(attestation):
    first = tdx.replay_event_log(attestation["event_log"])
    second = tdx.replay_event_log(attestation["event_log"])
    assert first == second
    assert set(first) == {0, 1, 2, 3}
    assert all(len(v) == 48 for v in first.values())
