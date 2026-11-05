"""Live hardware harness, run only when explicitly opted in.

Drives the **real** NEAR AI Cloud attested gateway (``cloud-api.near.ai``) with a
fresh nonce and asserts the properties the product claims:

* a genuine Intel TDX quote verifies locally, including Intel PCS collateral;
* the approved measurement (``mr_config_id`` derived from the measured
  ``app_compose``) is accepted, and a wrong pin is refused;
* the attestation nonce is bound to the request, and a wrong nonce is refused;
* if a signing endpoint is configured, a key is provisioned and an enclave
  signature over exact bytes verifies; if it is **not** configured, the harness
  reports signing unavailable rather than fabricating a result.

It is opt-in (``TRACESETTLE_ENCLAVE_HARNESS=1``) because it makes outbound
requests, and skipped otherwise, so the default suite stays offline. It performs
no transaction signing and holds no key.
"""

from __future__ import annotations

import os

import pytest

from tracesettle.near.enclave_harness import run_hardware_harness

pytestmark = pytest.mark.skipif(
    os.environ.get("TRACESETTLE_ENCLAVE_HARNESS", "").strip() != "1",
    reason="opt-in live hardware harness; set TRACESETTLE_ENCLAVE_HARNESS=1",
)


def test_live_tdx_quote_verifies_and_signing_is_reported_honestly():
    result = run_hardware_harness()

    assert result.failures == [], result.failures
    # The quote is genuine hardware attestation, verified locally.
    assert result.genuine is True
    assert result.attestation_ok is True
    assert result.collateral_ok is True
    # A wrong measurement pin and a wrong nonce must both be refused.
    assert result.wrong_pin_rejected is True
    assert result.nonce_bound is True
    assert result.wrong_nonce_rejected is True
    # Signing is only claimed when a real endpoint is configured and verified.
    if result.signing_available:
        assert result.signature_verified is True
    else:
        assert result.signature_verified is False
        assert any("no enclave signing endpoint" in n for n in result.notes)
