"""Reproducible hardware test harness for the enclave signing boundary.

The harness drives the **real** attested gateway (``cloud-api.near.ai``) with a
fresh, client-generated nonce and exercises the genuine parts of
:mod:`tracesettle.near.enclave` end to end:

1. Fetch a real Intel TDX quote with a fresh nonce.
2. Verify it locally, including Intel PCS collateral (TCB freshness, PCK
   revocation, QE identity).
3. Derive the approved measurement from the quote's ``app_compose`` (the
   documented ``mr_config_id = 01 || sha256(app_compose) || 15 zero bytes``) and
   confirm :class:`MeasurementPolicy` accepts it — and rejects a wrong pin.
4. Confirm the attestation nonce is bound to the request and refuses another.
5. If a signing endpoint is configured (``TRACESETTLE_ENCLAVE_SIGN_URL``),
   provision a key and verify an enclave signature over exact bytes; if the
   endpoint is **not** configured, report that signing is unavailable rather than
   fabricating a result.

It performs no signing of a real transaction and holds no key. It is opt-in
(``TRACESETTLE_ENCLAVE_HARNESS=1``) because it makes an outbound request.
"""

from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass, field
from typing import Any

from ..httpclient import HttpClient
from .enclave import (
    ApprovedMeasurement,
    EnclaveError,
    EnclaveSigningBoundary,
    HttpEnclaveTransport,
    MeasurementMismatch,
    MeasurementPolicy,
    ProvisioningRequest,
)
from .collateral import PcsCollateralClient

#: The documented attested gateway. Not invented: it is the endpoint the
#: product already verifies against (``DEFAULT_ATTESTATION_URL``'s host).
DEFAULT_HARNESS_BASE_URL = "https://cloud-api.near.ai"


def measurement_from_app_compose(app_compose: str) -> str:
    """Compute ``mr_config_id`` from the measured configuration, per the docs.

    ``01`` then ``sha256(app_compose)`` then 15 zero bytes (48 bytes total).
    """
    digest = hashlib.sha256(app_compose.encode("utf-8")).hexdigest()
    return "01" + digest + "00" * 15


def _hex(value: Any) -> bytes | None:
    if not isinstance(value, str) or not value:
        return None
    try:
        return bytes.fromhex(value.removeprefix("0x"))
    except ValueError:
        return None


@dataclass
class HarnessResult:
    """What the hardware harness actually observed."""

    attestation_ok: bool = False
    collateral_ok: bool = False
    measurement: str = ""
    approved_measurement_name: str = ""
    wrong_pin_rejected: bool = False
    nonce_bound: bool = False
    wrong_nonce_rejected: bool = False
    signing_available: bool = False
    signature_verified: bool = False
    checks: dict[str, bool] = field(default_factory=dict)
    failures: list[str] = field(default_factory=list)
    notes: list[str] = field(default_factory=list)

    @property
    def genuine(self) -> bool:
        """True only when real hardware evidence verified and was bound."""
        return (
            self.attestation_ok
            and self.collateral_ok
            and bool(self.measurement)
            and bool(self.approved_measurement_name)
            and self.wrong_pin_rejected
            and self.nonce_bound
            and self.wrong_nonce_rejected
        )

    def to_dict(self) -> dict[str, Any]:
        return {
            "genuine": self.genuine,
            "attestation_ok": self.attestation_ok,
            "collateral_ok": self.collateral_ok,
            "measurement": self.measurement,
            "approved_measurement_name": self.approved_measurement_name,
            "wrong_pin_rejected": self.wrong_pin_rejected,
            "nonce_bound": self.nonce_bound,
            "wrong_nonce_rejected": self.wrong_nonce_rejected,
            "signing_available": self.signing_available,
            "signature_verified": self.signature_verified,
            "checks": dict(self.checks),
            "failures": list(self.failures),
            "notes": list(self.notes),
        }


def run_hardware_harness(
    *,
    base_url: str = DEFAULT_HARNESS_BASE_URL,
    sign_url: str | None = None,
    client: Any = None,
    now: int | None = None,
) -> HarnessResult:
    """Run the harness against the real attested gateway and return the evidence."""
    result = HarnessResult()
    http = client or HttpClient(timeout=30, max_attempts=2)
    collateral = PcsCollateralClient()
    transport = HttpEnclaveTransport(
        base_url=base_url, sign_url=sign_url, client=http
    )

    # First, read the report once to learn the measured configuration, so we can
    # pin it. This is a real read; nothing is hardcoded.
    probe_nonce = hashlib.sha256(b"harness-probe").hexdigest()
    try:
        report = transport.attestation_report(probe_nonce)
    except EnclaveError as exc:
        result.failures.append(f"attestation fetch failed: {exc}")
        return result
    gateway = report.get("gateway_attestation", report)
    info = gateway.get("info") if isinstance(gateway, dict) else None
    app_compose = ""
    if isinstance(info, dict):
        tcb = info.get("tcb_info")
        if isinstance(tcb, dict) and isinstance(tcb.get("app_compose"), str):
            app_compose = tcb["app_compose"]
    if not app_compose:
        result.failures.append("the report carried no measured app_compose")
        return result
    result.measurement = measurement_from_app_compose(app_compose)

    approved = ApprovedMeasurement(
        "near-ai-cloud-gateway", {"mr_config_id": result.measurement}
    )
    boundary = EnclaveSigningBoundary(
        transport=transport,
        measurements=MeasurementPolicy([approved], require_pin=True),
        verifier=None,
        collateral_client=collateral,
        now=now,
    )

    request = ProvisioningRequest(
        key_id="harness-key",
        purpose="enclave-signing-harness",
        execution_id="harness-execution",
        transaction_digest=hashlib.sha256(b"harness-tx").hexdigest(),
        decision_nonce=hashlib.sha256(b"harness-decision").hexdigest(),
        policy_version="harness-v1",
    )
    try:
        key = boundary.provision(request)
    except EnclaveError as exc:
        result.failures.append(f"provisioning failed: {exc}")
        return result

    result.approved_measurement_name = key.measurement_name
    verification = key.verification or {}
    result.checks = dict(verification.get("checks", {}))
    result.attestation_ok = bool(verification.get("verified"))
    result.collateral_ok = bool(result.checks.get("collateral_verified"))
    result.nonce_bound = str(verification.get("nonce", "")).lower() == key.nonce.lower()

    # A wrong pin must be rejected: pin the measurement to a different value.
    wrong = ApprovedMeasurement("wrong", {"mr_config_id": "00" * 48})
    strict = EnclaveSigningBoundary(
        transport=transport,
        measurements=MeasurementPolicy([wrong], require_pin=True),
        collateral_client=collateral,
        now=now,
    )
    try:
        strict.provision(request)
        result.failures.append("a wrong measurement pin was accepted")
    except MeasurementMismatch:
        result.wrong_pin_rejected = True

    # A nonce from a different request must not verify: fetch the quote for this
    # request's nonce, then verify it against another request's nonce. The local
    # verification binds the nonce, so the wrong nonce must fail.
    other = ProvisioningRequest(
        key_id="harness-key",
        purpose="enclave-signing-harness",
        execution_id="other-execution",
        transaction_digest=hashlib.sha256(b"other-tx").hexdigest(),
        decision_nonce=hashlib.sha256(b"other-decision").hexdigest(),
        policy_version="harness-v1",
    )
    try:
        from .enclave import derive_provisioning_nonce

        nonce_a = derive_provisioning_nonce(request, salt=b"fixed-salt")
        report_a = transport.attestation_report(nonce_a.hex())
        gw_a = report_a.get("gateway_attestation", report_a)
        quote_a = bytes.fromhex(gw_a["intel_quote"])
        from . import tdx

        good = tdx.verify_tdx_quote(
            quote_a,
            nonce=nonce_a,
            signing_address=_hex(gw_a.get("signing_address")),
            tls_cert_fingerprint=_hex(gw_a.get("tls_cert_fingerprint")),
            event_log=(gw_a.get("info", {}).get("tcb_info", {}) or {}).get("event_log"),
            collateral_client=collateral,
            now=now,
        )
        bad = tdx.verify_tdx_quote(
            quote_a,
            nonce=derive_provisioning_nonce(other, salt=b"other-salt"),
            signing_address=_hex(gw_a.get("signing_address")),
            tls_cert_fingerprint=_hex(gw_a.get("tls_cert_fingerprint")),
            event_log=(gw_a.get("info", {}).get("tcb_info", {}) or {}).get("event_log"),
            collateral_client=collateral,
            now=now,
        )
        result.nonce_bound = bool(good.verified and good.checks.get("nonce_bound"))
        result.wrong_nonce_rejected = not bad.verified
    except EnclaveError as exc:
        result.failures.append(f"nonce binding check failed: {exc}")

    result.signing_available = boundary.available()
    if result.signing_available:
        message = b"harness-message-to-sign"
        try:
            signature = boundary.sign(key, request, message)
            result.signature_verified = signature.verified
        except EnclaveError as exc:
            result.failures.append(f"enclave signing failed: {exc}")
    else:
        result.notes.append(
            "no enclave signing endpoint is configured (TRACESETTLE_ENCLAVE_SIGN_URL); "
            "hardware-required signing stays disabled"
        )
    return result


def main() -> int:  # pragma: no cover - manual entry point
    result = run_hardware_harness()
    print(json.dumps(result.to_dict(), indent=2, sort_keys=True))
    return 0 if result.genuine else 1


if __name__ == "__main__":  # pragma: no cover
    raise SystemExit(main())
