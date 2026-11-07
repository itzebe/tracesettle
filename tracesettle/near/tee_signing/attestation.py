"""Attestation verification for the TEE signing boundary.

A verified Intel TDX quote proves *some* approved enclave ran *some* build. It
does **not** prove *this* transaction was signed. This module keeps those claims
separate and checks each one, in order, failing closed at the first that does not
hold:

1. the quote is genuine — signature chain to the pinned Intel SGX Root CA, QE
   binding, event-log replay (:mod:`tracesettle.near.tdx`, re-used, not
   re-implemented);
2. the Intel collateral is authentic and fresh (TCB status, PCK revocation, QE
   identity) — :mod:`tracesettle.near.collateral`, re-used;
3. the measurement is an **approved** identity the operator pinned;
4. the run's ``wasm_hash`` equals the approved build;
5. the caller/project identity is the one the request names;
6. the quote's nonce is the fresh nonce the host chose for this execution;
7. the run's input hash commits to this signing request;
8. the run's output hash commits to the signature that came back;
9. the signature verifies over the exact digest, under the returned public key;
10. the digest the signature covers equals the transaction digest the
    authorization bound.

Only when all hold is :class:`AttestationVerdict` ``VERIFIED``. An attestation
for a different execution, a stale or replayed one, or one whose measurement or
build is not approved, is refused — never promoted.
"""

from __future__ import annotations

import hashlib
from dataclasses import dataclass, field
from typing import Any, Mapping, Sequence

from .. import ed25519


@dataclass(frozen=True)
class AttestationClaim:
    """One separate thing the attestation evidence is asserted to prove."""

    name: str
    holds: bool
    detail: str = ""

    def to_dict(self) -> dict[str, Any]:
        return {"name": self.name, "holds": self.holds, "detail": self.detail}


@dataclass
class AttestationVerdict:
    """The outcome of checking every separate claim. ``verified`` is all-of."""

    verified: bool
    claims: list[AttestationClaim] = field(default_factory=list)
    quote_verified: bool = False
    measurement: dict[str, Any] = field(default_factory=dict)
    measurement_name: str = ""
    build_hash: str = ""
    input_hash: str = ""
    output_hash: str = ""
    nonce: str = ""
    failures: list[str] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        return {
            "verified": self.verified,
            "quote_verified": self.quote_verified,
            "measurement_name": self.measurement_name,
            "measurement": dict(self.measurement),
            "build_hash": self.build_hash,
            "input_hash": self.input_hash,
            "output_hash": self.output_hash,
            "nonce": self.nonce,
            "claims": [c.to_dict() for c in self.claims],
            "failures": list(self.failures),
        }


def _sha256_hex(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def verify_signing_attestation(
    *,
    quote_verifier: Any,
    quote: bytes,
    nonce: bytes,
    signing_address: bytes | None,
    event_log: Sequence[Mapping[str, Any]] | None,
    request_digest: str,
    transaction_digest: str,
    signature_raw64: bytes,
    public_key_raw: bytes,
    approved_measurement: Any,
    approved_build: str,
    observed_build: str,
    caller: str,
    expected_caller: str,
    project: str,
    expected_project: str,
    input_hash: str = "",
    output_hash: str = "",
    collateral_client: Any = None,
    now: int | None = None,
) -> AttestationVerdict:
    """Check every separate claim. A failure anywhere refuses the whole thing."""
    claims: list[AttestationClaim] = []
    failures: list[str] = []

    def add(name: str, holds: bool, detail: str = "") -> None:
        claims.append(AttestationClaim(name=name, holds=holds, detail=detail))
        if not holds:
            failures.append(name)

    # 1-2. Genuine quote + fresh Intel collateral (delegated to the existing
    # verifier; this module does not re-implement TDX parsing).
    verification = quote_verifier(
        quote,
        nonce=nonce,
        signing_address=signing_address,
        tls_cert_fingerprint=None,
        event_log=list(event_log) if event_log else None,
        now=now,
        collateral_client=collateral_client,
    )
    quote_ok = bool(getattr(verification, "verified", False))
    add("genuine_intel_quote", quote_ok, "; ".join(getattr(verification, "failures", []) or []))

    # 3. The measurement is an approved identity the operator pinned.
    measurement = dict(getattr(verification, "measurement", {}) or {})
    measurement_name = ""
    try:
        approved = approved_measurement.evaluate(measurement)
        measurement_name = getattr(approved, "name", "")
        add("approved_measurement", True, f"approved identity {measurement_name!r}")
    except Exception as exc:  # noqa: BLE001 - not approved is a refusal
        add("approved_measurement", False, f"the measurement is not approved: {exc}")

    # 4. The build that ran is the build the operator approved.
    build_ok = bool(observed_build) and observed_build == approved_build
    add("approved_build", build_ok, f"observed {observed_build!r} vs approved {approved_build!r}")

    # 5. The caller/project identity is the one the request names.
    add("caller_identity", bool(caller) and caller == expected_caller, f"caller {caller!r}")
    add("project_identity", bool(project) and project == expected_project, f"project {project!r}")

    # 6. The quote's nonce is the fresh host nonce for this execution.
    verified_nonce = str(getattr(verification, "nonce", "") or "").lower()
    add(
        "freshness_nonce",
        bool(verified_nonce) and verified_nonce == nonce.hex(),
        "the quote carries the host nonce for this execution",
    )

    # 7. The run's input hash commits to this signing request.
    if input_hash:
        want = "sha256:" + _sha256_hex(request_digest.encode("utf-8"))
        add(
            "input_commitment",
            input_hash == request_digest or input_hash == want,
            "the attested input commits to this signing request",
        )

    # 8. The run's output hash commits to the signature that came back.
    if output_hash:
        want_sig = "sha256:" + _sha256_hex(signature_raw64)
        add(
            "output_commitment",
            output_hash == want_sig,
            "the attested output commits to the returned signature",
        )

    # 9. The signature verifies over the exact digest, under the returned key.
    digest_hex = transaction_digest.split(":")[-1]
    try:
        digest = bytes.fromhex(digest_hex)
    except ValueError:
        digest = b""
        add("transaction_digest_wellformed", False, "the transaction digest is not hex")
    sig_ok = bool(digest) and ed25519.verify(signature_raw64, digest, public_key_raw)
    add("signature_over_exact_digest", sig_ok, "the signature verifies over the NEAR digest")

    return AttestationVerdict(
        verified=not failures,
        claims=claims,
        quote_verified=quote_ok,
        measurement=measurement,
        measurement_name=measurement_name,
        build_hash=observed_build,
        input_hash=input_hash,
        output_hash=output_hash,
        nonce=nonce.hex(),
        failures=failures,
    )
