"""End-to-end proof that a genuine Intel TDX enclave produced a signed NEAR transaction.

Mission 25 proved a real TDX enclave signed a real testnet transaction, and
Mission 26 proved the enclave's execution is attested (``outlayer_attestation``).
Neither, on its own, ties the two together: the attestation proves *an approved
enclave ran an approved build for this task*, and the signing output proves *a
signature verifies over the transaction digest*. This module closes that gap with
one chain of commitments that a reviewer can check offline, from public data only:

    Intel-signed quote
        -> report_data[0:32] = Task Hash V1 (over the record's own fields)
            -> output_hash = sha256(the enclave's stdout, verbatim)
                -> that stdout, parsed, IS the signing output (every field equal)
                    -> output.signed_transaction bytes
                        -> recomputed digest sha256(borsh(unsigned)) == output.transaction_digest
                            -> b58(digest) == output.tx_hash
                                -> ed25519(output.signature, digest, output.public_key) verifies

Each link is a separate, named check; the verdict is all-of. A break anywhere is a
refusal. The decisive link is the third one: the enclave's ``output_hash`` — which
Intel signed into the quote — equals the sha256 of the exact bytes whose parse
carries the signed transaction. A host that swapped the signed transaction after
the enclave produced it would change the stdout bytes, so ``output_hash`` would no
longer match and the check fails.

Honesty rules (unchanged from the rest of the product)
------------------------------------------------------

* Nothing here trusts a value echoed outside the quote for a claim the quote can
  settle. The output hash is matched against bytes *re-hashed here*.
* A valid signature alone is **not** reported as TEE-verified. The verdict only
  reaches ``TEE_SIGNING_VERIFIED`` when the attestation verifies too; otherwise it
  is at most ``SIGNATURE_VERIFIED`` and the failing link is named.
* A missing attestation is ``NOT_VERIFIED``; a bad one is ``REFUTED``.
* The signature is verified with the rule the algorithm names; an algorithm the
  product cannot verify is refused, never checked with the wrong scheme.
"""

from __future__ import annotations

import base64
import hashlib
import json
from dataclasses import dataclass, field
from typing import Any, Mapping

from ...base58 import b58decode, b58encode
from .. import ed25519
from ..txbuild import SIGNATURE_TRAILER_LEN, NearTransaction
from .outlayer_attestation import (
    LEVEL_REFUTED,
    OutLayerAttestationError,
    verify_outlayer_attestation,
)

#: The evidence ladder, weakest to strongest. The product never promotes a
#: verdict above the evidence that actually holds.
LEVEL_SIGNATURE_VERIFIED = "SIGNATURE_VERIFIED"
LEVEL_TEE_SIGNING_VERIFIED = "TEE_SIGNING_VERIFIED"
LEVEL_NOT_VERIFIED = "NOT_VERIFIED"


@dataclass(frozen=True)
class ProvenanceCheck:
    """One separately-checked link in the chain of commitments."""

    name: str
    holds: bool
    detail: str = ""

    def to_dict(self) -> dict[str, Any]:
        return {"name": self.name, "holds": self.holds, "detail": self.detail}


@dataclass
class AttestedSigningVerdict:
    """The outcome of checking every link from the quote to the signature."""

    level: str
    verified: bool
    checks: list[ProvenanceCheck] = field(default_factory=list)
    failures: list[str] = field(default_factory=list)
    tx_hash: str = ""
    transaction_digest: str = ""
    public_key: str = ""
    enclave_output_hash: str = ""
    recomputed_output_hash: str = ""
    attestation_level: str = ""
    attestation_verified: bool = False
    note: str = ""

    def to_dict(self) -> dict[str, Any]:
        return {
            "level": self.level,
            "verified": self.verified,
            "tee_signing_verified": self.level == LEVEL_TEE_SIGNING_VERIFIED,
            "tx_hash": self.tx_hash,
            "transaction_digest": self.transaction_digest,
            "public_key": self.public_key,
            "enclave_output_hash": self.enclave_output_hash,
            "recomputed_output_hash": self.recomputed_output_hash,
            "attestation_level": self.attestation_level,
            "attestation_verified": self.attestation_verified,
            "checks": [c.to_dict() for c in self.checks],
            "failures": list(self.failures),
            "note": self.note,
        }


def _success_values(tx_result: Mapping[str, Any]) -> list[bytes]:
    """Every decoded base64 ``SuccessValue`` a receipt carries, in order."""
    out: list[bytes] = []
    for receipt in tx_result.get("receipts_outcome", []) or []:
        status = (receipt.get("outcome") or {}).get("status")
        if isinstance(status, dict) and isinstance(status.get("SuccessValue"), str):
            try:
                out.append(base64.b64decode(status["SuccessValue"]))
            except (ValueError, base64.binascii.Error):
                continue
    return out


def verify_attested_signing(
    run_record: Mapping[str, Any],
    attestation_record: Mapping[str, Any],
    *,
    network: str = "testnet",
    tx_result: Mapping[str, Any] | None = None,
    rpc: Any | None = None,
    expected_wasm_sha256: str = "",
    now: int | None = None,
    max_age_seconds: int | None = None,
) -> AttestedSigningVerdict:
    """Prove that an attested Intel TDX enclave produced this signed transaction.

    ``run_record`` is a Mission 25-shaped run capture: it carries
    ``sign_transaction.output`` (the enclave's answer) and ``wasm_sha256``.
    ``attestation_record`` is the raw OutLayer attestation record (the value under
    the fixture's ``attestation`` key), and ``tx_result`` is the on-chain
    ``request_execution`` transaction result the attestation's payload hashes
    commit to.

    Never raises on a *negative* result: it returns a verdict naming the failing
    link. It raises only if the inputs are structurally unusable.
    """
    checks: list[ProvenanceCheck] = []
    failures: list[str] = []

    def add(name: str, holds: bool, detail: str = "") -> bool:
        checks.append(ProvenanceCheck(name=name, holds=holds, detail=detail))
        if not holds:
            failures.append(name)
        return holds

    verdict = AttestedSigningVerdict(level=LEVEL_NOT_VERIFIED, verified=False)

    output = (run_record.get("sign_transaction") or {}).get("output")
    if not isinstance(output, Mapping):
        raise OutLayerAttestationError("the run record carries no sign_transaction.output")
    if str(output.get("status", "")) != "ok":
        raise OutLayerAttestationError("the run record's signing output is not a success")

    verdict.public_key = str(output.get("public_key", ""))
    verdict.tx_hash = str(output.get("tx_hash", ""))
    verdict.transaction_digest = str(output.get("transaction_digest", ""))

    # 1. Recompute the NEAR digest from the exact signed bytes.
    signed_b64 = str(output.get("signed_transaction", ""))
    try:
        signed = base64.b64decode(signed_b64, validate=True)
    except (ValueError, base64.binascii.Error) as exc:
        add("signed_bytes_parse", False, f"the signed transaction is not valid base64: {exc}")
        verdict.checks = checks
        verdict.failures = failures
        return verdict
    if len(signed) <= SIGNATURE_TRAILER_LEN:
        add("signed_bytes_parse", False, "the signed transaction is too short to carry a signature")
        verdict.checks = checks
        verdict.failures = failures
        return verdict
    add("signed_bytes_parse", True, f"{len(signed)} signed bytes")

    unsigned = NearTransaction.unsigned_from_signed(signed)
    signature = NearTransaction.signature_from_signed(signed)
    digest = hashlib.sha256(unsigned).digest()
    recomputed = "sha256:" + digest.hex()
    add(
        "digest_matches_signed_bytes",
        recomputed == verdict.transaction_digest,
        f"recomputed {recomputed} vs recorded {verdict.transaction_digest}",
    )
    add(
        "tx_hash_is_b58_of_digest",
        b58encode(digest) == verdict.tx_hash,
        f"b58(digest) = {b58encode(digest)}",
    )

    # 2. The signature verifies over the recomputed digest under the named key.
    raw_key = b58decode(verdict.public_key.split(":")[-1])
    signature_ok = (
        raw_key is not None
        and len(raw_key) == 32
        and ed25519.verify(signature, digest, raw_key)
    )
    add(
        "signature_verifies_over_digest",
        signature_ok,
        "ed25519 signature verified over the recomputed digest"
        if signature_ok
        else "the signature does not verify over the recomputed digest",
    )

    # 3. The enclave's attested output IS this signing output.
    enclave_output_hash = str(attestation_record.get("output_hash", ""))
    verdict.enclave_output_hash = enclave_output_hash
    if tx_result is None:
        add(
            "enclave_output_is_the_signed_transaction",
            False,
            "no on-chain execution result was supplied to bind the enclave output",
        )
    else:
        matched_hash = False
        matched_json = False
        for raw in _success_values(tx_result):
            if hashlib.sha256(raw).hexdigest() != enclave_output_hash:
                continue
            matched_hash = True
            verdict.recomputed_output_hash = enclave_output_hash
            try:
                parsed = json.loads(raw.decode("utf-8"))
            except (ValueError, UnicodeDecodeError):
                continue
            if isinstance(parsed, Mapping) and _outputs_equal(parsed, output):
                matched_json = True
                break
        add(
            "enclave_output_hash_binds_the_receipt",
            matched_hash,
            f"a receipt SuccessValue hashes to the attested output hash {enclave_output_hash[:24]}…"
            if matched_hash
            else "no receipt SuccessValue hashes to the attested output hash",
        )
        add(
            "attested_output_is_this_signing_output",
            matched_json,
            "the attested output, parsed, equals the signing output field-for-field"
            if matched_json
            else "the attested output does not equal the signing output",
        )

    # 4. The attestation itself: quote, task hash, worker, build, payloads.
    attestation_verdict = verify_outlayer_attestation(
        attestation_record,
        expected_transaction_hash=str(attestation_record.get("transaction_hash", "")),
        expected_wasm_sha256=expected_wasm_sha256 or str(run_record.get("wasm_sha256", "")),
        network=network,
        rpc=rpc,
        tx_result=tx_result,
        now=now,
        max_age_seconds=max_age_seconds,
    )
    verdict.attestation_level = attestation_verdict.level
    verdict.attestation_verified = attestation_verdict.verified
    add(
        "attestation_verified",
        attestation_verdict.verified,
        f"{attestation_verdict.level}"
        + (f"; failed {attestation_verdict.failures}" if attestation_verdict.failures else ""),
    )

    verdict.checks = checks
    verdict.failures = failures
    verdict.verified = not failures
    if verdict.verified:
        verdict.level = LEVEL_TEE_SIGNING_VERIFIED
    elif signature_ok and not any(
        c.name in ("digest_matches_signed_bytes", "tx_hash_is_b58_of_digest", "signature_verifies_over_digest")
        and not c.holds
        for c in checks
    ):
        # The signature is genuine for the exact transaction, but the enclave
        # provenance did not hold. Report exactly that, never more.
        verdict.level = LEVEL_SIGNATURE_VERIFIED
    elif not attestation_verdict.quote_verified:
        verdict.level = LEVEL_NOT_VERIFIED
    else:
        verdict.level = LEVEL_REFUTED
    return verdict


def _outputs_equal(a: Mapping[str, Any], b: Mapping[str, Any]) -> bool:
    """Compare two signing outputs, field for field.

    Every key the recorded output carries must be present in the attested output
    with an equal value; a differing value for a shared key fails. Keys the
    attested output carries beyond the record are tolerated (the record is the
    narrower of the two), but nothing the record asserts is allowed to differ.
    """
    for key, value in b.items():
        if key not in a:
            return False
        if a[key] != value:
            return False
    return True


__all__ = [
    "AttestedSigningVerdict",
    "ProvenanceCheck",
    "LEVEL_SIGNATURE_VERIFIED",
    "LEVEL_TEE_SIGNING_VERIFIED",
    "LEVEL_NOT_VERIFIED",
    "verify_attested_signing",
]
