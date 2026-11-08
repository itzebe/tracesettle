"""Independent verification of an OutLayer on-chain execution attestation.

Mission 25 proved a real Intel TDX enclave signed a real NEAR testnet
transaction, but it recorded the run as *provider-trusted*: the on-chain
``execution_completed`` event carries no quote, so nothing in the product could
show the enclave's attestation. It can. OutLayer publishes the attestation for an
execution at a **free, unauthenticated** endpoint::

    GET https://<api-host>/attestations/by-tx/<near_transaction_hash>

That record carries the TDX quote and the fields the worker hashed into the
quote's ``report_data`` before Intel signed it. This module fetches that record
and verifies it, using the product's own TDX verifier (:mod:`tracesettle.near.tdx`)
rather than re-implementing quote parsing.

What is verified, and against which trust anchor
------------------------------------------------

Each claim is separate, and the verdict is all-of. A failure anywhere refuses.

1. **Quote authenticity** — the quote's ECDSA chain to the *pinned* Intel SGX
   Root CA, the QE report, the attestation-key binding, and the quote signature.
   Trust anchor: Intel's root CA, pinned in :mod:`tracesettle.near.tdx`.
2. **Commitment binding** — the 32 bytes at ``report_data[0:32]`` equal the
   Task Hash recomputed from the record's own fields, using OutLayer's published
   V1 algorithm. This is what stops a genuine quote from one execution being
   re-used to vouch for another.
3. **Worker identity** — the record's ``worker_measurement`` equals the quote's
   ``rt_mr3``. A provider cannot name a worker the quote does not carry.
4. **Worker approval** — ``rt_mr3`` (plus MRTD and RTMR0-2) are an approved build
   according to the on-chain register contract
   (``worker.outlayer.testnet`` / ``worker.outlayer.near``). Trust anchor: the
   register contract, whose approval is itself an on-chain fact.
5. **Artifact identity** — the attested ``wasm_hash`` equals the sha256 the
   caller pinned as the approved build.
6. **Execution binding** — the record's ``transaction_hash`` is the execution
   the caller is asking about.
7. **Payload binding** (optional) — ``input_hash`` / ``output_hash`` equal the
   sha256 of the on-chain input data and the final receipt's ``SuccessValue``,
   recomputed from a NEAR RPC transaction result the caller supplies.

Honesty rules
-------------

* Nothing here trusts a value echoed *outside* the quote for a claim the quote
  can settle. The task hash is recomputed and matched against the signed bytes.
* A missing endpoint, an absent record, or an unreachable register contract is
  ``NOT_VERIFIED`` / ``UNAVAILABLE`` — never a pass.
* The two payload hash rules differ (the coordinator preserves JSON key order
  for the input; the worker sorts keys for the output). That is OutLayer's
  documented behaviour and is reproduced here rather than "corrected", because
  reproducing it is what makes the check meaningful.
"""

from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass, field
from typing import Any, Mapping

from ...model import SourceStatus
from .. import tdx
from ..rpc import NearRpc

#: OutLayer's public HTTP API, per network. Both are unauthenticated for the
#: ``attestations/by-tx`` read; no key and no payment is involved.
ATTESTATION_API_HOSTS: dict[str, str] = {
    "testnet": "https://testnet-api.outlayer.ai",
    "mainnet": "https://api.outlayer.ai",
}

#: The on-chain register contract that approves worker measurements, per network.
REGISTER_CONTRACTS: dict[str, str] = {
    "testnet": "worker.outlayer.testnet",
    "mainnet": "worker.outlayer.near",
}

#: The register contract's approval method.
APPROVAL_METHOD = "is_measurements_approved"

#: The five TDX measurements the register contract approves, in the order the
#: contract's ``ApprovedMeasurements`` struct names them.
_MEASUREMENT_FIELDS = ("mrtd", "rtmr0", "rtmr1", "rtmr2", "rtmr3")

#: How a verdict was reached, so a reader can tell trust from verification.
LEVEL_INDEPENDENTLY_VERIFIED = "INDEPENDENTLY_VERIFIED"
LEVEL_EXTERNAL_TRUST_ROOT = "CRYPTOGRAPHICALLY_VERIFIED_EXTERNAL_TRUST_ROOT"
LEVEL_PROVIDER_TRUSTED = "PROVIDER_TRUSTED"
LEVEL_NOT_VERIFIED = "NOT_VERIFIED"
LEVEL_REFUTED = "REFUTED"


class OutLayerAttestationError(RuntimeError):
    """The attestation could not be fetched or is structurally unusable."""


@dataclass(frozen=True)
class AttestationClaim:
    """One separately-checked thing the attestation is asserted to prove."""

    name: str
    holds: bool
    detail: str = ""

    def to_dict(self) -> dict[str, Any]:
        return {"name": self.name, "holds": self.holds, "detail": self.detail}


@dataclass
class OutLayerAttestationVerdict:
    """The outcome of checking every separate claim."""

    level: str
    verified: bool
    claims: list[AttestationClaim] = field(default_factory=list)
    failures: list[str] = field(default_factory=list)
    task_hash: str = ""
    report_data: str = ""
    quote_verified: bool = False
    worker_measurement: str = ""
    measurement_approved: bool | None = None
    wasm_hash: str = ""
    transaction_hash: str = ""
    input_hash: str = ""
    output_hash: str = ""
    quote_checks: dict[str, Any] = field(default_factory=dict)
    provider_trusted_only: bool = False
    note: str = ""

    def to_dict(self) -> dict[str, Any]:
        return {
            "level": self.level,
            "verified": self.verified,
            "provider_trusted_only": self.provider_trusted_only,
            "quote_verified": self.quote_verified,
            "task_hash": self.task_hash,
            "report_data": self.report_data,
            "worker_measurement": self.worker_measurement,
            "measurement_approved": self.measurement_approved,
            "wasm_hash": self.wasm_hash,
            "transaction_hash": self.transaction_hash,
            "input_hash": self.input_hash,
            "output_hash": self.output_hash,
            "claims": [c.to_dict() for c in self.claims],
            "failures": list(self.failures),
            "quote_checks": dict(self.quote_checks),
            "note": self.note,
        }


# -- the documented Task Hash (OutLayer V1 preimage) -------------------------


def _b(value: Any) -> bytes:
    """One optional field's contribution: its UTF-8 bytes, or nothing at all.

    Absent optional fields contribute no bytes — this is the documented encoding,
    and it is why ``repo=None, commit="x"`` hashes like ``repo="x", commit=None``.
    The weakness is OutLayer's and is reproduced, not papered over.
    """
    if value is None:
        return b""
    return str(value).encode("utf-8")


def task_hash_v1(record: Mapping[str, Any]) -> bytes:
    """The 32-byte commitment OutLayer embeds at ``report_data[0:32]`` (format V1).

    Transcribed from OutLayer's own verifier
    (``out-layer/outlayer-verify``, ``crates/verify-core/src/preimage.rs``):
    ``task_type`` UTF-8, ``task_id`` little-endian i64, then the optional
    ``repo_url``/``commit_hash``/``build_target``/``wasm_hash``/``input_hash``,
    then ``output_hash``, then optional ``block_height`` (u64 LE); V1 adds the
    optional ``caller_account_id``/``project_id``/``secrets_ref``, ``timestamp``
    (i64 LE) and optional ``attached_usd``.
    """
    h = hashlib.sha256()
    h.update(_b(record.get("task_type")))
    h.update(int(record["task_id"]).to_bytes(8, "little", signed=True))
    for key in ("repo_url", "commit_hash", "build_target", "wasm_hash", "input_hash"):
        h.update(_b(record.get(key)))
    h.update(_b(record.get("output_hash")))
    height = record.get("block_height")
    if height is not None:
        h.update(int(height).to_bytes(8, "little"))
    for key in ("caller_account_id", "project_id", "secrets_ref"):
        h.update(_b(record.get(key)))
    h.update(int(record["timestamp"]).to_bytes(8, "little", signed=True))
    h.update(_b(record.get("attached_usd")))
    return h.digest()


def payload_hashes(input_value: Any, output_value: Any) -> tuple[str, str]:
    """``(input_hash, output_hash)`` for a parsed input/output, per OutLayer's rule.

    The input is hashed with the caller's key order preserved; the output with
    keys sorted. Both are compact (no spaces) and leave non-ASCII as UTF-8. A
    caller that already holds the exact recorded strings should use
    :func:`hash_raw` instead — re-serialising could introduce a difference that
    was never there.
    """
    return (
        hashlib.sha256(_compact(input_value, sort_keys=False).encode("utf-8")).hexdigest(),
        hashlib.sha256(_compact(output_value, sort_keys=True).encode("utf-8")).hexdigest(),
    )


def hash_raw(value: str) -> str:
    """sha256 of a string that was already recorded verbatim (the on-chain case)."""
    return hashlib.sha256(value.encode("utf-8")).hexdigest()


def _compact(value: Any, *, sort_keys: bool) -> str:
    if sort_keys:
        value = _sorted(value)
    return json.dumps(value, separators=(",", ":"), ensure_ascii=False)


def _sorted(value: Any) -> Any:
    if isinstance(value, Mapping):
        return {k: _sorted(value[k]) for k in sorted(value)}
    if isinstance(value, list):
        return [_sorted(v) for v in value]
    return value


# -- fetching ----------------------------------------------------------------


def attestation_api_host(network: str) -> str:
    try:
        return ATTESTATION_API_HOSTS[network]
    except KeyError as exc:
        raise OutLayerAttestationError(f"no OutLayer attestation host is known for {network!r}") from exc


def fetch_attestation(
    transaction_hash: str,
    *,
    network: str = "testnet",
    http: Any | None = None,
    host: str | None = None,
) -> dict[str, Any]:
    """Fetch the attestation record for an execution transaction. No key needed.

    A 404 means the worker has not uploaded a quote for that transaction (yet, or
    ever — a failed call has none). That is a *missing* record, not a failed
    verification, so it raises :class:`OutLayerAttestationError` and the caller
    reports ``NOT_VERIFIED`` rather than a pass or a contradiction.
    """
    from ...httpclient import HttpClient

    base = host or attestation_api_host(network)
    url = f"{base}/attestations/by-tx/{transaction_hash}"
    client = http or HttpClient(timeout=20.0, max_attempts=2)
    result = client.get_json(url)
    if result.status is not SourceStatus.OK or not isinstance(result.data, dict):
        raise OutLayerAttestationError(
            f"no attestation is published for {transaction_hash!r} "
            f"({result.status.value}{': ' + result.error if result.error else ''})"
        )
    return result.data


# -- the register contract ---------------------------------------------------


def measurements_from_quote(raw_quote: bytes) -> dict[str, str]:
    """The five approved measurements, read from the quote's own bytes.

    ``mrtd`` is the 48 bytes at ``report_body[136:184]``; ``rtmr0..3`` follow at
    the offsets the product's parser names. The report body starts after the
    48-byte quote header, and the measurements are read from that authenticated
    range — not from anything the provider echoed.
    """
    body = tdx.parse_quote(raw_quote).signed_body[tdx._QUOTE_HEADER_SIZE :]
    return {
        "mrtd": body[136:184].hex(),
        "rtmr0": body[328:376].hex(),
        "rtmr1": body[376:424].hex(),
        "rtmr2": body[424:472].hex(),
        "rtmr3": body[472:520].hex(),
    }


def worker_is_approved(
    measurements: Mapping[str, str],
    *,
    network: str = "testnet",
    rpc: NearRpc | None = None,
    contract: str | None = None,
) -> tuple[bool | None, str]:
    """Ask the on-chain register contract whether these measurements are approved.

    Returns ``(True, detail)`` / ``(False, detail)`` for a definitive answer, and
    ``(None, detail)`` when the contract could not be reached — an unavailable
    check is never reported as a pass.
    """
    contract_id = contract or REGISTER_CONTRACTS.get(network, "")
    if not contract_id:
        return None, f"no register contract is known for {network!r}"
    args = {"measurements": {k: measurements[k] for k in _MEASUREMENT_FIELDS}}
    if rpc is None:
        from ..networks import network_config, parse_network

        rpc = NearRpc(network_config(parse_network(network)))
    result = rpc.call_function(contract_id, APPROVAL_METHOD, args)
    if result.status is not SourceStatus.OK or result.data is None:
        return None, f"the register contract could not be reached ({result.status.value})"
    value = result.data
    if isinstance(value, bool):
        return value, f"{contract_id}.{APPROVAL_METHOD} -> {value}"
    return None, f"the register contract returned an unusable answer: {value!r}"


class RecordedApprovalRpc:
    """Replays a *recorded* register-contract answer instead of calling the chain.

    The approval is an on-chain fact, but a test (and an offline reviewer) must not
    depend on the network. This stand-in answers only the one question the record
    captured, and only for the measurements the record names; anything else is
    ``UNAVAILABLE``. It is a transport stand-in, not a logic stub — the caller's
    verification code runs unchanged.
    """

    def __init__(self, approval: Mapping[str, Any]) -> None:
        self._approved = approval.get("approved")
        self._measurements = {
            str(k): str(v).lower()
            for k, v in (approval.get("measurements") or {}).items()
        }

    def call_function(self, contract_id: str, method: str, args: Mapping[str, Any]):
        from ...model import SourceStatus
        from ..rpc import RpcResult

        if method != APPROVAL_METHOD:
            return RpcResult(SourceStatus.NOT_FOUND, error="not the recorded question")
        asked = {
            str(k): str(v).lower()
            for k, v in (args.get("measurements") or {}).items()
        }
        if self._measurements and asked != self._measurements:
            # A different worker: the recorded answer does not apply.
            return RpcResult(SourceStatus.NOT_FOUND, error="a different measurement")
        return RpcResult(SourceStatus.OK, data=self._approved)


# -- verification ------------------------------------------------------------


def verify_outlayer_attestation(
    record: Mapping[str, Any],
    *,
    expected_transaction_hash: str = "",
    expected_wasm_sha256: str = "",
    network: str = "testnet",
    rpc: NearRpc | None = None,
    check_worker_approval: bool = True,
    tx_result: Mapping[str, Any] | None = None,
    now: int | None = None,
    max_age_seconds: int | None = None,
) -> OutLayerAttestationVerdict:
    """Check every claim about one execution attestation.

    ``record`` is an attestation record as fetched from OutLayer's API. The
    function never raises on a *negative* result — it returns a verdict with the
    failing claim named, so a caller can show what failed. It raises only if the
    record is structurally unusable (no quote, no task id).
    """
    claims: list[AttestationClaim] = []
    failures: list[str] = []

    def add(name: str, holds: bool, detail: str = "") -> bool:
        claims.append(AttestationClaim(name=name, holds=holds, detail=detail))
        if not holds:
            failures.append(name)
        return holds

    if not record.get("tdx_quote"):
        raise OutLayerAttestationError("the attestation record carries no TDX quote")
    if record.get("task_id") is None:
        raise OutLayerAttestationError("the attestation record carries no task id")

    import base64

    try:
        raw_quote = base64.b64decode(record["tdx_quote"])
    except (ValueError, base64.binascii.Error) as exc:
        raise OutLayerAttestationError(f"the TDX quote is not valid base64: {exc}") from exc

    verdict = OutLayerAttestationVerdict(level=LEVEL_NOT_VERIFIED, verified=False)
    verdict.transaction_hash = str(record.get("transaction_hash", ""))
    verdict.wasm_hash = str(record.get("wasm_hash", ""))
    verdict.worker_measurement = str(record.get("worker_measurement", ""))
    verdict.input_hash = str(record.get("input_hash", ""))
    verdict.output_hash = str(record.get("output_hash", ""))

    # 1. Quote authenticity, against the pinned Intel root.
    try:
        quote = tdx.verify_tdx_quote(raw_quote)
        verdict.quote_verified = bool(quote.verified)
        verdict.quote_checks = dict(quote.checks)
        verdict.report_data = getattr(quote, "report_data", "")
    except Exception as exc:  # noqa: BLE001 - an unparseable quote is a refusal
        add("quote_authentic", False, f"the quote could not be parsed: {exc}")
        verdict.claims = claims
        verdict.failures = failures
        verdict.level = LEVEL_REFUTED
        return verdict
    add(
        "quote_authentic",
        verdict.quote_verified,
        "signature chain to the pinned Intel SGX Root CA" if verdict.quote_verified
        else "; ".join(quote.failures) or "the quote did not verify",
    )

    # 2. The signed commitment equals the Task Hash recomputed from the record.
    try:
        computed = task_hash_v1(record)
    except (KeyError, TypeError, ValueError) as exc:
        add("task_hash_bound", False, f"the task hash could not be computed: {exc}")
        computed = b""
    embedded = raw_quote[tdx._QUOTE_HEADER_SIZE + 520 : tdx._QUOTE_HEADER_SIZE + 552]
    verdict.task_hash = computed.hex()
    add(
        "task_hash_bound",
        bool(computed) and computed == embedded,
        f"report_data[0:32] = {embedded.hex()}",
    )

    # 3. The named worker is the one in the quote.
    try:
        measurements = measurements_from_quote(raw_quote)
        quote_rtmr3 = measurements["rtmr3"]
    except Exception as exc:  # noqa: BLE001
        quote_rtmr3 = ""
        add("worker_measurement_matches_quote", False, f"measurements unreadable: {exc}")
    else:
        add(
            "worker_measurement_matches_quote",
            bool(verdict.worker_measurement) and verdict.worker_measurement == quote_rtmr3,
            f"record {verdict.worker_measurement[:24]}… vs quote rt_mr3 {quote_rtmr3[:24]}…",
        )

    # 4. The worker build is approved on-chain.
    if check_worker_approval and quote_rtmr3:
        approved, detail = worker_is_approved(measurements, network=network, rpc=rpc)
        verdict.measurement_approved = approved
        if approved is None:
            add("worker_measurement_approved", False, detail)
        else:
            add("worker_measurement_approved", approved, detail)
    else:
        verdict.measurement_approved = None
        verdict.note = "on-chain worker approval was not checked"

    # 5. The attested artifact is the build the caller approved.
    if expected_wasm_sha256:
        observed = str(record.get("wasm_hash", ""))
        add(
            "approved_build",
            observed.lower() == expected_wasm_sha256.lower(),
            f"attested {observed[:24]}… vs approved {expected_wasm_sha256[:24]}…",
        )
        executed = str(record.get("executed_wasm_sha256", "") or observed)
        add(
            "executed_wasm_matches_named_wasm",
            executed.lower() == observed.lower(),
            "the executed artifact is the one the record names",
        )

    # 6. This is the execution the caller asked about.
    if expected_transaction_hash:
        add(
            "execution_binding",
            verdict.transaction_hash == expected_transaction_hash,
            f"record names {verdict.transaction_hash}",
        )

    # 7. Payload binding, when a chain result is supplied.
    if tx_result is not None:
        _check_payloads(add, record, tx_result)

    # Freshness, when the caller asks for it.
    if max_age_seconds is not None:
        timestamp = record.get("timestamp")
        if now is not None and isinstance(timestamp, (int, float)):
            age = int(now) - int(timestamp)
            add("freshness", 0 <= age <= max_age_seconds, f"attestation age {age}s")
        else:
            add("freshness", False, "no timestamp to check freshness against")

    verdict.claims = claims
    verdict.failures = failures
    verdict.verified = not failures
    if verdict.verified:
        verdict.level = (
            LEVEL_INDEPENDENTLY_VERIFIED
            if verdict.measurement_approved is True
            else LEVEL_EXTERNAL_TRUST_ROOT
        )
    elif not verdict.quote_verified:
        verdict.level = LEVEL_NOT_VERIFIED
    else:
        verdict.level = LEVEL_REFUTED
    return verdict


def _check_payloads(add: Any, record: Mapping[str, Any], tx_result: Mapping[str, Any]) -> None:
    """Compare the record's input/output hashes to the on-chain execution.

    The input is the ``execution_requested`` event's ``input_data`` string, hashed
    verbatim. The output is the final receipt's base64 ``SuccessValue``, decoded
    and hashed. Both are read from the transaction the caller supplies.
    """
    import base64

    input_data = _execution_input(tx_result)
    if input_data is None:
        add("input_hash_bound", False, "the transaction carries no execution_requested input")
    else:
        add(
            "input_hash_bound",
            hash_raw(input_data) == str(record.get("input_hash", "")),
            "sha256(input_data) equals the attested input hash",
        )

    success_values = _success_values(tx_result)
    if not success_values:
        add("output_hash_bound", False, "the transaction carries no SuccessValue output")
    else:
        want = str(record.get("output_hash", ""))
        matched = False
        for success_value in success_values:
            try:
                decoded = base64.b64decode(success_value)
            except (ValueError, base64.binascii.Error):
                continue
            if hashlib.sha256(decoded).hexdigest() == want:
                matched = True
                break
        add(
            "output_hash_bound",
            matched,
            "a receipt SuccessValue hashes to the attested output hash",
        )


def _execution_input(tx_result: Mapping[str, Any]) -> str | None:
    for receipt in tx_result.get("receipts_outcome", []) or []:
        for line in (receipt.get("outcome") or {}).get("logs", []) or []:
            if not isinstance(line, str) or not line.startswith("EVENT_JSON:"):
                continue
            try:
                event = json.loads(line[len("EVENT_JSON:") :])
            except ValueError:
                continue
            if event.get("event") != "execution_requested":
                continue
            data = event.get("data") or []
            if not data:
                continue
            try:
                request = json.loads(data[0].get("request_data", "{}"))
            except (ValueError, AttributeError):
                continue
            value = request.get("input_data")
            if isinstance(value, str):
                return value
    return None


def _success_values(tx_result: Mapping[str, Any]) -> list[str]:
    """Every base64 ``SuccessValue`` a receipt carries, in order.

    An OutLayer execution produces several receipts; the guest's own output is the
    one the worker hashed. The verifier matches against *any* of them, so it does
    not have to guess which receipt the worker chose, and an output hash that
    matches none is refused.
    """
    values: list[str] = []
    for receipt in tx_result.get("receipts_outcome", []) or []:
        status = (receipt.get("outcome") or {}).get("status")
        if isinstance(status, dict) and isinstance(status.get("SuccessValue"), str):
            values.append(status["SuccessValue"])
    return values


__all__ = [
    "ATTESTATION_API_HOSTS",
    "AttestationClaim",
    "OutLayerAttestationError",
    "OutLayerAttestationVerdict",
    "LEVEL_EXTERNAL_TRUST_ROOT",
    "LEVEL_INDEPENDENTLY_VERIFIED",
    "LEVEL_NOT_VERIFIED",
    "LEVEL_PROVIDER_TRUSTED",
    "LEVEL_REFUTED",
    "REGISTER_CONTRACTS",
    "attestation_api_host",
    "fetch_attestation",
    "hash_raw",
    "measurements_from_quote",
    "payload_hashes",
    "task_hash_v1",
    "verify_outlayer_attestation",
    "worker_is_approved",
]
