"""Independent verification of the OutLayer execution attestation.

The fixture is a **real** attestation: an Intel TDX quote the OutLayer worker
produced for the Mission 25 on-chain signing run, together with that run's FINAL
transaction result. Nothing here is fabricated, and no network call is made — the
real capture is replayed offline, so the checks are the real code paths.

The point of these tests is that every claim can *fail*: a tampered quote, a
re-used commitment, a substituted worker, a wrong build, a mismatched execution,
or a payload that does not hash to the recorded value must each be refused.
"""

from __future__ import annotations

import base64
import copy
import json
from pathlib import Path

import pytest

from tracesettle.near.tee_signing.outlayer_attestation import (
    LEVEL_INDEPENDENTLY_VERIFIED,
    LEVEL_NOT_VERIFIED,
    LEVEL_REFUTED,
    OutLayerAttestationError,
    fetch_attestation,
    hash_raw,
    measurements_from_quote,
    payload_hashes,
    task_hash_v1,
    verify_outlayer_attestation,
)
from tracesettle.near.tee_signing.outlayer_attestation import worker_is_approved

FIXTURE = Path(__file__).resolve().parents[1] / "tracesettle/near/fixtures/onchain_tee_attestation.json"


@pytest.fixture()
def captured() -> dict:
    return json.loads(FIXTURE.read_text(encoding="utf-8"))


def _recorded_rpc(captured: dict):
    from tracesettle.near.tee_signing.outlayer_attestation import RecordedApprovalRpc

    return RecordedApprovalRpc(captured["worker_approval"])


def _verify(captured: dict, **overrides):
    kwargs = dict(
        expected_transaction_hash=captured["execution_tx_hash"],
        expected_wasm_sha256=captured["approved_wasm_sha256"],
        network="testnet",
        tx_result=captured["tx_result"],
        rpc=_recorded_rpc(captured),
    )
    kwargs.update(overrides)
    return verify_outlayer_attestation(captured["attestation"], **kwargs)


def test_the_real_attestation_verifies_every_claim(captured):
    verdict = _verify(captured)
    assert verdict.verified, verdict.failures
    assert verdict.level == LEVEL_INDEPENDENTLY_VERIFIED
    assert verdict.quote_verified
    assert verdict.measurement_approved is True
    assert not verdict.provider_trusted_only
    assert verdict.failures == []
    # Every claim the module names is present and holds.
    names = {c.name for c in verdict.claims}
    assert {
        "quote_authentic",
        "task_hash_bound",
        "worker_measurement_matches_quote",
        "worker_measurement_approved",
        "approved_build",
        "execution_binding",
        "input_hash_bound",
        "output_hash_bound",
    } <= names
    assert all(c.holds for c in verdict.claims)


def test_the_task_hash_is_the_commitment_inside_the_signed_quote(captured):
    record = captured["attestation"]
    raw = base64.b64decode(record["tdx_quote"])
    # The TD report body starts after the 48-byte quote header; report_data is the
    # last 64 bytes of the 584-byte body.
    embedded = raw[48 + 520 : 48 + 552]
    assert task_hash_v1(record) == embedded


def test_a_tampered_quote_is_refused(captured):
    record = copy.deepcopy(captured["attestation"])
    raw = bytearray(base64.b64decode(record["tdx_quote"]))
    raw[48 + 520] ^= 0xFF  # flip a bit inside report_data
    record["tdx_quote"] = base64.b64encode(bytes(raw)).decode()
    verdict = verify_outlayer_attestation(record, network="testnet", rpc=_recorded_rpc(captured))
    assert not verdict.verified
    assert verdict.level in {LEVEL_REFUTED, LEVEL_NOT_VERIFIED}
    assert not verdict.quote_verified


def test_a_quote_reused_for_another_execution_is_refused(captured):
    # A genuine quote, but the record's own fields are changed so the recomputed
    # Task Hash no longer matches the signed commitment.
    record = copy.deepcopy(captured["attestation"])
    record["input_hash"] = "00" * 32
    verdict = verify_outlayer_attestation(record, network="testnet", rpc=_recorded_rpc(captured))
    assert not verdict.verified
    assert "task_hash_bound" in verdict.failures


def test_a_worker_the_quote_does_not_carry_is_refused(captured):
    record = copy.deepcopy(captured["attestation"])
    record["worker_measurement"] = "ab" * 48
    verdict = verify_outlayer_attestation(
        record, network="testnet", rpc=_recorded_rpc(captured)
    )
    assert not verdict.verified
    assert "worker_measurement_matches_quote" in verdict.failures


def test_a_worker_the_register_does_not_approve_is_refused(captured):
    # The recorded answer is for one worker; a quote carrying a different worker
    # must not be approved by it.
    approval = dict(captured["worker_approval"])
    approval["measurements"] = {**approval["measurements"], "rtmr3": "00" * 48}
    from tracesettle.near.tee_signing.outlayer_attestation import RecordedApprovalRpc

    verdict = verify_outlayer_attestation(
        captured["attestation"], network="testnet", rpc=RecordedApprovalRpc(approval)
    )
    assert not verdict.verified
    assert "worker_measurement_approved" in verdict.failures


def test_a_recorded_disapproval_is_reported_as_a_failure(captured):
    approval = dict(captured["worker_approval"])
    approval["approved"] = False
    from tracesettle.near.tee_signing.outlayer_attestation import RecordedApprovalRpc

    verdict = verify_outlayer_attestation(
        captured["attestation"], network="testnet", rpc=RecordedApprovalRpc(approval)
    )
    assert not verdict.verified
    assert verdict.measurement_approved is False
    assert "worker_measurement_approved" in verdict.failures


def test_a_different_approved_build_is_refused(captured):
    verdict = _verify(captured, expected_wasm_sha256="11" * 32)
    assert not verdict.verified
    assert "approved_build" in verdict.failures


def test_an_execution_binding_mismatch_is_refused(captured):
    verdict = _verify(captured, expected_transaction_hash="SomeOtherTransactionHash")
    assert not verdict.verified
    assert "execution_binding" in verdict.failures


def test_a_payload_that_does_not_hash_to_the_recorded_value_is_refused(captured):
    tx = copy.deepcopy(captured["tx_result"])
    # Change the final SuccessValue so it no longer hashes to the attested output.
    for receipt in tx["receipts_outcome"]:
        status = (receipt.get("outcome") or {}).get("status")
        if isinstance(status, dict) and "SuccessValue" in status:
            status["SuccessValue"] = base64.b64encode(b"tampered").decode()
    verdict = verify_outlayer_attestation(
        captured["attestation"],
        network="testnet",
        tx_result=tx,
        rpc=_recorded_rpc(captured),
    )
    assert not verdict.verified
    assert "output_hash_bound" in verdict.failures


def test_a_missing_quote_is_a_structural_error(captured):
    record = copy.deepcopy(captured["attestation"])
    record.pop("tdx_quote")
    with pytest.raises(OutLayerAttestationError):
        verify_outlayer_attestation(record, network="testnet")


def test_an_unreachable_register_contract_is_not_a_pass(captured):
    # With the register read unavailable, the claim must be a failure, never a pass.
    verdict = verify_outlayer_attestation(
        captured["attestation"],
        network="testnet",
        rpc=_UnreachableRpc(),
    )
    assert not verdict.verified
    assert "worker_measurement_approved" in verdict.failures
    assert verdict.measurement_approved is None


def test_worker_approval_reads_the_five_measurements_from_the_quote(captured):
    raw = base64.b64decode(captured["attestation"]["tdx_quote"])
    measurements = measurements_from_quote(raw)
    assert set(measurements) == {"mrtd", "rtmr0", "rtmr1", "rtmr2", "rtmr3"}
    assert measurements["rtmr3"] == captured["attestation"]["worker_measurement"]
    for value in measurements.values():
        assert len(value) == 96  # 48 bytes hex


def test_worker_is_approved_reports_unavailable_without_a_contract():
    approved, detail = worker_is_approved({"mrtd": "00"}, network="unknownnet")
    assert approved is None
    assert "register contract" in detail


def test_the_payload_hash_rules_match_outlayers_documented_encoding():
    # Input preserves key order; output sorts keys. The same object hashed both
    # ways differs, which is exactly why the two rules are kept separate.
    value = {"b": 1, "a": 2}
    input_hash, output_hash = payload_hashes(value, value)
    assert input_hash == hash_raw('{"b":1,"a":2}')
    assert output_hash == hash_raw('{"a":2,"b":1}')
    assert input_hash != output_hash


def test_fetch_attestation_reports_a_missing_record_without_raising_a_pass():
    # No network in CI: a stand-in HTTP client that answers NOT_FOUND.
    class _NotFound:
        def get_json(self, url):
            from tracesettle.model import SourceStatus

            class R:
                status = SourceStatus.NOT_FOUND
                data = None
                error = "not found"

            return R()

    with pytest.raises(OutLayerAttestationError):
        fetch_attestation("nonexistent", network="testnet", http=_NotFound())


def test_fetch_attestation_builds_its_http_client_with_max_attempts(monkeypatch):
    """Regression: the live fetch path must construct its HTTP client correctly.

    The default client is built with ``max_attempts``; the code once passed
    ``attempts``, so ``fetch_attestation`` raised ``TypeError`` *before any
    request* — the live path (``--tx-hash``) crashed instead of fetching. This
    spies on the constructor and requires the exact keyword, so the defect cannot
    return, without making a network call.
    """
    import tracesettle.httpclient as httpclient_mod

    calls: list[dict] = []

    class _SpyClient:
        def __init__(self, **kwargs):
            calls.append(kwargs)

        def get_json(self, url):
            from tracesettle.model import SourceStatus

            class R:
                status = SourceStatus.NOT_FOUND
                data = None
                error = "not found"

            return R()

    monkeypatch.setattr(httpclient_mod, "HttpClient", _SpyClient)
    with pytest.raises(OutLayerAttestationError):
        fetch_attestation("no-such-tx", network="testnet")

    assert calls, "fetch_attestation must build its own HTTP client when none is supplied"
    assert calls[0].get("max_attempts") == 2
    assert "attempts" not in calls[0], "the constructor keyword is max_attempts, not attempts"


class _UnreachableRpc:
    """A NearRpc stand-in that cannot reach the register contract."""

    def call_function(self, *args, **kwargs):
        from tracesettle.model import SourceStatus
        from tracesettle.near.rpc import RpcResult

        return RpcResult(SourceStatus.TIMEOUT, error="unreachable")
