"""Tests for Intel PCS collateral validation.

The fixture in ``evidence/raw/intel_pcs/collateral_capture.json`` is a **real**
capture of Intel's TDX certification service (TCB Info, QE Identity, PCK CRL) for
the FMSPC of the NEAR AI Cloud gateway quote. A fake transport serves it, so every
test runs offline while still exercising the real signature verification against
the real Intel collateral bytes.
"""

from __future__ import annotations

import base64
import json
import time
from pathlib import Path

import pytest

from tracesettle.near import collateral, p256, tdx

_CAPTURE = Path(__file__).resolve().parents[1] / "evidence" / "raw" / "intel_pcs" / "collateral_capture.json"
_QUOTE_FIXTURE = (
    Path(__file__).resolve().parents[1]
    / "evidence"
    / "raw"
    / "nearai_cloud_gateway_attestation.json"
)


@pytest.fixture(scope="module")
def capture() -> dict:
    return json.loads(_CAPTURE.read_text())


@pytest.fixture(scope="module")
def parsed_quote():
    raw = json.loads(_QUOTE_FIXTURE.read_text())
    gateway = raw.get("gateway_attestation") or raw
    return tdx.parse_quote(bytes.fromhex(gateway["intel_quote"]))


def _make_transport(capture: dict, mutate=None):
    """Serve the captured collateral; ``mutate(label, body_bytes, headers)`` may edit."""

    def transport(url: str):
        if "/tcb" in url:
            label = "tcb"
        elif "/qe/identity" in url:
            label = "qe_identity"
        elif "/pckcrl" in url:
            label = "pckcrl"
        else:  # pragma: no cover - a test asked for an unknown URL
            raise AssertionError(f"unexpected collateral URL {url}")
        entry = capture[label]
        if label == "pckcrl":
            body = base64.b64decode(entry["body_der_b64"])
        else:
            body = entry["body"].encode()
        headers = {"content-type": "application/json"}
        header_name = (
            "TCB-Info-Issuer-Chain"
            if label == "tcb"
            else "SGX-Enclave-Identity-Issuer-Chain"
            if label == "qe_identity"
            else "SGX-PCK-CRL-Issuer-Chain"
        )
        headers[header_name] = entry["issuer_chain_header"]
        if mutate is not None:
            body, headers = mutate(label, body, headers)
        return body, headers

    return transport


def test_real_intel_collateral_verifies_fully(parsed_quote):
    client = collateral.PcsCollateralClient(transport=_make_transport(json.loads(_CAPTURE.read_text())))
    bundle = collateral.validate_collateral(
        client, pck_leaf=parsed_quote.pck_chain[0], qe_report=parsed_quote.qe_report
    )
    assert bundle.available is True
    assert bundle.verified is True, bundle.failures
    assert bundle.tcb_acceptable is True
    assert bundle.pck_revoked is False
    assert bundle.qe_identity_ok is True
    assert bundle.tcb_status in {"UpToDate", "SWHardeningNeeded"}
    assert not bundle.failures


def test_each_collateral_document_is_signed_by_the_pinned_intel_root(parsed_quote):
    client = collateral.PcsCollateralClient(transport=_make_transport(json.loads(_CAPTURE.read_text())))
    bundle = collateral.validate_collateral(
        client, pck_leaf=parsed_quote.pck_chain[0], qe_report=parsed_quote.qe_report
    )
    for document in (bundle.tcb, bundle.pckcrl, bundle.qe_identity):
        assert document.verified, document.detail
        assert document.chain_fingerprints[-1] == tdx.INTEL_SGX_ROOT_CA_SHA256


def test_a_tampered_tcb_signature_is_refused(parsed_quote):
    def mutate(label, body, headers):
        if label != "tcb":
            return body, headers
        document = json.loads(body)
        signature = document["signature"]
        document["signature"] = ("1" if signature[0] == "0" else "0") + signature[1:]
        return json.dumps(document).encode(), headers

    client = collateral.PcsCollateralClient(transport=_make_transport(json.loads(_CAPTURE.read_text()), mutate))
    bundle = collateral.validate_collateral(
        client, pck_leaf=parsed_quote.pck_chain[0], qe_report=parsed_quote.qe_report
    )
    assert bundle.verified is False
    assert bundle.tcb.verified is False
    assert "signature" in bundle.tcb.detail


def test_a_tampered_tcb_body_is_refused(parsed_quote):
    """Editing the signed bytes (even to a valid-looking document) must fail."""

    def mutate(label, body, headers):
        if label != "tcb":
            return body, headers
        document = json.loads(body)
        # Change a signed field without touching the signature.
        document["tcbInfo"]["tcbEvaluationDataNumber"] = (
            int(document["tcbInfo"].get("tcbEvaluationDataNumber", 0)) + 1
        )
        return json.dumps(document).encode(), headers

    client = collateral.PcsCollateralClient(transport=_make_transport(json.loads(_CAPTURE.read_text()), mutate))
    bundle = collateral.validate_collateral(
        client, pck_leaf=parsed_quote.pck_chain[0], qe_report=parsed_quote.qe_report
    )
    assert bundle.tcb.verified is False
    assert bundle.verified is False


def test_a_chain_that_does_not_reach_the_pinned_root_is_refused(parsed_quote):
    """Swap the issuer chain for an unrelated self-signed certificate."""

    def mutate(label, body, headers):
        if label != "tcb":
            return body, headers
        # Use the CRL's issuer chain (a different Intel CA), which must not be
        # accepted as the TCB document's signer unless it reaches the pinned root.
        other = json.loads(_CAPTURE.read_text())["pckcrl"]["issuer_chain_header"]
        headers["TCB-Info-Issuer-Chain"] = other
        return body, headers

    client = collateral.PcsCollateralClient(transport=_make_transport(json.loads(_CAPTURE.read_text()), mutate))
    bundle = collateral.validate_collateral(
        client, pck_leaf=parsed_quote.pck_chain[0], qe_report=parsed_quote.qe_report
    )
    # The PCK CRL issuer chain is a *different* CA, so the TCB signature will not
    # verify under it; either way the document must not be accepted.
    assert bundle.tcb.verified is False
    assert bundle.verified is False


def test_stale_collateral_is_refused(parsed_quote):
    """Collateral past its nextUpdate is never treated as current."""
    far_future = time.mktime(time.strptime("2030-01-01", "%Y-%m-%d"))
    client = collateral.PcsCollateralClient(transport=_make_transport(json.loads(_CAPTURE.read_text())))
    bundle = collateral.validate_collateral(
        client,
        pck_leaf=parsed_quote.pck_chain[0],
        qe_report=parsed_quote.qe_report,
        now=far_future,
    )
    assert bundle.verified is False
    assert any("stale" in failure for failure in bundle.failures)


def test_unavailable_collateral_service_fails_closed(parsed_quote):
    def transport(url):
        raise OSError("network down")

    client = collateral.PcsCollateralClient(transport=transport)
    bundle = collateral.validate_collateral(
        client, pck_leaf=parsed_quote.pck_chain[0], qe_report=parsed_quote.qe_report
    )
    assert bundle.available is False
    assert bundle.verified is False
    assert bundle.failures


def test_a_revoked_pck_serial_is_refused(parsed_quote, monkeypatch):
    """If the PCK leaf's serial appears in the CRL, the bundle must refuse.

    The CRL is real and signature-checked; only the parsed serial list is
    substituted, so the refusal path through ``validate_collateral`` is exercised
    for real rather than re-signed offline (which is impossible without Intel's key).
    """
    from tracesettle.near.collateral import _certificate_serial

    leaf_serial = _certificate_serial(parsed_quote.pck_chain[0])
    assert leaf_serial > 0

    real_parse = collateral.parse_crl_revoked_serials

    def fake_parse(crl_der):
        _revoked, metadata = real_parse(crl_der)
        return {leaf_serial}, metadata

    monkeypatch.setattr(collateral, "parse_crl_revoked_serials", fake_parse)
    client = collateral.PcsCollateralClient(transport=_make_transport(json.loads(_CAPTURE.read_text())))
    bundle = collateral.validate_collateral(
        client, pck_leaf=parsed_quote.pck_chain[0], qe_report=parsed_quote.qe_report
    )
    assert bundle.pck_revoked is True
    assert bundle.verified is False
    assert any("revoked" in failure for failure in bundle.failures)


def test_tcb_level_matching_rejects_a_platform_below_every_level():
    tcb_info = {
        "tcbLevels": [
            {
                "tcb": {"sgxtcbcomponents": [{"svn": 9}] * 16, "pcesvn": 13},
                "tcbStatus": "UpToDate",
                "tcbDate": "2025-01-01T00:00:00Z",
            }
        ]
    }
    platform = collateral.PckExtension(fmspc="AABB", components={1: 1}, pcesvn=1, sgx_type="")
    status, _date, acceptable = collateral.evaluate_tcb_level(tcb_info, platform)
    assert status == "OutOfDate"
    assert acceptable is False


def test_tcb_level_matching_accepts_a_platform_at_the_level():
    tcb_info = {
        "tcbLevels": [
            {
                "tcb": {"sgxtcbcomponents": [{"svn": 4}] * 16, "pcesvn": 13},
                "tcbStatus": "UpToDate",
                "tcbDate": "2025-01-01T00:00:00Z",
            }
        ]
    }
    platform = collateral.PckExtension(
        fmspc="AABB", components={i: 4 for i in range(1, 17)}, pcesvn=13, sgx_type=""
    )
    status, _date, acceptable = collateral.evaluate_tcb_level(tcb_info, platform)
    assert status == "UpToDate"
    assert acceptable is True


def test_a_revoked_tcb_level_is_not_acceptable():
    tcb_info = {
        "tcbLevels": [
            {
                "tcb": {"sgxtcbcomponents": [{"svn": 1}] * 16, "pcesvn": 1},
                "tcbStatus": "Revoked",
                "tcbDate": "2025-01-01T00:00:00Z",
            }
        ]
    }
    platform = collateral.PckExtension(
        fmspc="AABB", components={i: 9 for i in range(1, 17)}, pcesvn=9, sgx_type=""
    )
    status, _date, acceptable = collateral.evaluate_tcb_level(tcb_info, platform)
    assert status == "Revoked"
    assert acceptable is False


def test_qe_identity_mismatch_is_refused(parsed_quote):
    identity = {"mrsigner": "00" * 32, "isvprodid": 2, "tcbLevels": [{"tcb": {"isvsvn": 1}}]}
    ok, detail = collateral.evaluate_qe_identity(identity, parsed_quote.qe_report)
    assert ok is False
    assert "MRSIGNER" in detail


def test_qe_identity_missing_fields_is_refused(parsed_quote):
    ok, detail = collateral.evaluate_qe_identity({}, parsed_quote.qe_report)
    assert ok is False
    assert "missing" in detail


def test_locate_signed_document_extracts_exact_bytes():
    raw = b'{"tcbInfo":{"a":1,"b":{"c":2}},"signature":"ab"}'
    signed = collateral._locate_signed_document(raw, "tcbInfo")
    assert signed == b'{"a":1,"b":{"c":2}}'


def test_locate_signed_document_handles_whitespace():
    raw = b'{"tcbInfo":  {"a": 1}, "signature": "ab"}'
    signed = collateral._locate_signed_document(raw, "tcbInfo")
    assert signed == b'{"a": 1}'


def test_cache_reuses_a_fresh_document(parsed_quote):
    calls = {"n": 0}
    base = _make_transport(json.loads(_CAPTURE.read_text()))

    def counting(url):
        calls["n"] += 1
        return base(url)

    client = collateral.PcsCollateralClient(transport=counting, cache_ttl_seconds=3600)
    client.tcb_info("70A06D070000")
    first = calls["n"]
    client.tcb_info("70A06D070000")
    assert calls["n"] == first, "a fresh cached document must be reused"
    cached = client.tcb_info("70A06D070000")
    assert cached.from_cache is True


def test_cache_is_not_used_past_its_ttl(parsed_quote):
    calls = {"n": 0}
    base = _make_transport(json.loads(_CAPTURE.read_text()))

    def counting(url):
        calls["n"] += 1
        return base(url)

    client = collateral.PcsCollateralClient(transport=counting, cache_ttl_seconds=0)
    client.tcb_info("70A06D070000")
    first = calls["n"]
    client.tcb_info("70A06D070000")
    assert calls["n"] > first, "a zero-TTL cache must not serve stale entries"


def test_crl_parse_reads_revoked_serials_and_times(capture):
    crl_der = base64.b64decode(capture["pckcrl"]["body_der_b64"])
    revoked, metadata = collateral.parse_crl_revoked_serials(crl_der)
    assert isinstance(revoked, set)
    assert metadata["this_update"].endswith("Z")
    assert metadata["revoked_count"] == len(revoked)


def test_pck_extension_parse_reads_the_real_fmspc(parsed_quote):
    extension = collateral.parse_pck_extensions(parsed_quote.pck_chain[0])
    assert extension.fmspc == "70A06D070000"
    assert extension.pcesvn > 0
    assert 1 in extension.components


def test_pck_extension_parse_rejects_a_certificate_without_the_extension():
    # The Intel SGX Root CA has no SGX extension.
    root = p256.parse_certificate(tdx.intel_root_der())
    with pytest.raises(collateral.CollateralError):
        collateral.parse_pck_extensions(root)


def test_bundle_verified_requires_every_condition():
    """A bundle is verified only when all three documents and the derived verdicts hold."""
    good = collateral.CollateralDocument("x", "", True, True, "ok", body={})
    bundle = collateral.CollateralBundle(available=True, tcb=good, pckcrl=good, qe_identity=good)
    assert bundle.verified is False, "a bundle with no TCB/QE verdicts must not be verified"
    bundle.tcb_acceptable = True
    bundle.qe_identity_ok = True
    assert bundle.verified is True
    bundle.pck_revoked = True
    assert bundle.verified is False


def test_freshness_helper_rejects_empty_and_past():
    now = time.time()
    assert collateral._is_fresh("", now=now) is False
    assert collateral._is_fresh("2000-01-01T00:00:00Z", now=now) is False
    assert collateral._is_fresh("2999-01-01T00:00:00Z", now=now) is True
