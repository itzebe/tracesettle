"""Genuine Intel TDX attestation verification, standard-library only.

This module verifies a real TDX quote the way a relying party must: it does not trust any field
echoed in an HTTP response, it re-derives every fact from the hardware-signed quote and checks the
signature chain up to the pinned Intel SGX Root CA.

What it verifies (all locally, no paid service):

1. The quote is a well-formed TDX (v4) quote with a TD report body and a signature section.
2. The PCK certificate chain embedded in the quote is valid: leaf -> intermediate -> Intel SGX Root
   CA, with the root's SHA-256 fingerprint equal to the pinned Intel root, and every link signed
   with ECDSA-P256-SHA256.
3. The Quoting Enclave (QE) report inside the certification data is signed by the PCK leaf key, and
   its ``report_data[0:32]`` equals ``SHA256(attestation_key || qe_auth_data)``, which binds the
   quote's signing key to a genuine Quoting Enclave.
4. The quote signature over the quote body verifies under the attestation key from the quote.
5. The quote's ``report_data`` binds a caller-supplied nonce and, optionally, a signing address and
   a TLS certificate fingerprint, so a replayed or unrelated quote is rejected.
6. When an event log is supplied, replaying it reproduces RTMR0..3, so the measured runtime is the
   one that produced the quote.

Deliberately **not** verified here (and therefore never claimed): the PCK certificate revocation
status and the TCB level against Intel's PCS collateral. Those require fetching Intel collateral
(a network service). ``tracesettle.near.tee`` records that limitation; nothing in this project
claims TCB-freshness or revocation checking that was not performed.

The signature check is a real ECDSA-P256 verification (:mod:`tracesettle.near.p256`), and the
root of trust is a hard-pinned Intel certificate, so a fabricated quote cannot pass.
"""

from __future__ import annotations

import base64
import hashlib
import struct
from dataclasses import dataclass, field
from typing import Any, Sequence

from . import p256

#: The Intel SGX Root CA (self-signed, valid to 2049-12-31). Pinned by SHA-256 fingerprint.
INTEL_SGX_ROOT_CA_DER_B64 = (
    "MIICjzCCAjSgAwIBAgIUImUM1lqdNInzg7SVUr9QGzknBqwwCgYIKoZIzj0EAwIwaDEaMBgGA1UE"
    "AwwRSW50ZWwgU0dYIFJvb3QgQ0ExGjAYBgNVBAoMEUludGVsIENvcnBvcmF0aW9uMRQwEgYDVQQH"
    "DAtTYW50YSBDbGFyYTELMAkGA1UECAwCQ0ExCzAJBgNVBAYTAlVTMB4XDTE4MDUyMTEwNDUxMFoX"
    "DTQ5MTIzMTIzNTk1OVowaDEaMBgGA1UEAwwRSW50ZWwgU0dYIFJvb3QgQ0ExGjAYBgNVBAoMEUlu"
    "dGVsIENvcnBvcmF0aW9uMRQwEgYDVQQHDAtTYW50YSBDbGFyYTELMAkGA1UECAwCQ0ExCzAJBgNV"
    "BAYTAlVTMFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEC6nEwMDIYZOj/iPWsCzaEKi71OiOSLRF"
    "hWGjbnBVJfVnkY4u3IjkDYYL0MxO4mqsyYjlBalTVYxFP2sJBK5zlKOBuzCBuDAfBgNVHSMEGDAW"
    "gBQiZQzWWp00ifODtJVSv1AbOScGrDBSBgNVHR8ESzBJMEegRaBDhkFodHRwczovL2NlcnRpZmlj"
    "YXRlcy50cnVzdGVkc2VydmljZXMuaW50ZWwuY29tL0ludGVsU0dYUm9vdENBLmRlcjAdBgNVHQ4E"
    "FgQUImUM1lqdNInzg7SVUr9QGzknBqwwDgYDVR0PAQH/BAQDAgEGMBIGA1UdEwEB/wQIMAYBAf8C"
    "AQEwCgYIKoZIzj0EAwIDSQAwRgIhAOW/5QkR+S9CiSDcNoowLuPRLsWGf/Yi7GSX94BgwTwgAiEA"
    "4J0lrHoMs+Xo5o/sX6O9QWxHRAvZUGOdRQ7cvqRXaqI="
)

#: SHA-256 fingerprint of the pinned Intel SGX Root CA.
INTEL_SGX_ROOT_CA_SHA256 = "44a0196b2b99f889b8e149e95b807a350e7424964399e885a7cbb8ccfab674d3"

#: Intel's QE vendor ID (the first 16 bytes of a TDX quote header).
INTEL_QE_VENDOR_ID = bytes.fromhex("939a7233f79c4ca9940a0db3957f0607")

#: TDX v4 quote header size.
_QUOTE_HEADER_SIZE = 48
#: Candidate TD report body sizes. The Intel TD report is 584 bytes; some quotes carry four extra
#: trailing bytes, so both are accepted and the one that yields a well-formed signature section
#: (a valid on-curve attestation key and parseable certification data) is used.
_TD_REPORT_SIZES = (584, 588)
#: The fixed TD report body size used when nothing needs to be re-derived.
_TD_REPORT_SIZE = 584


class TdxQuoteError(ValueError):
    """A quote could not be parsed as a TDX quote."""


def intel_root_der() -> bytes:
    return base64.b64decode(INTEL_SGX_ROOT_CA_DER_B64)


def intel_root_fingerprint() -> str:
    return hashlib.sha256(intel_root_der()).hexdigest()


@dataclass(frozen=True)
class TdReport:
    """The measurement fields of a TD report body."""

    tee_tcb_svn: bytes
    mr_seam: bytes
    mr_signer_seam: bytes
    mr_config_id: bytes
    mr_owner: bytes
    mr_owner_config: bytes
    rt_mr0: bytes
    rt_mr1: bytes
    rt_mr2: bytes
    rt_mr3: bytes
    report_data: bytes
    td_attributes: bytes
    xfam: bytes

    def rtmrs(self) -> tuple[bytes, bytes, bytes, bytes]:
        return (self.rt_mr0, self.rt_mr1, self.rt_mr2, self.rt_mr3)

    def to_dict(self) -> dict[str, Any]:
        return {
            "tee_tcb_svn": self.tee_tcb_svn.hex(),
            "mr_seam": self.mr_seam.hex(),
            "mr_signer_seam": self.mr_signer_seam.hex(),
            "mr_config_id": self.mr_config_id.hex(),
            "mr_owner": self.mr_owner.hex(),
            "mr_owner_config": self.mr_owner_config.hex(),
            "rt_mr0": self.rt_mr0.hex(),
            "rt_mr1": self.rt_mr1.hex(),
            "rt_mr2": self.rt_mr2.hex(),
            "rt_mr3": self.rt_mr3.hex(),
            "report_data": self.report_data.hex(),
            "td_attributes": self.td_attributes.hex(),
            "xfam": self.xfam.hex(),
        }


@dataclass(frozen=True)
class ParsedQuote:
    version: int
    attestation_key_type: int
    tee_type: int
    qe_vendor_id: bytes
    report: TdReport
    report_data: bytes
    attestation_key: p256.Point
    quote_signature: bytes
    qe_report: bytes
    qe_report_signature: bytes
    qe_auth_data: bytes
    pck_chain: tuple[p256.Certificate, ...]
    signed_body: bytes = b""


def _u16(data: bytes, offset: int) -> int:
    return struct.unpack_from("<H", data, offset)[0]


def _u32(data: bytes, offset: int) -> int:
    return struct.unpack_from("<I", data, offset)[0]


def parse_quote(raw: bytes) -> ParsedQuote:
    """Parse a TDX v4 quote. Raises :class:`TdxQuoteError` on anything unexpected."""
    if len(raw) < _QUOTE_HEADER_SIZE + _TD_REPORT_SIZE + 64:
        raise TdxQuoteError("quote is shorter than a TDX quote header and body")
    version = _u16(raw, 0)
    if version != 4:
        raise TdxQuoteError(f"unsupported quote version {version}; only TDX v4 is handled")
    attestation_key_type = _u16(raw, 2)
    tee_type = _u32(raw, 4)
    if tee_type != 0x81:
        raise TdxQuoteError(f"quote is not a TDX quote (tee_type={tee_type:#x})")
    qe_vendor_id = raw[12:28]

    body_start = _QUOTE_HEADER_SIZE
    last_error: Exception | None = None
    for report_size in _TD_REPORT_SIZES:
        body_end = body_start + report_size
        try:
            return _parse_signature_section(
                raw,
                body_start=body_start,
                body_end=body_end,
                report_size=report_size,
                version=version,
                attestation_key_type=attestation_key_type,
                tee_type=tee_type,
                qe_vendor_id=qe_vendor_id,
            )
        except TdxQuoteError as exc:
            last_error = exc
    raise last_error if last_error is not None else TdxQuoteError("could not parse quote")


def _parse_signature_section(
    raw: bytes,
    *,
    body_start: int,
    body_end: int,
    report_size: int,
    version: int,
    attestation_key_type: int,
    tee_type: int,
    qe_vendor_id: bytes,
) -> ParsedQuote:
    """Parse the signature section that follows a TD report body of ``report_size`` bytes.

    The section is ``quote_signature (64) || attestation_key (64) || certification_data``.
    """
    if body_end + 128 > len(raw):
        raise TdxQuoteError("quote signature section is truncated")
    report = _parse_td_report(raw[body_start:body_end])
    quote_signature = raw[body_end : body_end + 64]
    ak_bytes = raw[body_end + 64 : body_end + 128]
    attestation_key = p256.Point(
        int.from_bytes(ak_bytes[:32], "big"), int.from_bytes(ak_bytes[32:], "big")
    )
    if not p256.is_on_curve(attestation_key):
        raise TdxQuoteError("attestation key is not a valid P-256 point")

    cd_hdr = body_end + 128
    if cd_hdr + 6 > len(raw):
        raise TdxQuoteError("certification data header is truncated")
    cd_type = _u16(raw, cd_hdr)
    cd_size = _u32(raw, cd_hdr + 2)
    cd_start = cd_hdr + 6
    if cd_start + cd_size > len(raw):
        raise TdxQuoteError("certification data is truncated")
    if cd_type != 6:
        raise TdxQuoteError(
            f"unsupported certification data type {cd_type}; expected QEReportCertificationData"
        )
    cd = raw[cd_start : cd_start + cd_size]
    qe_report, qe_report_signature, qe_auth_data, pck_chain = _parse_qe_certification_data(cd)

    return ParsedQuote(
        version=version,
        attestation_key_type=attestation_key_type,
        tee_type=tee_type,
        qe_vendor_id=qe_vendor_id,
        report=report,
        report_data=report.report_data,
        attestation_key=attestation_key,
        quote_signature=quote_signature,
        qe_report=qe_report,
        qe_report_signature=qe_report_signature,
        qe_auth_data=qe_auth_data,
        pck_chain=pck_chain,
        signed_body=raw[:body_end],
    )


def _parse_td_report(body: bytes) -> TdReport:
    if len(body) < _TD_REPORT_SIZE:
        raise TdxQuoteError("TD report body has the wrong size")
    return TdReport(
        tee_tcb_svn=body[0:16],
        mr_seam=body[16:64],
        mr_signer_seam=body[64:112],
        mr_config_id=body[184:232],
        mr_owner=body[232:280],
        mr_owner_config=body[280:328],
        rt_mr0=body[328:376],
        rt_mr1=body[376:424],
        rt_mr2=body[424:472],
        rt_mr3=body[472:520],
        report_data=body[520:584],
        td_attributes=body[120:128],
        xfam=body[128:136],
    )


def _parse_qe_certification_data(
    cd: bytes,
) -> tuple[bytes, bytes, bytes, tuple[p256.Certificate, ...]]:
    if len(cd) < 384 + 64 + 2 + 2:
        raise TdxQuoteError("QEReportCertificationData is too short")
    qe_report = cd[0:384]
    qe_report_signature = cd[384:448]
    offset = 448
    qe_auth_len = _u16(cd, offset)
    offset += 2
    qe_auth_data = cd[offset : offset + qe_auth_len]
    offset += qe_auth_len
    # The PCK certificate chain is itself a TLV: type (u16) + size (u32) + PEM payload.
    if offset + 6 > len(cd):
        raise TdxQuoteError("PCK certificate chain header is truncated")
    offset += 2  # certificate-chain type (5 for a PCK chain)
    pck_len = _u32(cd, offset)
    offset += 4
    pck_bytes = cd[offset : offset + pck_len]
    certs = _parse_pem_chain(pck_bytes)
    if not certs:
        raise TdxQuoteError("certification data contains no PCK certificate chain")
    return qe_report, qe_report_signature, qe_auth_data, certs


def _parse_pem_chain(pem_blob: bytes) -> tuple[p256.Certificate, ...]:
    import re

    blocks = re.findall(
        rb"-----BEGIN CERTIFICATE-----.*?-----END CERTIFICATE-----", pem_blob, re.S
    )
    certs = []
    for block in blocks:
        body = (
            block.replace(b"-----BEGIN CERTIFICATE-----", b"")
            .replace(b"-----END CERTIFICATE-----", b"")
            .strip()
        )
        der = base64.b64decode(body)
        certs.append(p256.parse_certificate(der))
    return tuple(certs)


# --- ECDSA signature helpers --------------------------------------------------


def _raw_to_der(signature: bytes) -> bytes:
    """Convert a 64-byte raw r||s signature into an ASN.1 DER ECDSA-Sig-Value."""
    r = int.from_bytes(signature[:32], "big")
    s = int.from_bytes(signature[32:], "big")

    def _int(value: int) -> bytes:
        raw = value.to_bytes((value.bit_length() + 7) // 8 or 1, "big")
        if raw[0] & 0x80:
            raw = b"\x00" + raw
        return b"\x02" + bytes([len(raw)]) + raw

    body = _int(r) + _int(s)
    return b"\x30" + bytes([len(body)]) + body


def verify_ecdsa_raw(public_key: p256.Point, data: bytes, signature: bytes) -> bool:
    """Verify a raw 64-byte ECDSA-P256-SHA256 signature."""
    if len(signature) != 64:
        return False
    return p256.verify_signature(public_key, data, _raw_to_der(signature))


# --- event log replay ---------------------------------------------------------


def replay_event_log(events: Sequence[dict[str, Any]]) -> dict[int, bytes]:
    """Replay an RTMR event log.

    Each event extends its RTMR with ``SHA384(old || digest)``. Returns the four replayed RTMR
    values keyed by index.
    """
    registers = {0: bytes(48), 1: bytes(48), 2: bytes(48), 3: bytes(48)}
    for event in events:
        imr = int(event.get("imr", -1))
        if imr not in registers:
            continue
        digest = bytes.fromhex(str(event["digest"]))
        if len(digest) != 48:
            raise TdxQuoteError("event-log digest is not 48 bytes")
        registers[imr] = hashlib.sha384(registers[imr] + digest).digest()
    return registers


# --- verification -------------------------------------------------------------


@dataclass
class TdxVerification:
    """The outcome of verifying a TDX quote. ``verified`` is true only when ``failures`` is empty."""

    verified: bool
    failures: list[str] = field(default_factory=list)
    checks: dict[str, bool] = field(default_factory=dict)
    report_data: str = ""
    attestation_key: str = ""
    qe_vendor_id: str = ""
    intel_root_fingerprint: str = ""
    pck_chain_fingerprints: list[str] = field(default_factory=list)
    measurement: dict[str, Any] = field(default_factory=dict)
    nonce: str = ""
    signing_address: str = ""
    tls_cert_fingerprint: str = ""

    def to_dict(self) -> dict[str, Any]:
        return {
            "verified": self.verified,
            "failures": list(self.failures),
            "checks": dict(self.checks),
            "report_data": self.report_data,
            "attestation_key": self.attestation_key,
            "qe_vendor_id": self.qe_vendor_id,
            "intel_root_fingerprint": self.intel_root_fingerprint,
            "pck_chain_fingerprints": list(self.pck_chain_fingerprints),
            "measurement": dict(self.measurement),
            "nonce": self.nonce,
            "signing_address": self.signing_address,
            "tls_cert_fingerprint": self.tls_cert_fingerprint,
        }


def verify_tdx_quote(
    raw_quote: bytes,
    *,
    nonce: bytes | None = None,
    signing_address: bytes | None = None,
    tls_cert_fingerprint: bytes | None = None,
    event_log: Sequence[dict[str, Any]] | None = None,
    expected_root_fingerprint: str = INTEL_SGX_ROOT_CA_SHA256,
    now: int | None = None,
) -> TdxVerification:
    """Verify a TDX quote and its bindings.

    Every check is recorded in ``checks``; any failure is appended to ``failures`` and forces
    ``verified`` to be false. Nothing here trusts a value echoed outside the quote.
    """
    result = TdxVerification(verified=False)
    try:
        quote = parse_quote(raw_quote)
    except (TdxQuoteError, p256.P256Error) as exc:
        result.failures.append(f"parse_error: {exc}")
        return result

    result.report_data = quote.report_data.hex()
    result.qe_vendor_id = quote.qe_vendor_id.hex()
    result.attestation_key = (
        quote.attestation_key.x.to_bytes(32, "big") + quote.attestation_key.y.to_bytes(32, "big")
    ).hex()
    result.measurement = quote.report.to_dict()
    result.pck_chain_fingerprints = [c.fingerprint_sha256.hex() for c in quote.pck_chain]

    checks = result.checks
    failures = result.failures

    # 1. QE vendor id must be Intel's.
    checks["qe_vendor_id_is_intel"] = quote.qe_vendor_id == INTEL_QE_VENDOR_ID
    if not checks["qe_vendor_id_is_intel"]:
        failures.append("quote QE vendor id is not Intel's")

    # 2. PCK chain: leaf -> intermediate -> pinned Intel root, each link signed.
    chain = quote.pck_chain
    chain_ok = len(chain) >= 2
    if chain_ok:
        for child, issuer in zip(chain, chain[1:]):
            if not p256.verify_certificate_signature(child, issuer):
                chain_ok = False
                failures.append("PCK certificate chain link is not validly signed")
                break
        root = chain[-1]
        root_self = p256.verify_certificate_signature(root, root)
        root_pinned = root.fingerprint_sha256.hex() == expected_root_fingerprint
        result.intel_root_fingerprint = root.fingerprint_sha256.hex()
        checks["pck_chain_links_valid"] = chain_ok
        checks["root_is_self_signed"] = root_self
        checks["root_matches_pinned_intel_root"] = root_pinned
        if not root_self:
            failures.append("PCK chain root is not self-signed")
        if not root_pinned:
            failures.append("PCK chain root does not match the pinned Intel root CA")
    else:
        checks["pck_chain_links_valid"] = False
        failures.append("PCK chain has fewer than two certificates")

    pck_leaf = chain[0] if chain else None

    # 3. QE report signature by the PCK leaf, and the AK binding inside it.
    if pck_leaf is not None:
        qe_sig_ok = verify_ecdsa_raw(
            pck_leaf.public_key, quote.qe_report, quote.qe_report_signature
        )
        checks["qe_report_signed_by_pck_leaf"] = qe_sig_ok
        if not qe_sig_ok:
            failures.append("QE report is not validly signed by the PCK leaf certificate")
        qe_report_data = quote.qe_report[320:384]
        ak_bytes = quote.attestation_key.x.to_bytes(32, "big") + quote.attestation_key.y.to_bytes(
            32, "big"
        )
        expected_binding = hashlib.sha256(ak_bytes + quote.qe_auth_data).digest()
        ak_bound = qe_report_data[:32] == expected_binding
        checks["attestation_key_bound_to_qe"] = ak_bound
        if not ak_bound:
            failures.append("attestation key is not bound to the Quoting Enclave report")
    else:
        checks["qe_report_signed_by_pck_leaf"] = False
        checks["attestation_key_bound_to_qe"] = False

    # 4. Quote signature by the attestation key, over the quote body.
    body = raw_quote[: _QUOTE_HEADER_SIZE + _TD_REPORT_SIZE]
    quote_sig_ok = verify_ecdsa_raw(quote.attestation_key, body, quote.quote_signature)
    checks["quote_signature_valid"] = quote_sig_ok
    if not quote_sig_ok:
        failures.append("quote signature does not verify under the quote's attestation key")

    # 5. report_data bindings.
    report_data = quote.report_data
    if nonce is not None:
        checks["nonce_bound"] = report_data[32:64] == nonce
        result.nonce = nonce.hex()
        if not checks["nonce_bound"]:
            failures.append("report_data does not bind the supplied nonce")
    if signing_address is not None or tls_cert_fingerprint is not None:
        spki_hash = tls_cert_fingerprint if tls_cert_fingerprint is not None else bytes(32)
        expected = hashlib.sha256((signing_address or b"") + spki_hash).digest()
        checks["signing_identity_bound"] = report_data[:32] == expected
        result.signing_address = (signing_address or b"").hex()
        result.tls_cert_fingerprint = (tls_cert_fingerprint or b"").hex()
        if not checks["signing_identity_bound"]:
            failures.append("report_data does not bind the supplied signing address / TLS key")

    # 6. Event-log replay to the RTMRs.
    if event_log is not None:
        try:
            replayed = replay_event_log(event_log)
            quote_rtmrs = quote.report.rtmrs()
            replay_ok = all(replayed[i] == quote_rtmrs[i] for i in range(4))
        except (TdxQuoteError, KeyError, ValueError) as exc:
            replay_ok = False
            failures.append(f"event log could not be replayed: {exc}")
        checks["event_log_replays_to_rtmrs"] = replay_ok
        if not replay_ok and not any("event log" in f for f in failures):
            failures.append("replayed event log does not match the quote's RTMRs")

    # 7. Certificate validity window (the PCK leaf must be valid now).
    if pck_leaf is not None:
        window_ok = _certificate_within_window(pck_leaf, now)
        checks["pck_leaf_within_validity"] = window_ok
        if not window_ok:
            failures.append("PCK leaf certificate is outside its validity window")

    result.verified = not failures
    return result


def _certificate_within_window(cert: p256.Certificate, now: int | None) -> bool:
    """Check the PCK leaf's notBefore/notAfter against ``now`` (or the current time)."""
    import time

    moment = now if now is not None else int(time.time())
    not_before, not_after = p256.certificate_time_bytes(cert)
    try:
        start = _parse_asn1_time(not_before)
        end = _parse_asn1_time(not_after)
    except ValueError:
        return False
    return start <= moment <= end


def _parse_asn1_time(raw: bytes) -> int:
    """Parse a UTCTime/GeneralizedTime into a Unix timestamp (UTC)."""
    import calendar

    text = raw.decode("ascii")
    if text.endswith("Z"):
        text = text[:-1]
    # UTCTime: YYMMDDHHMMSS ; GeneralizedTime: YYYYMMDDHHMMSS
    if len(text) == 12:
        year = int(text[0:2])
        year += 2000 if year < 50 else 1900
        text = f"{year:04d}" + text[2:]
    if len(text) != 14:
        raise ValueError("unsupported ASN.1 time format")
    year = int(text[0:4])
    month = int(text[4:6])
    day = int(text[6:8])
    hour = int(text[8:10])
    minute = int(text[10:12])
    second = int(text[12:14])
    return calendar.timegm((year, month, day, hour, minute, second, 0, 0, 0))
