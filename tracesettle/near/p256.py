"""Pure standard-library ECDSA over NIST P-256, plus the DER/X.509 subset needed to verify an
Intel TDX attestation quote.

Why this exists: TDX attestation is signed with ECDSA-P256 (the PCK certificate chain and the
quote signature), and the runtime is deliberately standard-library only. Python's stdlib has no
elliptic-curve verification, so the curve arithmetic and the certificate parsing live here.

This is *verification only*. There is no private-key operation anywhere in this module: it can
check a signature, and it can do nothing else. Every routine is written so that malformed input
returns a failure rather than raising, because attestation input is attacker-supplied.

References: SEC1 v2 (EC arithmetic), RFC 5480 (EC public keys / SPKI), RFC 5280 (X.509),
FIPS 186-4 (ECDSA).
"""

from __future__ import annotations

import hashlib
from dataclasses import dataclass


class P256Error(ValueError):
    """A P-256 or DER structure could not be parsed or was invalid."""


# --- curve parameters (FIPS 186-4 / SEC2) ---------------------------------

#: Field prime.
P = 0xFFFFFFFF00000001000000000000000000000000FFFFFFFFFFFFFFFFFFFFFFFF
#: Curve coefficient a = -3 mod p.
_A = P - 3
#: Curve coefficient b.
_B = 0x5AC635D8AA3A93E7B3EBBD55769886BC651D06B0CC53B0F63BCE3C3E27D2604B
#: Group order.
N = 0xFFFFFFFF00000000FFFFFFFFFFFFFFFFBCE6FAADA7179E84F3B9CAC2FC632551
#: Base point.
GX = 0x6B17D1F2E12C4247F8BCE6E563A440F277037D812DEB33A0F4A13945D898C296
GY = 0x4FE342E2FE1A7F9B8EE7EB4A7C0F9E162BCE33576B315ECECBB6406837BF51F5

#: OID for id-ecPublicKey (RFC 5480).
OID_EC_PUBLIC_KEY = "1.2.840.10045.2.1"
#: OID for the prime256v1 / secp256r1 / P-256 curve.
OID_PRIME256V1 = "1.2.840.10045.3.1.7"
#: OID for ecdsa-with-SHA256.
OID_ECDSA_SHA256 = "1.2.840.10045.4.3.2"


@dataclass(frozen=True)
class Point:
    """An affine point on P-256, or the point at infinity when ``x``/``y`` are ``None``."""

    x: int | None
    y: int | None

    @property
    def infinity(self) -> bool:
        return self.x is None and self.y is None


INFINITY = Point(None, None)


def is_on_curve(point: Point) -> bool:
    if point.infinity:
        return True
    if point.x is None or point.y is None:
        return False
    if not (0 <= point.x < P and 0 <= point.y < P):
        return False
    return (point.y * point.y - (point.x * point.x * point.x + _A * point.x + _B)) % P == 0


def _inv(value: int, modulus: int) -> int:
    return pow(value % modulus, -1, modulus)


def point_add(left: Point, right: Point) -> Point:
    """Add two points. Returns the point at infinity for P + (-P)."""
    if left.infinity:
        return right
    if right.infinity:
        return left
    x1, y1 = left.x, left.y
    x2, y2 = right.x, right.y
    if x1 == x2 and (y1 + y2) % P == 0:
        return INFINITY
    if left == right:
        lam = (3 * x1 * x1 + _A) * _inv(2 * y1, P) % P
    else:
        lam = (y2 - y1) * _inv(x2 - x1, P) % P
    x3 = (lam * lam - x1 - x2) % P
    y3 = (lam * (x1 - x3) - y1) % P
    return Point(x3, y3)


def scalar_mult(scalar: int, point: Point) -> Point:
    """Multiply ``point`` by ``scalar`` using double-and-add."""
    if scalar % N == 0 or point.infinity:
        return INFINITY
    result = INFINITY
    addend = point
    while scalar > 0:
        if scalar & 1:
            result = point_add(result, addend)
        addend = point_add(addend, addend)
        scalar >>= 1
    return result


def public_key_from_point(point: Point) -> Point:
    """Validate a public point: on-curve and of the correct order (cofactor is 1)."""
    if point.infinity or not is_on_curve(point):
        raise P256Error("public key is not a valid point on P-256")
    if scalar_mult(N, point) is not INFINITY and not scalar_mult(N, point).infinity:
        raise P256Error("public key is not of the correct order")
    return point


def verify_signature(public_key: Point, data: bytes, signature_der: bytes) -> bool:
    """Verify an ECDSA-P256-SHA256 signature over ``data``.

    ``signature_der`` is the ASN.1 ``ECDSA-Sig-Value`` (SEQUENCE of two INTEGERs). Returns a
    boolean; malformed input is a failure, never an exception.
    """
    try:
        if public_key.infinity or not is_on_curve(public_key):
            return False
        r, s = _decode_ecdsa_signature(signature_der)
        if not (1 <= r < N and 1 <= s < N):
            return False
        digest = hashlib.sha256(data).digest()
        e = int.from_bytes(digest, "big")
        w = _inv(s, N)
        u1 = (e * w) % N
        u2 = (r * w) % N
        point = point_add(scalar_mult(u1, Point(GX, GY)), scalar_mult(u2, public_key))
        if point.infinity:
            return False
        return (point.x % N) == r
    except Exception:  # noqa: BLE001 - any parse/arith failure is simply "not verified"
        return False


def _decode_ecdsa_signature(der: bytes) -> tuple[int, int]:
    reader = _DerReader(der)
    seq = reader.read_sequence()
    inner = _DerReader(seq)
    r = inner.read_integer()
    s = inner.read_integer()
    return r, s


# --- DER / X.509 -----------------------------------------------------------


class _DerReader:
    """A minimal, strict DER reader for the structures X.509 needs."""

    def __init__(self, data: bytes) -> None:
        self.data = data
        self.pos = 0

    def _read_tlv(self) -> tuple[int, bytes, bytes]:
        if self.pos >= len(self.data):
            raise P256Error("truncated DER")
        start = self.pos
        tag = self.data[self.pos]
        self.pos += 1
        length = self.data[self.pos]
        self.pos += 1
        if length & 0x80:
            count = length & 0x7F
            if count == 0 or count > 4:
                raise P256Error("unsupported DER length")
            length = int.from_bytes(self.data[self.pos : self.pos + count], "big")
            self.pos += count
        value = self.data[self.pos : self.pos + length]
        if len(value) != length:
            raise P256Error("DER value shorter than its declared length")
        self.pos += length
        return tag, value, self.data[start : self.pos]

    def read(self, expected_tag: int) -> bytes:
        tag, value, _ = self._read_tlv()
        if tag != expected_tag:
            raise P256Error(f"expected DER tag {expected_tag:#x}, found {tag:#x}")
        return value

    def read_sequence(self) -> bytes:
        return self.read(0x30)

    def read_set(self) -> bytes:
        return self.read(0x31)

    def read_integer(self) -> int:
        value = self.read(0x02)
        if not value:
            raise P256Error("empty INTEGER")
        return int.from_bytes(value, "big", signed=True)

    def read_bit_string(self) -> bytes:
        value = self.read(0x03)
        if not value or value[0] != 0:
            raise P256Error("unsupported BIT STRING padding")
        return value[1:]

    def read_oid(self) -> str:
        raw = self.read(0x06)
        if not raw:
            raise P256Error("empty OBJECT IDENTIFIER")
        parts = [raw[0] // 40, raw[0] % 40]
        value = 0
        for byte in raw[1:]:
            value = (value << 7) | (byte & 0x7F)
            if not byte & 0x80:
                parts.append(value)
                value = 0
        return ".".join(str(part) for part in parts)

    def peek_tag(self) -> int:
        if self.pos >= len(self.data):
            raise P256Error("truncated DER")
        return self.data[self.pos]

    def read_raw_tlv(self) -> bytes:
        _, _, raw = self._read_tlv()
        return raw

    @property
    def exhausted(self) -> bool:
        return self.pos >= len(self.data)


@dataclass(frozen=True)
class Certificate:
    """The X.509 fields this project needs, parsed from DER."""

    der: bytes
    tbs_der: bytes
    signature_algorithm: str
    signature: bytes
    spki_der: bytes
    public_key: Point
    issuer_der: bytes
    subject_der: bytes
    not_before: bytes
    not_after: bytes

    @property
    def spki_sha256(self) -> bytes:
        return hashlib.sha256(self.spki_der).digest()

    @property
    def fingerprint_sha256(self) -> bytes:
        return hashlib.sha256(self.der).digest()


def parse_certificate(der: bytes) -> Certificate:
    """Parse a DER X.509 certificate. Raises :class:`P256Error` on anything unexpected."""
    outer = _DerReader(der)
    cert_body = outer.read_sequence()
    cert = _DerReader(cert_body)
    tbs_der = cert.read_raw_tlv()

    sig_alg_body = cert.read_sequence()
    sig_alg = _DerReader(sig_alg_body)
    signature_algorithm = sig_alg.read_oid()

    signature = cert.read_bit_string()

    tbs = _DerReader(tbs_der)
    tbs_body = tbs.read_sequence()
    inner = _DerReader(tbs_body)

    if inner.peek_tag() == 0xA0:  # [0] EXPLICIT version
        inner.read_raw_tlv()
    inner.read_integer()  # serialNumber
    inner.read_raw_tlv()  # signature AlgorithmIdentifier
    issuer_der = inner.read_raw_tlv()
    validity_body = inner.read_sequence()
    subject_der = inner.read_raw_tlv()
    spki_der = inner.read_raw_tlv()

    validity = _DerReader(validity_body)
    not_before = validity.read_raw_tlv()
    not_after = validity.read_raw_tlv()

    public_key = _parse_spki(spki_der)

    return Certificate(
        der=der,
        tbs_der=tbs_der,
        signature_algorithm=signature_algorithm,
        signature=signature,
        spki_der=spki_der,
        public_key=public_key,
        issuer_der=issuer_der,
        subject_der=subject_der,
        not_before=not_before,
        not_after=not_after,
    )


def _parse_spki(spki_der: bytes) -> Point:
    """Parse a SubjectPublicKeyInfo into a P-256 point, enforcing the curve OID."""
    reader = _DerReader(spki_der)
    body = reader.read_sequence()
    inner = _DerReader(body)
    alg_body = inner.read_sequence()
    alg = _DerReader(alg_body)
    if alg.read_oid() != OID_EC_PUBLIC_KEY:
        raise P256Error("SPKI is not an EC public key")
    if alg.read_oid() != OID_PRIME256V1:
        raise P256Error("SPKI is not on the P-256 curve")
    point_bytes = inner.read_bit_string()
    if len(point_bytes) != 65 or point_bytes[0] != 0x04:
        raise P256Error("SPKI point is not an uncompressed P-256 point")
    x = int.from_bytes(point_bytes[1:33], "big")
    y = int.from_bytes(point_bytes[33:65], "big")
    return Point(x, y)


def verify_certificate_signature(child: Certificate, issuer: Certificate) -> bool:
    """Verify that ``issuer`` signed ``child`` (ECDSA-P256-SHA256)."""
    if child.signature_algorithm != OID_ECDSA_SHA256:
        return False
    return verify_signature(issuer.public_key, child.tbs_der, child.signature)


def _asn1_time(raw: bytes) -> bytes:
    """Return the UTCTime/GeneralizedTime content bytes (the DER value, tag stripped)."""
    _, value, _ = _DerReader(raw)._read_tlv()  # type: ignore[attr-defined]
    return value


def certificate_time_bytes(cert: Certificate) -> tuple[bytes, bytes]:
    """Expose notBefore/notAfter as their ASN.1 time strings (e.g. ``b'260101000000Z'``)."""
    return _asn1_time(cert.not_before), _asn1_time(cert.not_after)
