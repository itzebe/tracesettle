"""Ed25519 signing and verification, standard-library only.

NEAR account keys are ed25519. The application itself never signs: signing is
the user's wallet's job. This module exists for two other reasons:

* the **testnet demonstration** (:mod:`demo.near_testnet_demo`) signs a real
  testnet transaction with a throwaway testnet key supplied through an
  environment variable, so the demonstration can prove the whole path end to end
  without a browser; and
* tests verify a *real* on-chain signature, which is the strongest possible
  check that the Borsh serializer produces the exact bytes the network signed.

It is a compact, well-understood implementation of the Ed25519 reference
algorithm (Bernstein et al., public domain). It is not constant-time and must
never be used to guard a secret in an adversarial setting; the only key it ever
touches is a disposable testnet key. Verified against RFC 8032 test vectors and
against a real NEAR transaction signature in ``tests/test_near_ed25519.py``.
"""

from __future__ import annotations

import hashlib

P = 2**255 - 19
Q = 2**252 + 27742317777372353535851937790883648493


def _inv(x: int) -> int:
    return pow(x, P - 2, P)


_D = (-121665 * _inv(121666)) % P
_I = pow(2, (P - 1) // 4, P)


def _xrecover(y: int) -> int:
    xx = (y * y - 1) * _inv(_D * y * y + 1)
    x = pow(xx, (P + 3) // 8, P)
    if (x * x - xx) % P != 0:
        x = (x * _I) % P
    if x % 2 != 0:
        x = P - x
    return x


_BY = (4 * _inv(5)) % P
_BX = _xrecover(_BY)
_B = (_BX % P, _BY % P)


def _edwards_add(p: tuple[int, int], q: tuple[int, int]) -> tuple[int, int]:
    x1, y1 = p
    x2, y2 = q
    denom1 = _inv(1 + _D * x1 * x2 * y1 * y2)
    denom2 = _inv(1 - _D * x1 * x2 * y1 * y2)
    x3 = (x1 * y2 + x2 * y1) * denom1 % P
    y3 = (y1 * y2 + x1 * x2) * denom2 % P
    return (x3, y3)


def _scalar_mult(p: tuple[int, int], e: int) -> tuple[int, int]:
    if e == 0:
        return (0, 1)
    q = _scalar_mult(p, e // 2)
    q = _edwards_add(q, q)
    if e & 1:
        q = _edwards_add(q, p)
    return q


def _encode_point(p: tuple[int, int]) -> bytes:
    x, y = p
    bits = [(y >> i) & 1 for i in range(255)] + [x & 1]
    return bytes(sum(bits[i * 8 + j] << j for j in range(8)) for i in range(32))


def _decode_point(s: bytes) -> tuple[int, int]:
    y = int.from_bytes(s, "little") & ((1 << 255) - 1)
    x = _xrecover(y)
    if (x & 1) != ((s[31] >> 7) & 1):
        x = P - x
    return (x, y)


def _clamp(h: bytes) -> int:
    a = int.from_bytes(h[:32], "little")
    a &= (1 << 254) - 8
    a |= 1 << 254
    return a


def public_key(seed: bytes) -> bytes:
    """Derive the 32-byte ed25519 public key from a 32-byte private seed."""
    if len(seed) != 32:
        raise ValueError("ed25519 seed must be 32 bytes")
    h = hashlib.sha512(seed).digest()
    a = _clamp(h)
    return _encode_point(_scalar_mult(_B, a))


def sign(message: bytes, seed: bytes, public: bytes | None = None) -> bytes:
    """Return the 64-byte ed25519 signature of ``message`` under ``seed``."""
    if len(seed) != 32:
        raise ValueError("ed25519 seed must be 32 bytes")
    if public is None:
        public = public_key(seed)
    h = hashlib.sha512(seed).digest()
    a = _clamp(h)
    r = int.from_bytes(hashlib.sha512(h[32:] + message).digest(), "little") % Q
    big_r = _scalar_mult(_B, r)
    encoded_r = _encode_point(big_r)
    k = int.from_bytes(hashlib.sha512(encoded_r + public + message).digest(), "little") % Q
    s = (r + k * a) % Q
    return encoded_r + s.to_bytes(32, "little")


def verify(signature: bytes, message: bytes, public: bytes) -> bool:
    """Verify a 64-byte ed25519 signature. Returns ``False`` on malformed input."""
    if len(signature) != 64 or len(public) != 32:
        return False
    try:
        big_r = _decode_point(signature[:32])
        s = int.from_bytes(signature[32:], "little")
        if s >= Q:
            return False
        a = _decode_point(public)
        k = int.from_bytes(hashlib.sha512(signature[:32] + public + message).digest(), "little") % Q
    except (ValueError, ArithmeticError):
        return False
    return _scalar_mult(_B, s) == _edwards_add(big_r, _scalar_mult(a, k))
