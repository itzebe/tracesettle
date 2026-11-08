"""Base58 and Base58Check decoding.

A single implementation is shared by identifier classification and Bitcoin
script decoding so the two can never disagree about what a string decodes to.
Nothing here classifies anything or decides an outcome; these are pure decoding
primitives that return ``None`` on malformed input rather than raising.
"""

from __future__ import annotations

import hashlib

#: Bitcoin/Solana base58 alphabet (no 0, O, I, l).
BASE58_ALPHABET = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz"


def b58decode(value: str) -> bytes | None:
    """Decode a base58 string to bytes, or ``None`` if it is not valid base58."""
    num = 0
    for ch in value:
        idx = BASE58_ALPHABET.find(ch)
        if idx < 0:
            return None
        num = num * 58 + idx
    # Leading '1's are leading zero bytes.
    pad = len(value) - len(value.lstrip("1"))
    body = num.to_bytes((num.bit_length() + 7) // 8, "big") if num else b""
    return b"\x00" * pad + body


def b58encode(raw: bytes) -> str:
    """Encode bytes as base58. The inverse of :func:`b58decode`."""
    num = int.from_bytes(raw, "big")
    out = ""
    while num:
        num, rem = divmod(num, 58)
        out = BASE58_ALPHABET[rem] + out
    pad = len(raw) - len(raw.lstrip(b"\x00"))
    return "1" * pad + (out or "")


def b58check_decode(value: str) -> bytes | None:
    """Decode a Base58Check string and return its payload, or ``None``.

    The 4-byte double-SHA256 checksum is verified, so a single mistyped
    character is rejected rather than silently decoding to a different payload.
    """
    raw = b58decode(value)
    if raw is None or len(raw) < 5:
        return None
    payload, checksum = raw[:-4], raw[-4:]
    if hashlib.sha256(hashlib.sha256(payload).digest()).digest()[:4] != checksum:
        return None
    return payload
