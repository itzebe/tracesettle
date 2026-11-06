"""The authorization firewall: short-lived, transaction-bound authorizations.

An authorization is the *only* thing that lets the reference signer execute. It
is bound to the exact transaction parameters, the requesting service, an
expiry, and a unique nonce, and it is signed by a guard key. The signer
re-validates all of that against the transaction it is actually asked to sign,
so a substituted parameter, a replayed token, an expired token, or a token from
another service all fail closed.

Key management
--------------
The signing key is read from ``TRACESETTLE_GUARD_AUTH_KEY`` (hex or base64,
at least 32 bytes). It is never logged and never returned to a client. When no
key is configured, the service generates an ephemeral random key at start-up and
records that fact, so a deployment can run for a demonstration without ever
committing a secret. An ephemeral key invalidates outstanding authorizations on
restart, which is the safe direction.

This module does **not** claim to be able to stop an arbitrary blockchain
transaction. It stops a transaction from reaching a signer that consults it.
"""

from __future__ import annotations

import base64
import binascii
import hashlib
import hmac
import json
import os
import secrets
import threading
import time
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from typing import Any, Protocol

from .model import (
    AuthState,
    Decision,
    RequestFingerprint,
    canonical_fields,
    fingerprint_of,
)
from .state import StateStoreError

AUTHORIZATION_VERSION = "ts-auth-v1"
MIN_KEY_BYTES = 32

#: Authorizations are short-lived by design. A long window is a wide replay
#: window; the caller is expected to sign immediately.
DEFAULT_TTL_SECONDS = 90


def _now() -> datetime:
    return datetime.now(timezone.utc)


def _iso(dt: datetime) -> str:
    return dt.strftime("%Y-%m-%dT%H:%M:%SZ")


def _parse_iso(value: str) -> datetime:
    return datetime.strptime(value, "%Y-%m-%dT%H:%M:%SZ").replace(tzinfo=timezone.utc)


@dataclass(frozen=True)
class Authorization:
    """A signed, transaction-bound authorization token.

    ``signature`` covers every other field via :meth:`signing_payload`, so any
    edit to the parameters, the binding, the expiry, or the nonce invalidates it.
    """

    version: str
    authorization_id: str
    decision_id: str
    service_id: str
    key_id: str
    nonce: str
    issued_at: str
    expires_at: str
    fingerprint: str
    parameters: dict[str, str]
    signature: str

    def signing_payload(self) -> bytes:
        body = {
            "version": self.version,
            "authorization_id": self.authorization_id,
            "decision_id": self.decision_id,
            "service_id": self.service_id,
            "key_id": self.key_id,
            "nonce": self.nonce,
            "issued_at": self.issued_at,
            "expires_at": self.expires_at,
            "fingerprint": self.fingerprint,
            "parameters": self.parameters,
        }
        return json.dumps(body, sort_keys=True, separators=(",", ":")).encode("utf-8")

    def to_dict(self) -> dict[str, Any]:
        return {
            "version": self.version,
            "authorization_id": self.authorization_id,
            "decision_id": self.decision_id,
            "service_id": self.service_id,
            "key_id": self.key_id,
            "nonce": self.nonce,
            "issued_at": self.issued_at,
            "expires_at": self.expires_at,
            "fingerprint": self.fingerprint,
            "parameters": dict(self.parameters),
            "signature": self.signature,
        }

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> "Authorization":
        parameters = data.get("parameters")
        if not isinstance(parameters, dict):
            raise ValueError("authorization.parameters must be an object")
        return cls(
            version=str(data.get("version", "")),
            authorization_id=str(data.get("authorization_id", "")),
            decision_id=str(data.get("decision_id", "")),
            service_id=str(data.get("service_id", "")),
            key_id=str(data.get("key_id", "")),
            nonce=str(data.get("nonce", "")),
            issued_at=str(data.get("issued_at", "")),
            expires_at=str(data.get("expires_at", "")),
            fingerprint=str(data.get("fingerprint", "")),
            parameters={str(k): str(v) for k, v in parameters.items()},
            signature=str(data.get("signature", "")),
        )


@dataclass(frozen=True)
class AuthVerification:
    """Result of validating an authorization. ``state`` is ``VALID`` or a refusal."""

    state: AuthState
    detail: str
    service_id: str | None = None
    authorization_id: str | None = None

    @property
    def valid(self) -> bool:
        return self.state.valid

    def to_dict(self) -> dict[str, Any]:
        return {
            "state": self.state.value,
            "valid": self.valid,
            "detail": self.detail,
            "service_id": self.service_id,
            "authorization_id": self.authorization_id,
        }


class ReplayStore(Protocol):
    """Records consumed authorization nonces.

    ``consume`` must be atomic: it returns True exactly once per nonce, and False
    for every later attempt. That single-use guarantee is what makes a stolen
    token useless after it has been spent once.
    """

    def consume(self, nonce: str, expires_at: float) -> bool: ...

    def is_consumed(self, nonce: str) -> bool: ...


class InMemoryReplayStore:
    """Thread-safe, bounded, single-use nonce store.

    A nonce is remembered until its authorization's expiry plus a grace period,
    after which it can never be valid again anyway (the token is expired), so
    forgetting it cannot re-enable a replay. The map is bounded so cycling
    nonces cannot exhaust memory.
    """

    def __init__(self, *, grace_seconds: float = 30.0, max_entries: int = 8192) -> None:
        self._grace = grace_seconds
        self._max_entries = max_entries
        self._lock = threading.Lock()
        self._consumed: dict[str, float] = {}

    def _prune(self, now: float) -> None:
        expired = [nonce for nonce, until in self._consumed.items() if until < now]
        for nonce in expired:
            self._consumed.pop(nonce, None)

    def consume(self, nonce: str, expires_at: float) -> bool:
        now = time.time()
        with self._lock:
            self._prune(now)
            if nonce in self._consumed:
                return False
            if len(self._consumed) >= self._max_entries:
                # Evict the soonest-to-expire entry. Every evicted entry is one
                # whose token is closest to being expired, so the exposure is
                # bounded by the shortest remaining lifetime.
                oldest = min(self._consumed.items(), key=lambda kv: kv[1])[0]
                self._consumed.pop(oldest, None)
            self._consumed[nonce] = expires_at + self._grace
            return True

    def is_consumed(self, nonce: str) -> bool:
        now = time.time()
        with self._lock:
            self._prune(now)
            return nonce in self._consumed


class RevocationStore:
    """Records revoked authorization ids (used when an incident is opened)."""

    def __init__(self, *, max_entries: int = 8192) -> None:
        self._max_entries = max_entries
        self._lock = threading.Lock()
        self._revoked: dict[str, float] = {}

    def revoke(self, authorization_id: str, until: float) -> None:
        with self._lock:
            if len(self._revoked) >= self._max_entries:
                oldest = min(self._revoked.items(), key=lambda kv: kv[1])[0]
                self._revoked.pop(oldest, None)
            self._revoked[authorization_id] = until

    def is_revoked(self, authorization_id: str) -> bool:
        now = time.time()
        with self._lock:
            expired = [k for k, until in self._revoked.items() if until < now]
            for key in expired:
                self._revoked.pop(key, None)
            return authorization_id in self._revoked


#: Convenience alias so callers can name the store by its role.
AuthorizationStore = InMemoryReplayStore


def load_key(explicit: str | None = None) -> tuple[bytes, str, bool]:
    """Return ``(key_bytes, key_id, ephemeral)``.

    The key is taken from ``explicit``, then ``TRACESETTLE_GUARD_AUTH_KEY``. A
    configured key shorter than 32 bytes is rejected outright rather than
    stretched. With no key configured, a fresh ephemeral key is generated and
    flagged as ephemeral so the caller can say so honestly.
    """
    raw = explicit or os.environ.get("TRACESETTLE_GUARD_AUTH_KEY")
    if raw:
        key = _decode_key(raw)
        if len(key) < MIN_KEY_BYTES:
            raise ValueError(
                f"guard authorization key must be at least {MIN_KEY_BYTES} bytes "
                f"(got {len(key)}); refusing to start with a weak key"
            )
        return key, f"k-{hashlib.sha256(key).hexdigest()[:16]}", False
    key = secrets.token_bytes(MIN_KEY_BYTES)
    return key, f"ephemeral-{secrets.token_hex(8)}", True


def _decode_key(raw: str) -> bytes:
    text = raw.strip()
    # Try base64 first only when it does not look like hex, so a hex string with
    # only [0-9a-f] is not misread as base64.
    if len(text) >= 2 and len(text) % 2 == 0 and all(c in "0123456789abcdefABCDEF" for c in text):
        try:
            return binascii.unhexlify(text)
        except binascii.Error as exc:
            raise ValueError("guard authorization key is not valid hex") from exc
    try:
        return base64.b64decode(text, validate=True)
    except (binascii.Error, ValueError) as exc:
        raise ValueError(
            "guard authorization key must be hex or base64 encoded bytes"
        ) from exc


class AuthorizationAuthority:
    """Issues and validates transaction-bound authorizations.

    The same object is used by the guard (to issue) and by the reference signer
    (to validate). A deployment that separates the two would share only the key
    and the replay store, which is exactly what the validation path needs.
    """

    def __init__(
        self,
        *,
        key: bytes | None = None,
        key_id: str | None = None,
        ephemeral: bool | None = None,
        replay_store: "ReplayStore | None" = None,
        revocations: "RevocationStore | None" = None,
        ttl_seconds: int = DEFAULT_TTL_SECONDS,
        clock: "callable[[], datetime] | None" = None,
    ) -> None:
        if key is None:
            key, generated_id, generated_ephemeral = load_key()
            key_id = key_id or generated_id
            ephemeral = generated_ephemeral if ephemeral is None else ephemeral
        elif key_id is None:
            key_id = f"k-{hashlib.sha256(key).hexdigest()[:16]}"
            ephemeral = False if ephemeral is None else ephemeral
        self._key = key
        self.key_id = key_id or "unknown"
        self.ephemeral = bool(ephemeral)
        self._replay = replay_store or InMemoryReplayStore()
        self._revocations = revocations or RevocationStore()
        self.ttl_seconds = max(1, int(ttl_seconds))
        self._clock = clock or _now

    # -- issuing ------------------------------------------------------------

    def issue(
        self,
        *,
        decision_id: str,
        decision: Decision,
        service_id: str,
        parameters: dict[str, str],
        ttl_seconds: int | None = None,
    ) -> Authorization:
        """Mint an authorization for an ALLOW decision.

        Refuses to issue for any non-authorizing decision, so a bug upstream
        cannot turn a BLOCK into a signed token.
        """
        if decision is not Decision.ALLOW:
            raise ValueError(
                f"refusing to issue an authorization for a {decision.value} decision"
            )
        now = self._clock()
        ttl = self.ttl_seconds if ttl_seconds is None else max(1, int(ttl_seconds))
        fingerprint = fingerprint_of(parameters)
        auth = Authorization(
            version=AUTHORIZATION_VERSION,
            authorization_id=f"auth_{secrets.token_hex(12)}",
            decision_id=decision_id,
            service_id=service_id,
            key_id=self.key_id,
            nonce=secrets.token_urlsafe(24),
            issued_at=_iso(now),
            expires_at=_iso(now + timedelta(seconds=ttl)),
            fingerprint=fingerprint.digest,
            parameters=dict(parameters),
            signature="",
        )
        return _replace_signature(auth, self._sign(auth))

    def _sign(self, auth: Authorization) -> str:
        return hmac.new(self._key, auth.signing_payload(), hashlib.sha256).hexdigest()

    # -- validating ---------------------------------------------------------

    def validate(
        self,
        token: Authorization | dict[str, Any] | None,
        *,
        expected: dict[str, str] | RequestFingerprint | None,
        consume: bool = True,
        expected_service_id: str | None = None,
    ) -> AuthVerification:
        """Validate an authorization against the transaction about to be signed.

        ``expected`` is the parameter set derived from the *actual* transaction.
        Every check below is a refusal on failure; the token is valid only when
        all of them pass. ``consume`` marks the nonce used, which makes the token
        single-use.
        """
        if token is None:
            return AuthVerification(AuthState.MISSING, "no authorization was supplied")
        if isinstance(token, dict):
            try:
                token = Authorization.from_dict(token)
            except ValueError as exc:
                return AuthVerification(AuthState.MALFORMED, f"malformed authorization: {exc}")
        elif not isinstance(token, Authorization):
            # A caller may present anything: a bare string, an int, a list. None of
            # them is a token, so this is a refusal, never an exception. Reaching
            # the attribute checks below with a non-token would raise, and an
            # unhandled exception on the sign path is both a 500 and an availability
            # risk, so the shape is checked before anything is dereferenced.
            return AuthVerification(
                AuthState.MALFORMED,
                f"malformed authorization: expected a token object, got {type(token).__name__}",
            )

        if token.version != AUTHORIZATION_VERSION:
            return AuthVerification(
                AuthState.MALFORMED,
                f"unknown authorization version {token.version!r}",
                service_id=token.service_id or None,
                authorization_id=token.authorization_id or None,
            )
        if token.key_id != self.key_id:
            return AuthVerification(
                AuthState.UNKNOWN_KEY,
                "the authorization was signed by a key this signer does not trust",
                service_id=token.service_id or None,
                authorization_id=token.authorization_id or None,
            )

        expected_signature = self._sign(token)
        if not hmac.compare_digest(expected_signature, token.signature or ""):
            return AuthVerification(
                AuthState.BAD_SIGNATURE,
                "the authorization signature does not verify",
                service_id=token.service_id or None,
                authorization_id=token.authorization_id or None,
            )

        # Signature verified, so the remaining fields are authentic and safe to
        # report back.
        if expected_service_id is not None and token.service_id != expected_service_id:
            return AuthVerification(
                AuthState.WRONG_SERVICE,
                f"the authorization names service '{token.service_id}', not "
                f"'{expected_service_id}'",
                service_id=token.service_id,
                authorization_id=token.authorization_id,
            )

        if expected is not None:
            expected_digest = (
                expected.digest if isinstance(expected, RequestFingerprint) else fingerprint_of(expected).digest
            )
            if not hmac.compare_digest(expected_digest, token.fingerprint or ""):
                return AuthVerification(
                    AuthState.WRONG_PARAMETERS,
                    "the authorization is bound to different transaction parameters than "
                    "the transaction being signed",
                    service_id=token.service_id,
                    authorization_id=token.authorization_id,
                )

        try:
            issued = _parse_iso(token.issued_at)
            expires = _parse_iso(token.expires_at)
        except (ValueError, TypeError):
            return AuthVerification(
                AuthState.MALFORMED,
                "the authorization has unparseable timestamps",
                service_id=token.service_id,
                authorization_id=token.authorization_id,
            )

        now = self._clock()
        if now < issued - timedelta(seconds=5):
            return AuthVerification(
                AuthState.NOT_YET_VALID,
                "the authorization is not valid yet",
                service_id=token.service_id,
                authorization_id=token.authorization_id,
            )
        if now > expires:
            return AuthVerification(
                AuthState.EXPIRED,
                f"the authorization expired at {token.expires_at}",
                service_id=token.service_id,
                authorization_id=token.authorization_id,
            )
        if not token.nonce:
            return AuthVerification(
                AuthState.MALFORMED,
                "the authorization carries no nonce",
                service_id=token.service_id,
                authorization_id=token.authorization_id,
            )
        try:
            revoked = self._revocations.is_revoked(token.authorization_id)
            if not revoked:
                if consume:
                    consumed_ok = self._replay.consume(token.nonce, expires.timestamp())
                else:
                    consumed_ok = not self._replay.is_consumed(token.nonce)
        except StateStoreError:
            # A durable-state failure must fail closed: we cannot prove the nonce
            # is unspent, so we refuse rather than assume it is unused.
            return AuthVerification(
                AuthState.STATE_STORE_UNAVAILABLE,
                "the authorization state store is unavailable; refusing to validate",
                service_id=token.service_id,
                authorization_id=token.authorization_id,
            )
        if revoked:
            return AuthVerification(
                AuthState.REVOKED,
                "the authorization has been revoked",
                service_id=token.service_id,
                authorization_id=token.authorization_id,
            )
        if not consumed_ok:
            return AuthVerification(
                AuthState.REPLAYED,
                "this authorization has already been used (nonce replay)",
                service_id=token.service_id,
                authorization_id=token.authorization_id,
            )

        return AuthVerification(
            AuthState.VALID,
            "authorization is valid for the supplied transaction parameters",
            service_id=token.service_id,
            authorization_id=token.authorization_id,
        )

    # -- maintenance --------------------------------------------------------

    def revoke(self, authorization_id: str, *, ttl_seconds: int | None = None) -> None:
        ttl = self.ttl_seconds if ttl_seconds is None else max(1, int(ttl_seconds))
        self._revocations.revoke(authorization_id, time.time() + ttl + 30)

    @property
    def replay_store(self) -> Any:
        return self._replay


def _replace_signature(auth: Authorization, signature: str) -> Authorization:
    return Authorization(
        version=auth.version,
        authorization_id=auth.authorization_id,
        decision_id=auth.decision_id,
        service_id=auth.service_id,
        key_id=auth.key_id,
        nonce=auth.nonce,
        issued_at=auth.issued_at,
        expires_at=auth.expires_at,
        fingerprint=auth.fingerprint,
        parameters=dict(auth.parameters),
        signature=signature,
    )


def parameters_from_request(
    *,
    service_id: str,
    operation: str,
    chain: str,
    asset: str,
    amount: Any,
    destination: str,
) -> dict[str, str]:
    """Build the canonical parameter set an authorization is bound to."""
    return canonical_fields(
        service_id=service_id,
        operation=operation,
        chain=chain,
        asset=asset,
        amount=amount,
        destination=destination,
    )
