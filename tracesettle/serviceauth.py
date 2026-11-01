"""Per-service authentication for the guard's service-facing endpoints.

The guard's policy layer trusts the ``service_id`` a caller *declares*. That is
fine for a loopback demonstration, but it means a compromised application could
name another service and inherit its policy. This module removes that trust: a
caller presents a **service credential**, the credential is resolved to the one
service identity it was issued for, and the declared ``service_id`` must match
that identity or the request is refused.

Design rules:

* The plaintext secret is never stored. Only a SHA-256 hash is persisted, and a
  credential's secret is shown exactly once, at mint time.
* Verification is constant-time (``hmac.compare_digest``) and evaluates every
  credential, so it does not leak which credential matched or how many exist.
* A credential is bound to exactly one ``service_id``; changing the declared
  ``service_id`` cannot change the authenticated identity.
* Credentials can expire, be revoked, and be rotated. Rotation adds a new
  credential and, by default, revokes the previous one.
* Nothing here is a secret store for the *signing* key; that lives in
  :mod:`tracesettle.guard.authorization`.

Standard library only, like the rest of the project.
"""

from __future__ import annotations

import enum
import hashlib
import hmac
import json
import secrets
from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Any, Callable, Iterable

#: A credential secret must carry at least this much entropy. The mint helper
#: draws from ``secrets.token_urlsafe``; the check rejects hand-written weak
#: secrets rather than accepting a guessable one.
SECRET_MIN_BYTES = 32

_HASH_PREFIX = "sha256:"
STORE_VERSION = 1

#: Header the caller presents its service credential in.
CREDENTIAL_HEADER = "X-Service-Credential"


class ServiceAuthState(str, enum.Enum):
    """Result of authenticating a presented service credential.

    Every state other than ``OK`` is a refusal. There is no "probably fine".
    """

    OK = "OK"
    MISSING = "MISSING"
    INVALID = "INVALID"
    EXPIRED = "EXPIRED"
    REVOKED = "REVOKED"

    @property
    def ok(self) -> bool:
        return self is ServiceAuthState.OK


def _utc_now() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def _parse_iso(value: str) -> datetime:
    return datetime.strptime(value, "%Y-%m-%dT%H:%M:%SZ").replace(tzinfo=timezone.utc)


def hash_secret(secret: str) -> str:
    """Return the stored form of a secret: ``sha256:<hex>``.

    One-way, so a leaked store does not reveal any usable credential. The
    plaintext is never written anywhere by this module.
    """
    return _HASH_PREFIX + hashlib.sha256(secret.encode("utf-8")).hexdigest()


def mint_secret() -> str:
    """Generate a fresh, high-entropy credential secret (shown to the caller once)."""
    return secrets.token_urlsafe(SECRET_MIN_BYTES)


def new_credential_id() -> str:
    return f"cred_{secrets.token_hex(12)}"


@dataclass(frozen=True)
class ServiceCredential:
    """One credential issued to one service.

    ``secret_hash`` is never serialized by :meth:`to_dict`; the public view of a
    credential never contains anything that could be replayed.
    """

    credential_id: str
    service_id: str
    secret_hash: str
    created_at: str
    expires_at: str | None = None
    revoked: bool = False

    def to_dict(self) -> dict[str, Any]:
        """The safe, non-secret view of a credential."""
        return {
            "credential_id": self.credential_id,
            "service_id": self.service_id,
            "created_at": self.created_at,
            "expires_at": self.expires_at,
            "revoked": self.revoked,
        }

    def to_store(self) -> dict[str, Any]:
        """The persisted form, including the one-way hash. Never log this."""
        return {**self.to_dict(), "secret_hash": self.secret_hash}

    def is_expired(self, now: datetime) -> bool:
        if not self.expires_at:
            return False
        return _parse_iso(self.expires_at) <= now

    @classmethod
    def from_store(cls, data: dict[str, Any]) -> "ServiceCredential":
        if not isinstance(data, dict):
            raise ValueError("credential entry must be an object")
        credential_id = data.get("credential_id")
        service_id = data.get("service_id")
        secret_hash = data.get("secret_hash")
        if not isinstance(credential_id, str) or not credential_id:
            raise ValueError("credential entry is missing 'credential_id'")
        if not isinstance(service_id, str) or not service_id:
            raise ValueError("credential entry is missing 'service_id'")
        if not isinstance(secret_hash, str) or not secret_hash.startswith(_HASH_PREFIX):
            raise ValueError("credential entry has a malformed 'secret_hash'")
        expires_at = data.get("expires_at")
        if expires_at is not None and not isinstance(expires_at, str):
            raise ValueError("credential entry has a malformed 'expires_at'")
        return cls(
            credential_id=credential_id,
            service_id=service_id,
            secret_hash=secret_hash,
            created_at=str(data.get("created_at") or _utc_now()),
            expires_at=expires_at,
            revoked=bool(data.get("revoked", False)),
        )


@dataclass(frozen=True)
class AuthResult:
    """The outcome of authenticating one presented credential."""

    state: ServiceAuthState
    service_id: str | None = None
    credential_id: str | None = None

    @property
    def ok(self) -> bool:
        return self.state.ok


class ServiceRegistry:
    """Resolves service credentials to the service identity they were issued for.

    The registry holds only hashed secrets. It is the single authority for
    "which service is this caller", so a request cannot assert its own identity.
    """

    def __init__(
        self,
        credentials: Iterable[ServiceCredential] = (),
        *,
        clock: Callable[[], str] | None = None,
    ) -> None:
        self._credentials: list[ServiceCredential] = list(credentials)
        self._clock = clock or _utc_now

    # -- registration -------------------------------------------------------

    def add(
        self,
        service_id: str,
        secret: str,
        *,
        credential_id: str | None = None,
        expires_at: str | None = None,
    ) -> ServiceCredential:
        """Register a new credential for ``service_id``.

        The plaintext ``secret`` is hashed immediately and not retained. A weak
        secret (fewer than :data:`SECRET_MIN_BYTES` of entropy) is rejected.
        """
        if not service_id or not isinstance(service_id, str):
            raise ValueError("service_id must be a non-empty string")
        if not isinstance(secret, str) or len(secret.encode("utf-8")) < SECRET_MIN_BYTES:
            raise ValueError(
                f"a service secret must be at least {SECRET_MIN_BYTES} bytes of entropy"
            )
        if credential_id is not None and any(
            c.credential_id == credential_id for c in self._credentials
        ):
            raise ValueError("credential_id already exists")
        credential = ServiceCredential(
            credential_id=credential_id or new_credential_id(),
            service_id=service_id,
            secret_hash=hash_secret(secret),
            created_at=self._clock(),
            expires_at=expires_at,
        )
        self._credentials.append(credential)
        return credential

    def mint(self, service_id: str, *, expires_at: str | None = None) -> tuple[ServiceCredential, str]:
        """Mint a new credential and return ``(credential, secret)``.

        The secret is returned to the caller exactly once; only its hash is kept.
        """
        secret = mint_secret()
        credential = self.add(service_id, secret, expires_at=expires_at)
        return credential, secret

    def rotate(
        self, service_id: str, *, revoke_previous: bool = True
    ) -> tuple[ServiceCredential, str]:
        """Issue a fresh credential for ``service_id``.

        By default the service's previous active credentials are revoked, so a
        rotation does not silently leave an old secret usable. Pass
        ``revoke_previous=False`` to overlap during a cutover window.
        """
        credential, secret = self.mint(service_id)
        if revoke_previous:
            for existing in self._credentials:
                if existing.service_id == service_id and existing.credential_id != credential.credential_id:
                    self._revoke_in_place(existing.credential_id)
        return credential, secret

    def revoke(self, credential_id: str) -> bool:
        """Revoke a credential. Returns True when a credential was found."""
        return self._revoke_in_place(credential_id)

    def _revoke_in_place(self, credential_id: str) -> bool:
        for index, existing in enumerate(self._credentials):
            if existing.credential_id == credential_id:
                self._credentials[index] = ServiceCredential(
                    credential_id=existing.credential_id,
                    service_id=existing.service_id,
                    secret_hash=existing.secret_hash,
                    created_at=existing.created_at,
                    expires_at=existing.expires_at,
                    revoked=True,
                )
                return True
        return False

    # -- authentication -----------------------------------------------------

    def authenticate(self, presented: str | None) -> AuthResult:
        """Resolve a presented secret to its service identity.

        Every credential is compared (constant-time) so the work does not reveal
        which credential matched, or that none did, beyond the final state.
        """
        if not presented or not isinstance(presented, str):
            return AuthResult(ServiceAuthState.MISSING)

        candidate = hash_secret(presented)
        matches = [c for c in self._credentials if hmac.compare_digest(candidate, c.secret_hash)]
        if not matches:
            return AuthResult(ServiceAuthState.INVALID)

        now = _parse_iso(self._clock())
        valid = [c for c in matches if not c.revoked and not c.is_expired(now)]
        if valid:
            chosen = valid[0]
            return AuthResult(ServiceAuthState.OK, chosen.service_id, chosen.credential_id)
        revoked = next((c for c in matches if c.revoked), None)
        if revoked is not None:
            return AuthResult(ServiceAuthState.REVOKED, revoked.service_id, revoked.credential_id)
        expired = matches[0]
        return AuthResult(ServiceAuthState.EXPIRED, expired.service_id, expired.credential_id)

    def enabled(self) -> bool:
        """True when at least one credential is registered.

        When disabled the endpoints keep their loopback-development behaviour;
        the fail-closed startup check refuses to expose them publicly.
        """
        return bool(self._credentials)

    def credentials(self) -> tuple[ServiceCredential, ...]:
        return tuple(self._credentials)

    def credentials_for(self, service_id: str) -> tuple[ServiceCredential, ...]:
        return tuple(c for c in self._credentials if c.service_id == service_id)

    def active_service_ids(self) -> tuple[str, ...]:
        now = _parse_iso(self._clock())
        return tuple(
            sorted(
                {
                    c.service_id
                    for c in self._credentials
                    if not c.revoked and not c.is_expired(now)
                }
            )
        )

    # -- persistence --------------------------------------------------------

    def to_store(self) -> dict[str, Any]:
        return {
            "version": STORE_VERSION,
            "credentials": [c.to_store() for c in self._credentials],
        }

    @classmethod
    def from_store(cls, data: Any, *, clock: Callable[[], str] | None = None) -> "ServiceRegistry":
        """Build a registry from parsed JSON. A malformed store is a hard error."""
        if not isinstance(data, dict):
            raise ValueError("service credential store must be a JSON object")
        raw = data.get("credentials", [])
        if not isinstance(raw, list):
            raise ValueError("service credential store 'credentials' must be a list")
        return cls((ServiceCredential.from_store(entry) for entry in raw), clock=clock)

    @classmethod
    def load(cls, text: str, *, clock: Callable[[], str] | None = None) -> "ServiceRegistry":
        try:
            data = json.loads(text)
        except json.JSONDecodeError as exc:
            raise ValueError("service credential store is not valid JSON") from exc
        return cls.from_store(data, clock=clock)
