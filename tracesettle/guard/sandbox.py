"""Scoped sandbox integration so an independent judge can connect a real agent.

A judge must be able to point an agent they already operate at a *deployed*
TRACESETTLE and watch the authorization boundary decide, without a funded wallet,
a private key, a paid AI provider, or the operator's secrets. This module provides
that path honestly:

* **A scoped, short-lived credential.** Issued at ``/connect`` (or by the CLI),
  resolved against the durable guard-state store so it survives a restart and is
  honoured by every instance. Only the SHA-256 hash is stored; the secret is shown
  once. It expires, can be revoked, and carries a request cap and a rate limit.
* **A restricted sandbox policy.** The credential's identity (``sandbox-<label>``)
  is registered in the sandbox policy with a *fixed* small set of approved
  destinations and a low per-transaction limit. A judge therefore sees a genuine
  ``ALLOW`` for the approved path and a genuine ``BLOCK`` for anything else,
  because the policy really refuses it — not because a scenario was scripted.
* **A separate approval secret.** The approval authority is keyed on a *different*
  secret from the authorization key, so an agent cannot mint its own approval with
  the credential it holds for evaluation. That is the separation-of-duties the
  ``REQUIRE_APPROVAL`` path depends on.
* **Real code paths.** The decision, the transaction-bound authorization, the
  reference signer's refusal logic and the replay store are the production
  objects. The only substitution is :class:`~tracesettle.guard.signer.SimulatedExecutor`,
  which records what it was asked to do and never touches a chain. No simulated
  execution is ever given a blockchain transaction hash.

Nothing here weakens an existing control. The sandbox credential can only reach
the sandbox policy; it cannot name another service, reach the signer without a
valid authorization, or bypass a BLOCK.
"""

from __future__ import annotations

import hashlib
import hmac
import secrets
import time
from dataclasses import dataclass
from decimal import Decimal
from typing import Any

from .authorization import AuthorizationAuthority
from .policy import PolicyConfig, ServicePolicy
from .service import GuardService
from .signer import ReferenceSigner, SimulatedExecutor
from .state import StateStoreError

#: How long a sandbox credential lives. Short on purpose: it is a demonstration
#: credential, not an integration secret, and a judge can mint a fresh one.
SANDBOX_TTL_SECONDS = 3600

#: Requests one sandbox credential may make before it stops working. Bounds the
#: load a single credential can place on the free upstreams.
SANDBOX_MAX_REQUESTS = 200

#: The fixed destinations a sandbox credential's agent may pay. A judge sees
#: ``ALLOW`` for these and ``BLOCK`` for everything else, because the policy really
#: refuses it. These are synthetic placeholders, never real accounts.
SANDBOX_APPROVED_DESTINATIONS = (
    "0x1111111111111111111111111111111111111111",
    "0x2222222222222222222222222222222222222222",
)

#: A synthetic attacker destination the policy never approves.
SANDBOX_ATTACKER_DESTINATION = "0xdeadbeefdeadbeefdeadbeefdeadbeefdeadbeef"

#: The sandbox per-transaction limit and approval threshold.
SANDBOX_MAX_AMOUNT = Decimal("500")
SANDBOX_APPROVAL_THRESHOLD = Decimal("100")

#: The sandbox allows exactly these chains/assets/operations.
SANDBOX_CHAINS = frozenset({"eth", "base", "near"})
SANDBOX_ASSETS = frozenset({"USDC", "USDT", "NEAR"})
SANDBOX_OPERATIONS = frozenset({"WITHDRAWAL", "SETTLEMENT", "TRANSFER"})

#: Prefix for every sandbox service identity, so a sandbox credential can never
#: collide with an operator's real service allowlist entry.
SANDBOX_IDENTITY_PREFIX = "sandbox-"


def sandbox_service_id(label: str) -> str:
    """The service identity a sandbox credential acts as.

    Lower-cased and sanitised so it matches the guard's service-id grammar and
    can never be confused with an operator service.
    """
    slug = "".join(ch if (ch.isalnum() or ch in "._-") else "-" for ch in label.strip().lower())
    slug = slug.strip("-")[:40] or "judge"
    return f"{SANDBOX_IDENTITY_PREFIX}{slug}"


def sandbox_policy(service_id: str) -> PolicyConfig:
    """A real, enforced policy for one sandbox identity.

    It registers the sandbox identity with a fixed small allowance, exactly two
    approved destinations, and the denied placeholder. It exists so a judge can
    drive the boundary against a genuine policy, not to make any scenario pass:
    the destinations it refuses, it refuses because they are absent from the
    allowlist.
    """
    return PolicyConfig(
        policy_id="sandbox-v1",
        name="TraceSettle sandbox integration policy",
        version="1",
        approved_destinations=frozenset(SANDBOX_APPROVED_DESTINATIONS),
        blocked_destinations=frozenset({"0x000000000000000000000000000000000000dead"}),
        services={
            service_id: ServicePolicy(
                service_id=service_id,
                allowed_operations=SANDBOX_OPERATIONS,
                allowed_chains=SANDBOX_CHAINS,
                allowed_assets=SANDBOX_ASSETS,
                max_amount_per_transaction=SANDBOX_MAX_AMOUNT,
                max_amount_per_window=Decimal("2000"),
                approval_threshold=SANDBOX_APPROVAL_THRESHOLD,
            )
        },
        per_transaction_limit=SANDBOX_MAX_AMOUNT,
        window_seconds=3600,
        max_requests_per_window=SANDBOX_MAX_REQUESTS,
        max_blocked_per_window=20,
        approval_threshold=SANDBOX_APPROVAL_THRESHOLD,
        min_approvals=1,
        max_rejected_authorizations=5,
        authorization_ttl_seconds=90,
        allow_unlisted_destinations=False,
    )


# ---------------------------------------------------------------------------
# Credentials
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class SandboxCredential:
    """A minted sandbox credential. The secret is carried here, once."""

    credential_id: str
    label: str
    service_id: str
    secret: str
    approval_secret: str
    created_at: float
    expires_at: float

    def to_public_dict(self) -> dict[str, Any]:
        """The credential as a client may see it: metadata and the two secrets.

        The secrets are returned exactly once, at issue time, so the judge can
        copy them into an agent. They are never retrievable again.
        """
        return {
            "credential_id": self.credential_id,
            "label": self.label,
            "service_id": self.service_id,
            "api_credential": self.secret,
            "approval_secret": self.approval_secret,
            "created_at": self.created_at,
            "expires_at": self.expires_at,
            "ttl_seconds": int(self.expires_at - self.created_at),
            "max_requests": SANDBOX_MAX_REQUESTS,
            "note": (
                "A short-lived sandbox credential. It can only reach the sandbox policy, "
                "expires, and is revocable. The secrets are shown once and never stored in "
                "plaintext."
            ),
        }


def _hash_secret(secret: str) -> str:
    return "sha256:" + hashlib.sha256(secret.encode("utf-8")).hexdigest()


def load_master_key() -> tuple[bytes, str, bool]:
    """Load the sandbox master key from configuration, or mint an ephemeral one.

    Reads ``TRACESETTLE_SANDBOX_MASTER_KEY`` (hex or base64). When unset an
    ephemeral key is generated and reported as ephemeral: a restart then
    invalidates outstanding sandbox authorizations, which is safe and disclosed.
    The key is never logged or returned in any response body.
    """
    import base64
    import os

    raw = os.environ.get("TRACESETTLE_SANDBOX_MASTER_KEY")
    if raw:
        raw = raw.strip()
        try:
            if len(raw) == 64 and all(c in "0123456789abcdefABCDEF" for c in raw):
                key = bytes.fromhex(raw)
            else:
                key = base64.b64decode(raw, validate=True)
            if len(key) >= 32:
                return key, "sandbox-master-env", False
        except (ValueError, base64.binascii.Error):
            pass
        raise StateStoreError(
            "TRACESETTLE_SANDBOX_MASTER_KEY must be at least 32 bytes as hex or base64"
        )
    return secrets.token_bytes(32), "sandbox-master-ephemeral", True


class SandboxAuthority:
    """Mints, resolves, and revokes scoped sandbox credentials.

    Backed by the durable guard-state store, so a credential survives a restart
    and is honoured by every instance that shares the store. With no store it
    still works, but only for the lifetime of the process — reported honestly.
    """

    def __init__(
        self,
        store: Any,
        *,
        master_key: bytes | None = None,
        ttl_seconds: int = SANDBOX_TTL_SECONDS,
        max_requests: int = SANDBOX_MAX_REQUESTS,
        clock: Any = None,
    ) -> None:
        self._store = store
        #: The server-side master key from which every per-credential key is
        #: derived. It never leaves this object; when unset an ephemeral one is
        #: generated and reported, so a restart invalidates outstanding
        #: authorizations (a safe, disclosed consequence).
        if master_key is None:
            master_key, self.master_key_id, self.ephemeral = load_master_key()
        else:
            self.master_key_id = "sandbox-master"
            self.ephemeral = False
        self._master_key = master_key
        self.ttl_seconds = max(60, int(ttl_seconds))
        self.max_requests = max(1, int(max_requests))
        self._clock = clock or time.time
        #: Process-local fallback when no durable store is configured.
        self._memory: dict[str, dict[str, Any]] = {}

    @property
    def durable(self) -> bool:
        return self._store is not None

    def derive_keys(self, credential_id: str) -> tuple[bytes, bytes]:
        """Derive the (authorization, approval) keys for one credential.

        Distinct per credential, so one judge's authorizations never validate
        against another's, and distinct per purpose, so the approval key cannot be
        confused with the authorization key. Both are derived from the server-side
        master key, which the judge never sees.
        """
        auth_key = hmac.new(
            self._master_key, f"auth:{credential_id}".encode(), hashlib.sha256
        ).digest()
        approval_key = hmac.new(
            self._master_key, f"approval:{credential_id}".encode(), hashlib.sha256
        ).digest()
        return auth_key, approval_key

    def build_service(self, credential_id: str, service_id: str) -> "SandboxService":
        auth_key, approval_key = self.derive_keys(credential_id)
        # Back the replay store with the durable store when one is configured, so
        # a spent authorization nonce cannot be replayed after a restart (the
        # master key, and therefore the authorization, outlives the process when
        # it is configured rather than ephemeral).
        replay_store = None
        if self._store is not None:
            from .state import DurableReplayStore

            replay_store = DurableReplayStore(
                self._store,
                counter_retention_seconds=86400.0,
                idempotency_retention_seconds=86400.0,
            )
        return SandboxService(
            credential_id,
            service_id,
            auth_key=auth_key,
            approval_key=approval_key,
            replay_store=replay_store,
        )

    def _rows(self, *, include_inactive: bool = False) -> list[dict[str, Any]]:
        if self._store is None:
            now = self._clock()
            rows = []
            for row in self._memory.values():
                record = dict(row)
                record["expired"] = record["expires_at"] <= now
                record["active"] = not record["revoked"] and not record["expired"]
                if include_inactive or record["active"]:
                    rows.append(record)
            return rows
        return self._store.sandbox_credentials(include_inactive=include_inactive)

    def _secret_rows(self) -> list[dict[str, Any]]:
        """The stored hash material, for constant-time credential resolution."""
        if self._store is None:
            return [dict(row) for row in self._memory.values()]
        return self._store.sandbox_credential_secrets()

    def mint(self, *, label: str) -> SandboxCredential:
        """Issue a fresh scoped credential. The secrets are returned once."""
        service_id = sandbox_service_id(label)
        secret = secrets.token_urlsafe(32)
        approval_secret = secrets.token_urlsafe(32)
        credential_id = "sbx_" + secrets.token_hex(8)
        now = self._clock()
        expires_at = now + self.ttl_seconds
        if self._store is None:
            self._memory[credential_id] = {
                "credential_id": credential_id,
                "label": label[:60],
                "scope": "sandbox",
                "service_id": service_id,
                "created_at": now,
                "expires_at": expires_at,
                "revoked": False,
                "request_count": 0,
                "secret_hash": _hash_secret(secret),
                "approval_hash": _hash_secret(approval_secret),
            }
        else:
            self._store.add_sandbox_credential(
                credential_id=credential_id,
                label=label[:60],
                scope="sandbox",
                secret_hash=_hash_secret(secret),
                approval_hash=_hash_secret(approval_secret),
                service_id=service_id,
                expires_at=expires_at,
                at=now,
            )
        return SandboxCredential(
            credential_id=credential_id,
            label=label[:60],
            service_id=service_id,
            secret=secret,
            approval_secret=approval_secret,
            created_at=now,
            expires_at=expires_at,
        )

    def list(self, *, include_inactive: bool = False) -> list[dict[str, Any]]:
        return self._rows(include_inactive=include_inactive)

    def revoke(self, credential_id: str) -> bool:
        if self._store is None:
            row = self._memory.get(credential_id)
            if row is None:
                return False
            row["revoked"] = True
            return True
        return self._store.revoke_sandbox_credential(credential_id)

    def resolve(self, presented: str | None) -> tuple[dict[str, Any] | None, str]:
        """Resolve a presented credential to its active record, or a refusal reason.

        Every failure is a refusal with a stable reason code. The comparison is
        constant-time and evaluates every active credential, so it does not leak
        which credential matched or how many exist. The secret is never echoed.
        """
        if not presented:
            return None, "MISSING"
        presented_hash = _hash_secret(presented)
        now = self._clock()
        match_id: str | None = None
        # Compare against every stored hash, never breaking early, so the work does
        # not reveal which credential matched or how many exist.
        for row in self._secret_rows():
            stored = row.get("secret_hash")
            if stored is not None and hmac.compare_digest(stored, presented_hash):
                match_id = row["credential_id"]
        if match_id is None:
            return None, "INVALID"
        for row in self._rows(include_inactive=True):
            if row["credential_id"] != match_id:
                continue
            if row["revoked"]:
                return None, "REVOKED"
            if row["expires_at"] <= now:
                return None, "EXPIRED"
            if row["request_count"] >= self.max_requests:
                return None, "EXHAUSTED"
            return row, "OK"
        return None, "INVALID"

    def resolve_approval(self, credential_id: str, presented: str | None) -> bool:
        """Whether ``presented`` is this credential's approval secret.

        The approval secret is distinct from the API credential, so an agent
        cannot mint its own approval with the credential it evaluates with. This
        is the separation-of-duties the REQUIRE_APPROVAL path relies on.
        """
        if not presented:
            return False
        presented_hash = _hash_secret(presented)
        stored = None
        for row in self._secret_rows():
            if row["credential_id"] == credential_id:
                stored = row.get("approval_hash")
        if not stored:
            return False
        return hmac.compare_digest(stored, presented_hash)

    def touch(self, credential_id: str) -> None:
        if self._store is None:
            row = self._memory.get(credential_id)
            if row is not None:
                row["request_count"] = int(row.get("request_count", 0)) + 1
            return
        try:
            self._store.touch_sandbox_credential(credential_id)
        except StateStoreError:
            # A counter is diagnostic; a failure must not fail a valid request.
            return


# ---------------------------------------------------------------------------
# The sandbox service
# ---------------------------------------------------------------------------


class SandboxService:
    """A per-credential GuardService bound to the sandbox policy.

    Each credential gets its own authorization authority (keyed on a per-sandbox
    secret derived from the credential id) and its own executor, so one judge's
    receipts and authorizations are never visible to another. The signer and the
    replay store are the real production objects.
    """

    def __init__(
        self,
        credential_id: str,
        service_id: str,
        *,
        auth_key: bytes,
        approval_key: bytes,
        replay_store: Any = None,
    ) -> None:
        from ..near.agent_wrapper import AgentAuthorizationWrapper
        from ..near.approval import ApprovalAuthority

        self.credential_id = credential_id
        self.service_id = service_id
        self.executor = SimulatedExecutor()
        self.authority = AuthorizationAuthority(
            key=auth_key,
            key_id=f"sandbox-{credential_id}",
            replay_store=replay_store,
            ttl_seconds=sandbox_policy(service_id).authorization_ttl_seconds,
        )
        # The approval authority is keyed on a *different* secret from the
        # authorization key, so the credential an agent holds for evaluation can
        # never mint its own approval. A judge obtains an approval only through
        # the approval-secret path, which is separation of duties.
        self.approval_authority = ApprovalAuthority(
            key=approval_key, key_id=f"sandbox-approval-{credential_id}"
        )
        self.service = GuardService(
            policy=sandbox_policy(service_id),
            authority=self.authority,
            approval_authority=self.approval_authority,
        )
        self.service._signer = ReferenceSigner(self.authority, executor=self.executor)  # noqa: SLF001
        self.wrapper = AgentAuthorizationWrapper(self.service)

    def decide(self, payload: dict[str, Any], *, approval: Any = None) -> dict[str, Any]:
        """Evaluate one proposed transaction and return the decision plus evidence.

        ``approval`` is a payload-bound human approval. It is honoured only for a
        REQUIRE_APPROVAL decision and only when bound to this exact payload, so it
        can raise that decision to ALLOW. It can never override a BLOCK.
        """
        decision = self.service.evaluate_payload(
            payload, simulated=True, approval=approval
        )
        return decision.to_dict(include_authorization=True)

    def approval_request(self, payload: dict[str, Any]) -> dict[str, Any]:
        """Build the payload-bound approval a human must give for this transaction.

        Returns the request the judge's approval secret signs, so the judge can
        demonstrate that only an approval bound to *these* parameters can raise a
        REQUIRE_APPROVAL decision to ALLOW.
        """
        from .service import RequestValidationError, request_from_payload

        try:
            transaction = request_from_payload(payload, simulated=True)
        except RequestValidationError as exc:
            return {"error": str(exc), "status": 400}
        fingerprint = self.service.approval_payload_fingerprint(transaction)
        return {
            "service_id": transaction.service_id,
            "operation": transaction.operation,
            "chain": transaction.chain,
            "asset": transaction.asset,
            "amount": transaction.amount_raw,
            "destination": transaction.destination,
            "payload_fingerprint": fingerprint,
            "summary": (
                f"{transaction.operation} {transaction.amount_raw} {transaction.asset} to "
                f"{transaction.destination}"
            ),
        }

    def approve(self, payload: dict[str, Any], *, approver: str) -> Any:
        """Mint a payload-bound approval for a REQUIRE_APPROVAL transaction.

        Only the server holds this key, and the caller must present the separate
        approval secret, so an agent cannot self-approve.
        """
        from .service import RequestValidationError, request_from_payload

        try:
            transaction = request_from_payload(payload, simulated=True)
        except RequestValidationError as exc:
            return {"error": str(exc), "status": 400}
        fingerprint = self.service.approval_payload_fingerprint(transaction)
        request = self.approval_authority.build_request(
            service_id=transaction.service_id,
            operation=transaction.operation,
            chain=transaction.chain,
            asset=transaction.asset,
            amount=transaction.amount_raw,
            destination=transaction.destination,
            payload_fingerprint=fingerprint,
            summary=(
                f"{transaction.operation} {transaction.amount_raw} {transaction.asset} to "
                f"{transaction.destination}"
            ),
        )
        approval = self.approval_authority.approve(request, approver=approver)
        return approval.to_dict()

    def execute(
        self,
        payload: dict[str, Any],
        authorization: Any,
        *,
        approval: Any = None,
    ) -> dict[str, Any]:
        """Present an authorization to the signing boundary.

        The signer independently re-derives the binding from the *actual*
        transaction and refuses a token minted for different parameters, an
        expired token, or a replayed nonce. The decision itself happened at
        evaluate time; a BLOCK never minted an authorization, so there is nothing
        to present. ``approval`` is accepted for parity but is not consulted here
        (an approval is single-use and was consumed when the ALLOW decision was
        produced); the signer is the security boundary.
        """
        from .service import RequestValidationError, request_from_payload
        from .signer import SignRequest

        try:
            transaction = request_from_payload(payload, simulated=True)
        except RequestValidationError as exc:
            return {"error": str(exc), "status": 400}
        result = self.service.sign(
            SignRequest(
                transaction=transaction,
                authorization=authorization,
                expected_service_id=self.service_id,
            )
        )
        return {
            "sign_result": result.to_dict(),
            "executor_calls": len(self.executor.receipts()),
            "receipts": [r.to_dict() for r in self.executor.receipts()],
            "broadcast": False,
            "simulated": True,
            "note": (
                "The executor is a simulated stand-in: it records the transaction it was "
                "asked to execute and never touches a chain. No blockchain transaction "
                "hash is produced."
            ),
        }
