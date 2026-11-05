"""Human approval for a WARN decision, bound to the exact transaction.

When the wrapper returns ``REQUIRE_APPROVAL`` the agent must not sign until a
human has approved *this* transaction. The failure mode this module exists to
prevent is an approval that outlives the transaction it approved: a human is
shown "pay alice.testnet 1 NEAR", approves, and the agent then signs a transfer
of 100 NEAR to an attacker. Binding the approval to the transaction's *payload
fingerprint* makes any change to the receiver, amount, method, arguments or
signer a different payload, so the approval no longer applies.

An approval is
* minted only by an explicit human decision (never by the agent),
* HMAC-signed, so it cannot be forged without the key,
* bound to one payload fingerprint and one service identity,
* single-use, and
* time-limited.

The agent cannot approve its own request: :class:`HumanApprovalChannel` is the
only thing that can mint an approval, and the agent has no reference to it. The
default channel refuses everything, so an agent that never wires a real human
channel gets a refusal rather than a silent pass.
"""

from __future__ import annotations

import enum
import hashlib
import hmac
import secrets
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from typing import Any, Callable, Protocol

from ..guard.model import RequestFingerprint, fingerprint_of

APPROVAL_VERSION = "1"
DEFAULT_APPROVAL_TTL_SECONDS = 300

#: A domain prefix folded into the signed payload so an approval signature can
#: never be replayed as a guard authorization signature, even if a deployment
#: used the same key for both.
_SIGNING_DOMAIN = b"tracesettle-approval:v1:"


def _now() -> datetime:
    return datetime.now(timezone.utc)


def _iso(dt: datetime) -> str:
    return dt.strftime("%Y-%m-%dT%H:%M:%SZ")


def _parse_iso(value: str) -> datetime:
    return datetime.strptime(value, "%Y-%m-%dT%H:%M:%SZ").replace(tzinfo=timezone.utc)


class ApprovalState(str, enum.Enum):
    """Result of validating a human approval. Every non-VALID state is a refusal."""

    VALID = "VALID"
    MISSING = "MISSING"
    MALFORMED = "MALFORMED"
    BAD_SIGNATURE = "BAD_SIGNATURE"
    EXPIRED = "EXPIRED"
    #: The approval was for a different transaction payload. This is the case a
    #: change to the receiver, amount, method, arguments or signer produces.
    WRONG_PAYLOAD = "WRONG_PAYLOAD"
    WRONG_SERVICE = "WRONG_SERVICE"
    REPLAYED = "REPLAYED"

    @property
    def valid(self) -> bool:
        return self is ApprovalState.VALID


@dataclass(frozen=True)
class ApprovalRequest:
    """A pending approval, describing exactly what a human is being asked to approve."""

    request_id: str
    service_id: str
    operation: str
    chain: str
    asset: str
    amount: str
    destination: str
    payload_fingerprint: str
    summary: str
    created_at: str

    def to_dict(self) -> dict[str, Any]:
        return {
            "request_id": self.request_id,
            "service_id": self.service_id,
            "operation": self.operation,
            "chain": self.chain,
            "asset": self.asset,
            "amount": self.amount,
            "destination": self.destination,
            "payload_fingerprint": self.payload_fingerprint,
            "summary": self.summary,
            "created_at": self.created_at,
        }


@dataclass(frozen=True)
class Approval:
    """A signed, payload-bound, single-use human approval."""

    version: str
    approval_id: str
    request_id: str
    service_id: str
    key_id: str
    approver: str
    nonce: str
    issued_at: str
    expires_at: str
    payload_fingerprint: str
    signature: str

    def signing_payload(self) -> bytes:
        body = {
            "version": self.version,
            "approval_id": self.approval_id,
            "request_id": self.request_id,
            "service_id": self.service_id,
            "key_id": self.key_id,
            "approver": self.approver,
            "nonce": self.nonce,
            "issued_at": self.issued_at,
            "expires_at": self.expires_at,
            "payload_fingerprint": self.payload_fingerprint,
        }
        import json

        return _SIGNING_DOMAIN + json.dumps(
            body, sort_keys=True, separators=(",", ":")
        ).encode("utf-8")

    def to_dict(self) -> dict[str, Any]:
        return {
            "version": self.version,
            "approval_id": self.approval_id,
            "request_id": self.request_id,
            "service_id": self.service_id,
            "key_id": self.key_id,
            "approver": self.approver,
            "nonce": self.nonce,
            "issued_at": self.issued_at,
            "expires_at": self.expires_at,
            "payload_fingerprint": self.payload_fingerprint,
            "signature": self.signature,
        }

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> "Approval":
        return cls(
            version=str(data.get("version", "")),
            approval_id=str(data.get("approval_id", "")),
            request_id=str(data.get("request_id", "")),
            service_id=str(data.get("service_id", "")),
            key_id=str(data.get("key_id", "")),
            approver=str(data.get("approver", "")),
            nonce=str(data.get("nonce", "")),
            issued_at=str(data.get("issued_at", "")),
            expires_at=str(data.get("expires_at", "")),
            payload_fingerprint=str(data.get("payload_fingerprint", "")),
            signature=str(data.get("signature", "")),
        )


@dataclass(frozen=True)
class ApprovalVerification:
    state: ApprovalState
    detail: str
    approver: str | None = None
    approval_id: str | None = None

    @property
    def valid(self) -> bool:
        return self.state.valid

    def to_dict(self) -> dict[str, Any]:
        return {
            "state": self.state.value,
            "valid": self.valid,
            "detail": self.detail,
            "approver": self.approver,
            "approval_id": self.approval_id,
        }


class ApprovalReplayStore(Protocol):
    def consume(self, nonce: str, expires_at: float) -> bool: ...
    def is_consumed(self, nonce: str) -> bool: ...


class _InMemoryApprovalReplay:
    """A bounded, single-use nonce store for approvals."""

    def __init__(self, *, max_entries: int = 8192) -> None:
        self._consumed: dict[str, float] = {}
        self._max = max_entries

    def consume(self, nonce: str, expires_at: float) -> bool:
        self._prune()
        if nonce in self._consumed:
            return False
        self._consumed[nonce] = expires_at
        return True

    def is_consumed(self, nonce: str) -> bool:
        self._prune()
        return nonce in self._consumed

    def _prune(self) -> None:
        import time

        now = time.time()
        stale = [n for n, exp in self._consumed.items() if exp < now]
        for n in stale:
            self._consumed.pop(n, None)
        if len(self._consumed) > self._max:
            for n in sorted(self._consumed, key=lambda k: self._consumed[k])[
                : len(self._consumed) - self._max
            ]:
                self._consumed.pop(n, None)


class ApprovalAuthority:
    """Mints and validates payload-bound human approvals.

    Kept separate from the guard's :class:`~tracesettle.guard.authorization.AuthorizationAuthority`
    on purpose: an approval is a *human* decision about a payload, an
    authorization is the *machine* decision that the payload passed the controls.
    Conflating them would let either stand in for the other.
    """

    def __init__(
        self,
        *,
        key: bytes,
        key_id: str = "approval",
        replay_store: ApprovalReplayStore | None = None,
        ttl_seconds: int = DEFAULT_APPROVAL_TTL_SECONDS,
        clock: Callable[[], datetime] | None = None,
    ) -> None:
        self._key = key
        self.key_id = key_id
        self._replay = replay_store or _InMemoryApprovalReplay()
        self.ttl_seconds = max(1, int(ttl_seconds))
        self._clock = clock or _now

    def build_request(
        self,
        *,
        service_id: str,
        operation: str,
        chain: str,
        asset: str,
        amount: str,
        destination: str,
        payload_fingerprint: str,
        summary: str,
    ) -> ApprovalRequest:
        return ApprovalRequest(
            request_id=f"apr_{secrets.token_hex(12)}",
            service_id=service_id,
            operation=operation,
            chain=chain,
            asset=asset,
            amount=amount,
            destination=destination,
            payload_fingerprint=payload_fingerprint,
            summary=summary,
            created_at=_iso(self._clock()),
        )

    def approve(
        self, request: ApprovalRequest, *, approver: str, ttl_seconds: int | None = None
    ) -> Approval:
        """Mint an approval. Only a human channel calls this, never the agent."""
        approver = approver.strip()
        if not approver:
            raise ValueError("an approval must name the human who approved it")
        now = self._clock()
        ttl = self.ttl_seconds if ttl_seconds is None else max(1, int(ttl_seconds))
        approval = Approval(
            version=APPROVAL_VERSION,
            approval_id=f"apv_{secrets.token_hex(12)}",
            request_id=request.request_id,
            service_id=request.service_id,
            key_id=self.key_id,
            approver=approver,
            nonce=secrets.token_urlsafe(24),
            issued_at=_iso(now),
            expires_at=_iso(now + timedelta(seconds=ttl)),
            payload_fingerprint=request.payload_fingerprint,
            signature="",
        )
        return _replace_signature(approval, self._sign(approval))

    def _sign(self, approval: Approval) -> str:
        return hmac.new(self._key, approval.signing_payload(), hashlib.sha256).hexdigest()

    def validate(
        self,
        token: Approval | dict[str, Any] | None,
        *,
        expected_payload_fingerprint: str,
        expected_service_id: str | None = None,
        consume: bool = False,
    ) -> ApprovalVerification:
        """Validate an approval against the payload that is about to be signed."""
        if token is None:
            return ApprovalVerification(ApprovalState.MISSING, "no approval was supplied")
        try:
            approval = token if isinstance(token, Approval) else Approval.from_dict(token)
        except (AttributeError, TypeError, ValueError) as exc:
            return ApprovalVerification(ApprovalState.MALFORMED, f"approval could not be read: {exc}")

        if approval.version != APPROVAL_VERSION:
            return ApprovalVerification(ApprovalState.MALFORMED, "unknown approval version")
        if not hmac.compare_digest(approval.key_id, self.key_id):
            return ApprovalVerification(ApprovalState.BAD_SIGNATURE, "approval was signed with an unknown key")
        expected_sig = self._sign(approval)
        if not hmac.compare_digest(expected_sig, approval.signature):
            return ApprovalVerification(ApprovalState.BAD_SIGNATURE, "the approval signature does not verify")

        if expected_service_id is not None and approval.service_id != expected_service_id:
            return ApprovalVerification(
                ApprovalState.WRONG_SERVICE,
                f"the approval is for service '{approval.service_id}', not '{expected_service_id}'",
                approval.approver,
                approval.approval_id,
            )

        # The binding. Any change to the payload changes its fingerprint, so a
        # stale approval for a different receiver/amount/method/signer fails here.
        if not hmac.compare_digest(approval.payload_fingerprint, expected_payload_fingerprint):
            return ApprovalVerification(
                ApprovalState.WRONG_PAYLOAD,
                "the approval is bound to a different transaction payload; the transaction "
                "changed after it was approved",
                approval.approver,
                approval.approval_id,
            )

        now = self._clock()
        try:
            expires = _parse_iso(approval.expires_at)
        except ValueError:
            return ApprovalVerification(ApprovalState.MALFORMED, "the approval expiry is not a timestamp")
        if now > expires:
            return ApprovalVerification(
                ApprovalState.EXPIRED, "the approval has expired", approval.approver, approval.approval_id
            )

        if consume:
            if not self._replay.consume(approval.nonce, expires.timestamp()):
                return ApprovalVerification(
                    ApprovalState.REPLAYED,
                    "this approval has already been used",
                    approval.approver,
                    approval.approval_id,
                )

        return ApprovalVerification(
            ApprovalState.VALID,
            f"approved by {approval.approver}",
            approval.approver,
            approval.approval_id,
        )


def _replace_signature(approval: Approval, signature: str) -> Approval:
    from dataclasses import replace

    return replace(approval, signature=signature)


class HumanApprovalChannel(Protocol):
    """The seam a real human decision comes through.

    An implementation shows the :class:`ApprovalRequest` to a human (a console
    prompt, a chat approval, a hardware confirmation) and returns the approver's
    name, or ``None`` to deny. The agent holds no implementation of this and
    cannot call it.
    """

    def request_approval(self, request: ApprovalRequest) -> str | None: ...


class DenyAllChannel:
    """The safe default: no human is wired, so nothing is ever approved."""

    def request_approval(self, request: ApprovalRequest) -> str | None:
        return None


class CallbackChannel:
    """A channel backed by a caller-supplied function.

    Used by the CLI (which prompts on stdin) and by tests (which return a fixed
    approver). The function receives the :class:`ApprovalRequest` and returns an
    approver name or ``None``.
    """

    def __init__(self, decide: Callable[[ApprovalRequest], str | None]) -> None:
        self._decide = decide

    def request_approval(self, request: ApprovalRequest) -> str | None:
        return self._decide(request)


def payload_fingerprint(fields: dict[str, Any]) -> RequestFingerprint:
    """A canonical fingerprint over the exact payload a human is approving.

    String fields are taken verbatim (no case folding) because a fingerprint is
    compared for *equality*, not matched against a list; a case change is a
    change to the payload and must invalidate the approval.
    """
    normalized = {str(k): str(v) for k, v in fields.items()}
    return fingerprint_of(normalized)
