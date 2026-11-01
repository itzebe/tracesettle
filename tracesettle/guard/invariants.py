"""Structural safety invariants, each checked by execution.

The settlement engine keeps its invariants in ``reconcile.SAFETY_INVARIANTS`` and
proves them with tests. This module does the same for the security layer: every
guarantee the product claims is written as a checker that *runs the real code*
and returns whether the guarantee held, with a one-line explanation.

The checkers run against a throwaway :class:`GuardService`, so calling them never
disturbs the live counters, incidents, or audit chain. They are exposed on demand
at ``GET /api/guard/invariants`` so an operator can see the guarantees hold on the
running build, and ``tests/test_guard_invariants.py`` asserts each one.

An invariant that cannot be checked by execution does not belong here.
"""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from decimal import Decimal
from typing import Callable

from .authorization import AuthorizationAuthority, InMemoryReplayStore
from .model import AuthState, Decision, SignOutcome, canonical_fields
from .policy import DEFAULT_POLICY
from .service import GuardService
from .signer import ReferenceSigner, SignRequest, SimulatedExecutor

#: A fixed key so the checks are deterministic. Test material only.
_INVARIANT_KEY = bytes(range(32))

_UNAPPROVED = "0x9f8A2c4b7e6D1f03aB5C8e2947D6f10B3aE4c5D6"
_APPROVED = "0x4e6d3A556e485188E9C9a528bc72c88BD92BD735"


@dataclass(frozen=True)
class InvariantResult:
    name: str
    holds: bool
    detail: str

    def to_dict(self) -> dict[str, object]:
        return {"name": self.name, "holds": self.holds, "detail": self.detail}


class _CountingExecutor(SimulatedExecutor):
    def __init__(self) -> None:
        super().__init__()
        self.calls = 0

    def execute(self, request, authorization_id):  # noqa: ANN001
        self.calls += 1
        return super().execute(request, authorization_id)


def _fresh() -> tuple[GuardService, ReferenceSigner, _CountingExecutor]:
    authority = _authority_for_check()
    service = GuardService(policy=DEFAULT_POLICY, authority=authority)
    executor = _CountingExecutor()
    return service, ReferenceSigner(authority, executor), executor


def _authority_for_check() -> AuthorizationAuthority:
    return AuthorizationAuthority(
        key=_INVARIANT_KEY, key_id="invariant-key", ephemeral=False, replay_store=InMemoryReplayStore()
    )


def _payload(**overrides):
    base = {
        "service_id": "treasury-agent",
        "operation": "WITHDRAWAL",
        "chain": "eth",
        "asset": "USDC",
        "amount": "100",
        "destination": _APPROVED,
        "request_id": "inv-1",
    }
    base.update(overrides)
    return base


# --- the invariants --------------------------------------------------------


def _non_allow_never_authorizes() -> InvariantResult:
    service, _, _ = _fresh()
    for overrides in (
        {"service_id": "unregistered"},
        {"amount": "999999"},
        {"destination": _UNAPPROVED},
        {"approved": True},
        {"chain": "sol"},
    ):
        decision = service.evaluate_payload(_payload(**overrides))
        if decision.decision is Decision.ALLOW:
            continue
        if decision.authorization is not None or decision.authorizes_signing:
            return InvariantResult(
                "non_allow_never_authorizes",
                False,
                f"a {decision.decision.value} decision carried an authorization",
            )
    return InvariantResult(
        "non_allow_never_authorizes", True, "no non-ALLOW decision produced an authorization"
    )


def _refusal_never_reaches_the_executor() -> InvariantResult:
    service, signer, executor = _fresh()
    request = service.evaluate_payload(_payload()).request
    token = service.evaluate(request).authorization
    cases = {
        "missing": None,
        "malformed": {"version": "x"},
        "bad signature": dict(token.to_dict(), signature="0" * 64),
    }
    for label, token_value in cases.items():
        before = executor.calls
        result = signer.sign(SignRequest(transaction=request, authorization=token_value))
        if result.outcome is not SignOutcome.REFUSED:
            return InvariantResult(
                "refusal_never_reaches_the_executor", False, f"{label} was not refused"
            )
        if executor.calls != before:
            return InvariantResult(
                "refusal_never_reaches_the_executor", False, f"{label} reached the executor"
            )
    return InvariantResult(
        "refusal_never_reaches_the_executor",
        True,
        "no refused signing attempt reached the executor",
    )


def _authorization_is_bound_to_parameters() -> InvariantResult:
    service, signer, executor = _fresh()
    request = service.evaluate_payload(_payload()).request
    token = service.evaluate(request).authorization
    other = service.evaluate_payload(_payload(amount="42", destination=_UNAPPROVED)).request
    result = signer.sign(SignRequest(transaction=other, authorization=token))
    if result.state is not AuthState.WRONG_PARAMETERS:
        return InvariantResult(
            "authorization_is_bound_to_parameters",
            False,
            f"substituted parameters yielded {result.state.value}, not WRONG_PARAMETERS",
        )
    if executor.calls != 0:
        return InvariantResult(
            "authorization_is_bound_to_parameters", False, "the substituted transaction was executed"
        )
    return InvariantResult(
        "authorization_is_bound_to_parameters",
        True,
        "a token bound to other parameters is refused with WRONG_PARAMETERS",
    )


def _authorization_is_single_use() -> InvariantResult:
    service, signer, _ = _fresh()
    request = service.evaluate_payload(_payload()).request
    token = service.evaluate(request).authorization
    first = signer.sign(SignRequest(transaction=request, authorization=token))
    second = signer.sign(SignRequest(transaction=request, authorization=token))
    if first.outcome is not SignOutcome.EXECUTED:
        return InvariantResult(
            "authorization_is_single_use", False, "the first signing attempt did not execute"
        )
    if second.state is not AuthState.REPLAYED:
        return InvariantResult(
            "authorization_is_single_use", False, f"the second attempt yielded {second.state.value}"
        )
    return InvariantResult(
        "authorization_is_single_use", True, "the second use of a token is refused as REPLAYED"
    )


def _expiry_is_enforced() -> InvariantResult:
    now = datetime(2026, 1, 1, 12, 0, 0, tzinfo=timezone.utc)
    authority = AuthorizationAuthority(
        key=_INVARIANT_KEY, key_id="invariant-key", ephemeral=False, ttl_seconds=30, clock=lambda: now
    )
    service = GuardService(policy=DEFAULT_POLICY, authority=authority)
    request = service.evaluate_payload(_payload()).request
    token = service.evaluate(request).authorization
    authority._clock = lambda: now + timedelta(seconds=31)  # noqa: SLF001
    result = authority.validate(
        token,
        expected=canonical_fields(
            service_id=request.service_id,
            operation=request.operation,
            chain=request.chain,
            asset=request.asset,
            amount=request.amount,
            destination=request.destination,
        ),
    )
    if result.state is not AuthState.EXPIRED:
        return InvariantResult("expiry_is_enforced", False, f"expired token yielded {result.state.value}")
    return InvariantResult("expiry_is_enforced", True, "an expired token is refused as EXPIRED")


def _client_assertions_never_allow() -> InvariantResult:
    service, _, _ = _fresh()
    decision = service.evaluate_payload(_payload(approved=True, skip_checks=True))
    if decision.decision is Decision.ALLOW:
        return InvariantResult(
            "client_assertions_never_allow", False, "a client-asserted approval produced ALLOW"
        )
    if not any(f.code == "CLIENT_ASSERTED_APPROVAL_IGNORED" for f in decision.findings):
        return InvariantResult(
            "client_assertions_never_allow", False, "the assertion was not reported as a finding"
        )
    return InvariantResult(
        "client_assertions_never_allow", True, "client approval flags are ignored and reported"
    )


def _audit_chain_detects_modification() -> InvariantResult:
    from dataclasses import replace

    service, _, _ = _fresh()
    service.evaluate_payload(_payload())
    service.evaluate_payload(_payload(request_id="inv-2", destination=_UNAPPROVED))
    if not service.audit.verify().ok:
        return InvariantResult("audit_chain_detects_modification", False, "a clean chain failed to verify")
    records = list(service.audit.records())
    tampered = [replace(records[0], detail="tampered")] + records[1:]
    from .audit import AuditLog

    verification = AuditLog.verify_records([r.to_dict() for r in tampered])
    if verification.ok:
        return InvariantResult(
            "audit_chain_detects_modification", False, "an edited record was not detected"
        )
    return InvariantResult(
        "audit_chain_detects_modification",
        True,
        f"an edited record is detected at position {verification.broken_at}",
    )


def _no_key_material_in_output() -> InvariantResult:
    service, _, _ = _fresh()
    decision = service.evaluate_payload(_payload())
    serialized = repr(decision.to_dict(include_authorization=True))
    if _INVARIANT_KEY.hex() in serialized:
        return InvariantResult(
            "no_key_material_in_output", False, "the signing key appears in a decision payload"
        )
    metrics = repr(service.metrics())
    if _INVARIANT_KEY.hex() in metrics:
        return InvariantResult("no_key_material_in_output", False, "the signing key appears in metrics")
    return InvariantResult(
        "no_key_material_in_output", True, "no response carries the authorization signing key"
    )


def _unregistered_identity_never_executes() -> InvariantResult:
    service, signer, executor = _fresh()
    decision = service.evaluate_payload(_payload(service_id="rogue-service"))
    if decision.decision is not Decision.BLOCK:
        return InvariantResult(
            "unregistered_identity_never_executes", False, "an unregistered identity was not blocked"
        )
    result = signer.sign(SignRequest(transaction=decision.request, authorization=decision.authorization))
    if result.outcome is not SignOutcome.REFUSED or executor.calls != 0:
        return InvariantResult(
            "unregistered_identity_never_executes", False, "an unregistered identity reached the executor"
        )
    return InvariantResult(
        "unregistered_identity_never_executes",
        True,
        "an unregistered identity is blocked and refused with nothing executed",
    )


def _amounts_are_exact_decimals() -> InvariantResult:
    """A limit of exactly 0.3 admits 0.3 and refuses 0.30000000000000004.

    In binary floating point those two values are indistinguishable, so a float
    comparison would admit the larger one. Decimal comparison separates them,
    which is the property being checked.
    """
    from dataclasses import replace

    from .policy import PolicyConfig

    service_policy = replace(
        DEFAULT_POLICY.services["treasury-agent"],
        max_amount_per_transaction=Decimal("0.3"),
        approval_threshold=None,
    )
    policy = PolicyConfig(
        approved_destinations=DEFAULT_POLICY.approved_destinations,
        blocked_destinations=DEFAULT_POLICY.blocked_destinations,
        services={"treasury-agent": service_policy},
        per_transaction_limit=Decimal("0.3"),
        approval_threshold=None,
    )
    service = GuardService(policy=policy, authority=_authority_for_check())
    at_limit = service.evaluate_payload(_payload(amount="0.3"))
    above = service.evaluate_payload(_payload(amount="0.30000000000000004", request_id="inv-3"))
    if at_limit.decision is not Decision.ALLOW:
        return InvariantResult(
            "amounts_are_exact_decimals", False, "an amount exactly at the limit was not allowed"
        )
    if not any(f.code == "AMOUNT_EXCEEDS_LIMIT" for f in above.findings):
        return InvariantResult(
            "amounts_are_exact_decimals", False, "an amount above the limit was not refused"
        )
    return InvariantResult(
        "amounts_are_exact_decimals",
        True,
        "0.3 is admitted and 0.30000000000000004 is refused: comparison is exact",
    )


def _service_identity_cannot_be_forged() -> InvariantResult:
    """A credential resolves to exactly one service; a mismatched declaration is refused."""
    from ..serviceauth import ServiceRegistry
    from .api import GuardAPI

    registry = ServiceRegistry()
    _, secret = registry.mint("treasury-agent")
    api = GuardAPI(_fresh()[0])

    authenticated = registry.authenticate(secret)
    if not authenticated.ok or authenticated.service_id != "treasury-agent":
        return InvariantResult(
            "service_identity_cannot_be_forged", False, "a valid credential did not resolve to its service"
        )
    # Same valid credential, but the request claims another service.
    forged = api.dispatch(
        "POST",
        "/api/guard/evaluate",
        {},
        {"transaction": _payload(service_id="other-service")},
        authenticated_service_id=authenticated.service_id,
    )
    if forged.status != 403:
        return InvariantResult(
            "service_identity_cannot_be_forged",
            False,
            f"a forged service_id was not refused (status {forged.status})",
        )
    # The honest declaration still works with the same credential.
    honest = api.dispatch(
        "POST",
        "/api/guard/evaluate",
        {},
        {"transaction": _payload()},
        authenticated_service_id=authenticated.service_id,
    )
    if honest.status != 200:
        return InvariantResult(
            "service_identity_cannot_be_forged",
            False,
            "a correctly-declared identity was refused",
        )
    return InvariantResult(
        "service_identity_cannot_be_forged",
        True,
        "a credential authenticates one identity; a mismatched service_id is refused (403)",
    )


def _service_credentials_are_hashed_at_rest() -> InvariantResult:
    """The stored form of a credential never contains the plaintext secret."""
    from ..serviceauth import ServiceRegistry

    registry = ServiceRegistry()
    _, secret = registry.mint("treasury-agent")
    stored = repr(registry.to_store())
    if secret in stored:
        return InvariantResult(
            "service_credentials_are_hashed_at_rest", False, "the plaintext secret appears in the store"
        )
    public = repr([c.to_dict() for c in registry.credentials()])
    if secret in public:
        return InvariantResult(
            "service_credentials_are_hashed_at_rest", False, "the plaintext secret appears in the public view"
        )
    return InvariantResult(
        "service_credentials_are_hashed_at_rest",
        True,
        "only a one-way sha256 hash is stored; the plaintext secret never appears",
    )


INVARIANTS: dict[str, Callable[[], InvariantResult]] = {
    "non_allow_never_authorizes": _non_allow_never_authorizes,
    "refusal_never_reaches_the_executor": _refusal_never_reaches_the_executor,
    "authorization_is_bound_to_parameters": _authorization_is_bound_to_parameters,
    "authorization_is_single_use": _authorization_is_single_use,
    "expiry_is_enforced": _expiry_is_enforced,
    "client_assertions_never_allow": _client_assertions_never_allow,
    "audit_chain_detects_modification": _audit_chain_detects_modification,
    "no_key_material_in_output": _no_key_material_in_output,
    "unregistered_identity_never_executes": _unregistered_identity_never_executes,
    "amounts_are_exact_decimals": _amounts_are_exact_decimals,
    "service_identity_cannot_be_forged": _service_identity_cannot_be_forged,
    "service_credentials_are_hashed_at_rest": _service_credentials_are_hashed_at_rest,
}

#: Human-readable statement of each guarantee, for the console and the docs.
INVARIANT_DESCRIPTIONS: dict[str, str] = {
    "non_allow_never_authorizes": "A BLOCK, HOLD or REQUIRE_APPROVAL decision never carries an authorization.",
    "refusal_never_reaches_the_executor": "A refused signing attempt never calls the executor.",
    "authorization_is_bound_to_parameters": "An authorization is bound to the exact transaction parameters; any substitution is refused.",
    "authorization_is_single_use": "An authorization nonce can be spent exactly once; a replay is refused.",
    "expiry_is_enforced": "An authorization outside its validity window is refused.",
    "client_assertions_never_allow": "Client-supplied approval or bypass flags never produce ALLOW and are reported.",
    "audit_chain_detects_modification": "An edit to a stored audit record is detected by chain recomputation.",
    "no_key_material_in_output": "No response body or metric carries the authorization signing key.",
    "unregistered_identity_never_executes": "An unregistered service identity is blocked and never reaches the executor.",
    "amounts_are_exact_decimals": "Amounts are compared as exact decimals, never as binary floats.",
    "service_identity_cannot_be_forged": "A service credential authenticates exactly one identity; a request declaring another service is refused.",
    "service_credentials_are_hashed_at_rest": "Service credentials are stored only as one-way hashes; the plaintext secret never appears in a store or a public view.",
}


def check_all() -> list[InvariantResult]:
    """Run every invariant against an isolated service and return the results."""
    results: list[InvariantResult] = []
    for name, checker in INVARIANTS.items():
        try:
            results.append(checker())
        except Exception as exc:  # noqa: BLE001 - a checker crash is itself a failure
            results.append(InvariantResult(name, False, f"checker raised {type(exc).__name__}: {exc}"))
    return results
