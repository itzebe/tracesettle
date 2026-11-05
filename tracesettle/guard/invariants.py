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
from .state import StateStoreError

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


def _configured_audit_log_is_persistent() -> InvariantResult:
    """A configured audit-log path must survive construction and be written.

    An empty ``AuditLog`` is falsy, so a truthiness guard would swap a configured
    persistent log for an in-memory one on every fresh start, silently discarding
    durable audit evidence. This runs the real ``GuardService`` constructor with
    an empty, path-backed log and checks the record lands on disk.
    """
    import tempfile
    from pathlib import Path

    from .audit import AuditLog

    with tempfile.TemporaryDirectory() as directory:
        path = Path(directory) / "audit.jsonl"
        audit = AuditLog(path=path)
        if audit:
            return InvariantResult(
                "configured_audit_log_is_persistent", False, "a fresh path-backed log was truthy"
            )
        service = GuardService(policy=DEFAULT_POLICY, audit=audit)
        if service.audit is not audit:
            return InvariantResult(
                "configured_audit_log_is_persistent",
                False,
                "the configured audit log was replaced during construction",
            )
        service.audit.append(event_type="E", actor="invariant", outcome="OK", detail="probe")
        if not path.exists() or len(AuditLog(path=path).read_file()) != 1:
            return InvariantResult(
                "configured_audit_log_is_persistent", False, "the record was not persisted"
            )
    return InvariantResult(
        "configured_audit_log_is_persistent",
        True,
        "a configured audit-log path is kept and the record is written to disk",
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


def _durable_nonce_is_single_use_across_restart() -> InvariantResult:
    """A spent nonce stays spent when the process is replaced."""
    import tempfile

    from .state import DurableReplayStore, GuardStateStore

    with tempfile.TemporaryDirectory() as directory:
        path = f"{directory}/state.db"
        # First "process": issue a token and spend it.
        store = GuardStateStore(path)
        authority = AuthorizationAuthority(
            key=_INVARIANT_KEY,
            key_id="invariant-key",
            ephemeral=False,
            replay_store=DurableReplayStore(store),
        )
        service = GuardService(policy=DEFAULT_POLICY, authority=authority)
        request = service.evaluate_payload(_payload()).request
        token = service.evaluate(request).authorization
        signer = ReferenceSigner(authority)
        first = signer.sign(SignRequest(transaction=request, authorization=token))
        store.close()
        if first.outcome is not SignOutcome.EXECUTED:
            return InvariantResult(
                "durable_nonce_is_single_use_across_restart",
                False,
                "the first signing attempt did not execute",
            )
        # Second "process": reopen the same database and replay the same token.
        store2 = GuardStateStore(path)
        authority2 = AuthorizationAuthority(
            key=_INVARIANT_KEY,
            key_id="invariant-key",
            ephemeral=False,
            replay_store=DurableReplayStore(store2),
        )
        signer2 = ReferenceSigner(authority2)
        second = signer2.sign(SignRequest(transaction=request, authorization=token))
        store2.close()
        if second.state is not AuthState.REPLAYED:
            return InvariantResult(
                "durable_nonce_is_single_use_across_restart",
                False,
                f"a replay after restart yielded {second.state.value}, not REPLAYED",
            )
    return InvariantResult(
        "durable_nonce_is_single_use_across_restart",
        True,
        "a token spent before a restart is refused as REPLAYED after it",
    )


def _durable_counters_survive_restart() -> InvariantResult:
    """A window-volume counter written before a restart is still enforced after it."""
    import tempfile

    from .policy import PolicyConfig, ServicePolicy
    from .state import GuardStateStore

    # A policy whose window limit is reachable in two ordinary requests, so the
    # check does not depend on the default per-transaction limit or threshold.
    policy = PolicyConfig(
        approved_destinations=DEFAULT_POLICY.approved_destinations,
        blocked_destinations=DEFAULT_POLICY.blocked_destinations,
        services={
            "treasury-agent": ServicePolicy(
                service_id="treasury-agent",
                allowed_operations=frozenset({"WITHDRAWAL"}),
                allowed_chains=frozenset({"eth"}),
                allowed_assets=frozenset({"USDC"}),
                max_amount_per_transaction=Decimal("10000"),
                max_amount_per_window=Decimal("1000"),
                approval_threshold=None,
            )
        },
        per_transaction_limit=Decimal("10000"),
        window_seconds=3600,
        max_requests_per_window=100,
        max_blocked_per_window=100,
        approval_threshold=None,
        max_rejected_authorizations=100,
        allow_unlisted_destinations=False,
    )
    with tempfile.TemporaryDirectory() as directory:
        path = f"{directory}/state.db"
        store = GuardStateStore(path)
        service = GuardService(policy=policy, state_store=store)
        first = service.evaluate_payload(_payload(amount="600", request_id="inv-a"))
        store.close()
        if first.decision is not Decision.ALLOW:
            return InvariantResult(
                "durable_counters_survive_restart",
                False,
                f"the first request was {first.decision.value}, so no volume was recorded",
            )
        # A fresh process must still see the accumulated volume and hold.
        store2 = GuardStateStore(path)
        service2 = GuardService(policy=policy, state_store=store2)
        decision = service2.evaluate_payload(_payload(amount="600", request_id="inv-b"))
        store2.close()
        if decision.decision is Decision.ALLOW:
            return InvariantResult(
                "durable_counters_survive_restart",
                False,
                "the window-volume counter reset on restart and allowed an over-limit request",
            )
    return InvariantResult(
        "durable_counters_survive_restart",
        True,
        "window volume accumulated before a restart still holds a request after it",
    )


def _state_store_failure_fails_closed() -> InvariantResult:
    """A broken state store turns evaluation into HOLD, never ALLOW."""
    import tempfile

    from .state import GuardStateStore

    with tempfile.TemporaryDirectory() as directory:
        store = GuardStateStore(f"{directory}/state.db")
        service = GuardService(policy=DEFAULT_POLICY, state_store=store)
        store.close()  # every later read/write raises StateStoreError
        decision = service.evaluate_payload(_payload())
        if decision.decision is Decision.ALLOW or decision.authorization is not None:
            return InvariantResult(
                "state_store_failure_fails_closed",
                False,
                "a broken state store still produced an authorization",
            )
        if decision.decision is not Decision.HOLD:
            return InvariantResult(
                "state_store_failure_fails_closed",
                False,
                f"a broken state store produced {decision.decision.value}, not HOLD",
            )
    return InvariantResult(
        "state_store_failure_fails_closed",
        True,
        "an unreadable state store yields HOLD with no authorization",
    )


def _learning_loop_only_tightens_and_survives_restart() -> InvariantResult:
    """A learned safeguard tightens a later decision and never relaxes one."""
    import tempfile

    from .safeguards import SafeguardStore

    with tempfile.TemporaryDirectory() as directory:
        path = f"{directory}/safeguards.db"
        store = SafeguardStore(path)
        service = GuardService(policy=DEFAULT_POLICY, safeguard_store=store)

        # A first request to an unapproved destination teaches a lesson.
        first = service.evaluate_payload(_payload(request_id="learn-1", destination=_UNAPPROVED))
        if first.learned_safeguard is None:
            store.close()
            return InvariantResult(
                "learning_loop_only_tightens",
                False,
                "a refused unapproved-destination request taught no safeguard",
            )
        # A later request, larger than the one that tripped the lesson, is now
        # tightened above the operator's own policy outcome.
        second = service.evaluate_payload(_payload(request_id="learn-2", amount="5000"))
        if not second.influenced_by_learning:
            store.close()
            return InvariantResult(
                "learning_loop_only_tightens",
                False,
                "a learned safeguard did not tighten a later decision",
            )
        if second.decision is Decision.ALLOW or second.authorization is not None:
            store.close()
            return InvariantResult(
                "learning_loop_only_tightens",
                False,
                "a learned safeguard still produced an ALLOW with an authorization",
            )
        store.close()

        # The lesson is durable: a fresh service on the same store still applies it.
        reopened = SafeguardStore(path)
        restarted = GuardService(policy=DEFAULT_POLICY, safeguard_store=reopened)
        after_restart = restarted.evaluate_payload(_payload(request_id="learn-3", amount="5000"))
        holds = after_restart.influenced_by_learning and after_restart.decision is not Decision.ALLOW
        reopened.close()
        if not holds:
            return InvariantResult(
                "learning_loop_only_tightens",
                False,
                "a safeguard did not survive a restart",
            )
    return InvariantResult(
        "learning_loop_only_tightens",
        True,
        "a learned safeguard tightens later decisions and survives a restart",
    )


def _learning_never_relaxes_the_operators_policy() -> InvariantResult:
    """A safeguard can only ever make a decision stricter, never weaker."""
    from .learning import apply_safeguards
    from .safeguards import DIM_REQUIRE_APPROVAL_ABOVE, DIM_REQUIRE_VERIFICATION, Safeguard
    from .service import request_from_payload

    request = request_from_payload(_payload(amount="100"))
    # Even a permissive-looking safeguard (a threshold far above the amount) must
    # not change an outcome, and a verification safeguard can only HOLD.
    below = Safeguard(
        safeguard_id="sg_below",
        service_id="treasury-agent",
        asset="USDC",
        dimension=DIM_REQUIRE_APPROVAL_ABOVE,
        threshold=Decimal("1000000"),
        reason_code="TEST",
        reason="test",
        created_at=0.0,
    )
    verify = Safeguard(
        safeguard_id="sg_verify",
        service_id="treasury-agent",
        asset="USDC",
        dimension=DIM_REQUIRE_VERIFICATION,
        threshold=None,
        reason_code="TEST",
        reason="test",
        created_at=0.0,
    )
    below_app = apply_safeguards(request, (below,))
    verify_app = apply_safeguards(request, (verify,))
    if below_app.applied:
        return InvariantResult(
            "learning_never_relaxes_policy",
            False,
            "a safeguard above the request amount changed the outcome",
        )
    if verify_app.decision is not Decision.HOLD:
        return InvariantResult(
            "learning_never_relaxes_policy",
            False,
            "a verification safeguard did not produce HOLD",
        )
    return InvariantResult(
        "learning_never_relaxes_policy",
        True,
        "safeguards only ever tighten; none can relax an outcome",
    )


def _postgres_shared_state_refuses_cross_instance_replay() -> InvariantResult:
    """With the PostgreSQL backend, a second instance refuses a spent nonce.

    Honest about scope: this is only *checkable* when a PostgreSQL server is
    configured (``TRACESETTLE_GUARD_STATE_PG_DSN``). With no server the check
    reports ``holds=True`` but says plainly that it was not exercised, rather than
    claiming a guarantee it did not verify. The shared-state property itself is
    proven for real in ``tests/test_guard_postgres.py`` against a live server.
    """
    import os

    dsn = os.environ.get("TRACESETTLE_GUARD_STATE_PG_DSN")
    if not dsn:
        return InvariantResult(
            "postgres_shared_state_refuses_cross_instance_replay",
            True,
            "not exercised: no PostgreSQL server configured "
            "(set TRACESETTLE_GUARD_STATE_PG_DSN to check it live)",
        )
    try:
        from .state import DurableReplayStore
        from .state_pg import PostgresGuardStateStore
    except Exception as exc:  # noqa: BLE001
        return InvariantResult(
            "postgres_shared_state_refuses_cross_instance_replay",
            False,
            f"the PostgreSQL backend could not be imported: {type(exc).__name__}",
        )
    store_a = store_b = None
    nonce: str | None = None
    try:
        store_a = PostgresGuardStateStore(dsn)
        store_b = PostgresGuardStateStore(dsn)
        authority_a = AuthorizationAuthority(
            key=_INVARIANT_KEY,
            key_id="invariant-key",
            ephemeral=False,
            replay_store=DurableReplayStore(store_a),
        )
        authority_b = AuthorizationAuthority(
            key=_INVARIANT_KEY,
            key_id="invariant-key",
            ephemeral=False,
            replay_store=DurableReplayStore(store_b),
        )
        service = GuardService(policy=DEFAULT_POLICY, authority=authority_a)
        request = service.evaluate_payload(_payload()).request
        token = service.evaluate(request).authorization
        nonce = token.nonce
        first = ReferenceSigner(authority_a).sign(
            SignRequest(transaction=request, authorization=token)
        )
        if first.outcome is not SignOutcome.EXECUTED:
            return InvariantResult(
                "postgres_shared_state_refuses_cross_instance_replay",
                False,
                "the first signing attempt did not execute",
            )
        second = ReferenceSigner(authority_b).sign(
            SignRequest(transaction=request, authorization=token)
        )
        if second.state is not AuthState.REPLAYED:
            return InvariantResult(
                "postgres_shared_state_refuses_cross_instance_replay",
                False,
                f"a second instance yielded {second.state.value}, not REPLAYED",
            )
    except StateStoreError as exc:
        return InvariantResult(
            "postgres_shared_state_refuses_cross_instance_replay",
            False,
            f"the PostgreSQL store could not be used: {type(exc).__name__}",
        )
    finally:
        # The check must not leave residue in a shared database: drop the nonce it
        # consumed, so an operator pinging this endpoint does not accumulate state.
        if store_a is not None and nonce is not None:
            try:
                with store_a._connection.cursor() as cur:  # noqa: SLF001
                    cur.execute("DELETE FROM consumed_nonces WHERE nonce = %s", (nonce,))
            except Exception:  # noqa: BLE001
                pass
        if store_a is not None:
            store_a.close()
        if store_b is not None:
            store_b.close()
    return InvariantResult(
        "postgres_shared_state_refuses_cross_instance_replay",
        True,
        "a nonce spent by one instance is refused as REPLAYED by another",
    )


# ---------------------------------------------------------------------------
# NEAR integration invariants
# ---------------------------------------------------------------------------
#
# These prove the NEAR-specific guarantees with the real wrapper, the real
# policy parser, and the real access-key analyser. They are the structural
# counterpart to the attack scenarios: the scenarios show the attacks are
# stopped, these show the property that stops them cannot silently weaken.


#: Assurance levels that mean the destination leg (or the whole settlement) was
#: independently verified. The invariants below check that a provider claim can
#: never reach any of them, and that a shortfall is never among them.
_VERIFIED_ASSURANCE_LEVELS = frozenset(
    {
        "SETTLEMENT_VERIFIED",
        "DESTINATION_DELIVERY_VERIFIED",
    }
)


def _near_wrapper(*, policy_read=None, access_key=None):
    """A throwaway NEAR wrapper over a real guard service."""
    from ..near.agent_wrapper import AgentAuthorizationWrapper
    from ..near.attacks import DEMO_KEY, near_demo_policy

    authority = AuthorizationAuthority(
        key=DEMO_KEY, key_id="invariant-near", ephemeral=False, replay_store=InMemoryReplayStore()
    )
    service = GuardService(policy=near_demo_policy(), authority=authority)
    return AgentAuthorizationWrapper(service, policy_read=policy_read, access_key=access_key)


def _near_policy_fixture(name: str):
    import json
    import pathlib as _pathlib

    from ..near.policy import PolicyAdapter

    root = _pathlib.Path(__file__).resolve().parents[1] / "near" / "fixtures"
    raw = json.loads((root / name).read_text())
    return PolicyAdapter.from_fixture(raw)


def _near_legit_tx(**overrides):
    from ..near.agent_wrapper import AgentTransaction
    from ..near.policy import PolicyScope

    base = dict(
        service_id="treasury-agent",
        operation="WITHDRAWAL",
        chain="base",
        asset="USDC",
        amount="1250.50",
        destination="0x1111111111111111111111111111111111111111",
        scope=PolicyScope.INTENTS,
        policy_action="withdraw",
        request_id="near-invariant",
    )
    base.update(overrides)
    return AgentTransaction(**base)


def _near_policy_must_be_in_force():
    """A signed-but-not-applied policy update must never be treated as active."""
    not_applied = _near_policy_fixture("policy_not_applied.json")
    wrapper = _near_wrapper(policy_read=not_applied)
    decision = wrapper.evaluate(_near_legit_tx())
    if decision.outcome.value == "ALLOW":
        return InvariantResult(
            "near_policy_must_be_in_force",
            False,
            "a signed-but-not-applied policy produced ALLOW",
        )
    return InvariantResult(
        "near_policy_must_be_in_force",
        True,
        f"a signed-but-not-applied policy yields {decision.outcome.value}, never ALLOW",
    )


def _near_policy_selection_is_not_client_controlled():
    """A request must not be able to choose the policy it is judged against."""
    from .. import config
    from .api import GuardAPI

    if config.NEAR_ALLOW_CLIENT_POLICY_SELECTION:
        return InvariantResult(
            "near_policy_selection_is_not_client_controlled",
            True,
            "client policy selection is explicitly enabled; not exercised "
            "(loopback-only affordance, refused on a public binding)",
        )

    api = GuardAPI(GuardService(policy=DEFAULT_POLICY))
    # A permissive fixture that would allow an unapproved destination.
    permissive = {
        "agent_id": "treasury-agent",
        "revision": 99,
        "status": "APPLIED",
        "provider_policy_synced": True,
        "frozen": False,
        "actions": ["withdraw", "transfer", "swap"],
        "destinations": {"mode": "any", "list": []},
        "limits": {},
    }
    import json
    import tempfile

    with tempfile.NamedTemporaryFile("w", suffix=".json", delete=False) as handle:
        json.dump(permissive, handle)
        path = handle.name
    try:
        response = api.dispatch(
            "POST",
            "/api/guard/near/agent-evaluate",
            {},
            {
                "transaction": {
                    "service_id": "treasury-agent",
                    "operation": "WITHDRAWAL",
                    "chain": "base",
                    "asset": "USDC",
                    "amount": "1",
                    "destination": _UNAPPROVED,
                    "scope": "INTENTS",
                    "policy_action": "withdraw",
                },
                "policy_fixture": path,
            },
        )
    finally:
        import os

        os.unlink(path)

    payload = response.payload
    if payload.get("permits_signing") or payload.get("outcome") == "ALLOW":
        return InvariantResult(
            "near_policy_selection_is_not_client_controlled",
            False,
            "a client-supplied policy fixture changed the decision to ALLOW",
        )
    policy = payload.get("policy")
    if isinstance(policy, dict) and policy.get("local_fixture") is True:
        return InvariantResult(
            "near_policy_selection_is_not_client_controlled",
            False,
            "the decision used a policy the client supplied",
        )
    return InvariantResult(
        "near_policy_selection_is_not_client_controlled",
        True,
        "a client-supplied policy fixture was ignored; the operator's policy governs",
    )


def _near_unrecognised_access_key_never_allows():
    """An unrecognised access-key permission must never produce ALLOW.

    The analyser classifies an unknown permission shape as unrestricted
    (CRITICAL risk). Treating that as "safe" and allowing the action is the
    "unrecognised structure treated as safe" defect, so the wrapper must fail
    closed to a review. This mirrors the function-call-key invariant: the
    property that stops the attack is itself checked.
    """
    from ..near.access_keys import parse_access_key
    from ..near.policy import PolicyScope

    unknown_key = parse_access_key({"permission": {"SomethingBrandNew": {}}})
    if unknown_key.permission.value != "UNKNOWN":
        return InvariantResult(
            "near_unrecognised_access_key_never_allows",
            False,
            "the analyser did not classify an unrecognised permission as UNKNOWN",
        )
    wrapper = _near_wrapper(
        policy_read=_near_policy_fixture("policy_native_transfer.json"), access_key=unknown_key
    )
    tx = _near_legit_tx(
        operation="TRANSFER",
        chain="near",
        asset="NEAR",
        amount="5",
        destination="0x1111111111111111111111111111111111111111",
        scope=PolicyScope.NATIVE_NEAR,
        policy_action="transfer",
        transfers_near=True,
        metadata={"native_method": "transfer"},
    )
    decision = wrapper.evaluate(tx)
    if decision.outcome.value == "ALLOW" or decision.permits_signing:
        return InvariantResult(
            "near_unrecognised_access_key_never_allows",
            False,
            "an unrecognised access-key permission produced ALLOW",
        )
    return InvariantResult(
        "near_unrecognised_access_key_never_allows",
        True,
        f"an unrecognised access-key permission yields {decision.outcome.value}, never ALLOW",
    )


def _near_native_scope_gap_is_always_stated():
    """A native request must never be described as covered by the Intents money rules."""
    from ..near.policy import PolicyScope

    on_read = _near_policy_fixture("policy_native_transfer.json")
    wrapper = _near_wrapper(policy_read=on_read)
    tx = _near_legit_tx(
        operation="TRANSFER",
        chain="near",
        asset="NEAR",
        amount="5",
        scope=PolicyScope.NATIVE_NEAR,
        policy_action="transfer",
        transfers_near=True,
        metadata={"native_method": "transfer"},
    )
    decision = wrapper.evaluate(tx)
    if "destinations" not in decision.non_applicable_controls:
        return InvariantResult(
            "near_native_scope_gap_is_always_stated",
            False,
            "a native request did not report that the destinations control does not apply",
        )
    if decision.outcome.value == "ALLOW" and not decision.limitations:
        return InvariantResult(
            "near_native_scope_gap_is_always_stated",
            False,
            "a native request was allowed without stating the scope gap",
        )
    return InvariantResult(
        "near_native_scope_gap_is_always_stated",
        True,
        "a native request reports that the Intents money controls do not apply",
    )


def _near_function_call_key_cannot_transfer_near():
    """A function-call key must never be treated as able to transfer NEAR."""
    from ..near.access_keys import key_supports_operation, parse_access_key

    key = parse_access_key(
        {
            "permission": {
                "FunctionCall": {
                    "receiver_id": "wrap.near",
                    "method_names": ["ft_transfer"],
                    "allowance": "1",
                }
            }
        }
    )
    allowed, _ = key_supports_operation(key, operation="TRANSFER", transfers_near=True)
    if allowed:
        return InvariantResult(
            "near_function_call_key_cannot_transfer_near",
            False,
            "a function-call key was treated as able to transfer NEAR",
        )
    return InvariantResult(
        "near_function_call_key_cannot_transfer_near",
        True,
        "a function-call key can never transfer NEAR or attach NEAR to a call",
    )


def _near_provider_success_is_never_verified_without_evidence():
    """A provider success claim must never produce an independently-verified level."""
    from ..model import OverallOutcome, ReconciliationResult, Stage, StageAssessment, StageState
    from ..near.settlement import settlement_assurance_from_result

    result = ReconciliationResult(
        stages=(
            StageAssessment(stage=Stage.NEAR_SETTLEMENT, state=StageState.MISSING, summary="none"),
            StageAssessment(
                stage=Stage.DESTINATION_CHAIN_DELIVERY, state=StageState.MISSING, summary="none"
            ),
        ),
        last_confirmed_stage=None,
        outcome=OverallOutcome.UNKNOWN,
        summary="no evidence",
    )
    assurance = settlement_assurance_from_result(result, provider_reported_success=True)
    if assurance.independently_verified or assurance.level in _VERIFIED_ASSURANCE_LEVELS:
        return InvariantResult(
            "near_provider_success_is_never_verified_without_evidence",
            False,
            "a provider success claim produced an independently-verified settlement",
        )
    return InvariantResult(
        "near_provider_success_is_never_verified_without_evidence",
        True,
        "a provider success claim without independent evidence stays UNKNOWN/UNAVAILABLE",
    )


def _near_partial_settlement_is_never_verified():
    """A confirmed delivery that received less than expected is never VERIFIED."""
    from ..model import OverallOutcome, ReconciliationResult, Stage, StageAssessment, StageState
    from ..near.settlement import AssuranceLevel, settlement_assurance_from_result

    result = ReconciliationResult(
        stages=(
            StageAssessment(
                stage=Stage.DESTINATION_CHAIN_DELIVERY, state=StageState.CONFIRMED, summary="ok"
            ),
        ),
        last_confirmed_stage=Stage.DESTINATION_CHAIN_DELIVERY,
        outcome=OverallOutcome.SETTLED_VERIFIED,
        summary="delivered",
    )
    assurance = settlement_assurance_from_result(
        result, expected_amount_out="1000000", observed_amount_out="990000"
    )
    if assurance.independently_verified or assurance.level in _VERIFIED_ASSURANCE_LEVELS:
        return InvariantResult(
            "near_partial_settlement_is_never_verified",
            False,
            "a confirmed shortfall was reported as fully verified",
        )
    if assurance.level is not AssuranceLevel.PARTIAL:
        return InvariantResult(
            "near_partial_settlement_is_never_verified",
            False,
            "a confirmed shortfall was not classified as PARTIAL",
        )
    return InvariantResult(
        "near_partial_settlement_is_never_verified",
        True,
        "a confirmed shortfall is classified PARTIAL and never independently verified",
    )


def _near_terminal_states_are_evidence_distinguished():
    """A reported failure/refund is never presented as FAILED/REFUNDED.

    The mission forbids representing an upstream failure as a definitive
    settlement failure, and forbids presenting a refund as a successful
    settlement. This checks both directions: a merely reported failure or refund
    must not reach a terminal verified level, and a confirmed refund must be
    REFUNDED rather than VERIFIED.
    """
    from ..model import OverallOutcome, ReconciliationResult, Stage, StageAssessment, StageState
    from ..near.settlement import AssuranceLevel, settlement_assurance_from_result

    reported_failure = ReconciliationResult(
        stages=(
            StageAssessment(stage=Stage.NEAR_SETTLEMENT, state=StageState.REPORTED, summary="claim"),
        ),
        last_confirmed_stage=None,
        outcome=OverallOutcome.FAILED_REPORTED_UNVERIFIED,
        summary="provider says failed",
    )
    reported_level = settlement_assurance_from_result(reported_failure).level
    if reported_level is AssuranceLevel.FAILED:
        return InvariantResult(
            "near_terminal_states_are_evidence_distinguished",
            False,
            "a merely reported failure was presented as a definitive FAILED state",
        )

    confirmed_refund = ReconciliationResult(
        stages=(
            StageAssessment(stage=Stage.REFUND, state=StageState.CONFIRMED, summary="payout"),
        ),
        last_confirmed_stage=Stage.REFUND,
        outcome=OverallOutcome.REFUND_VERIFIED,
        summary="refund confirmed",
    )
    refund_level = settlement_assurance_from_result(confirmed_refund).level
    if refund_level is not AssuranceLevel.REFUNDED:
        return InvariantResult(
            "near_terminal_states_are_evidence_distinguished",
            False,
            "a confirmed refund was not classified REFUNDED",
        )

    return InvariantResult(
        "near_terminal_states_are_evidence_distinguished",
        True,
        "a reported failure stays unverified and a confirmed refund is REFUNDED, never a successful settlement",
    )


def _near_destination_delivery_requires_the_destination_chain():
    """A provider SUCCESS must never confirm a destination delivery by itself.

    The mission rule: provider success is a claim, and a confirmed origin deposit
    proves only that the money left the source. The destination leg is verified
    only by reading the destination chain and matching an explicit identifier (the
    recipient). This runs the real verifier and the real EVM adapter over a canned
    transport: a transaction that succeeded but pays a different recipient must be
    CONTRADICTORY (never VERIFIED), an unreachable source must be UNAVAILABLE
    (never a false confirmation), and a correctly-directed delivery must verify.
    """
    import json as _json

    from ..httpclient import HttpClient
    from ..near.destination_verify import DestinationVerdict, verify_destination_delivery

    name = "near_destination_delivery_requires_the_destination_chain"
    tx_hash = "0x" + "ab" * 32
    token = "0x" + "cd" * 20
    intended = "0x" + "11" * 20
    other = "0x" + "22" * 20
    transfer_topic = "0xddf252ad1be2c89b69c2b068fc378daa952ba7f163c4a11628f55a4df523b3ef"

    def _word(address: str) -> str:
        return "0x" + address.lower().replace("0x", "").rjust(64, "0")

    def _receipt(paid_to: str) -> dict:
        return {
            "jsonrpc": "2.0",
            "id": 1,
            "result": {
                "transactionHash": tx_hash,
                "status": "0x1",
                "from": intended,
                "to": token,
                "blockNumber": "0x100",
                "logs": [
                    {
                        "address": token,
                        "topics": [transfer_topic, _word(intended), _word(paid_to)],
                        "data": hex(1000),
                        "logIndex": "0x1",
                    }
                ],
            },
        }

    class _Opener:
        def __init__(self, payload: dict | None) -> None:
            self._payload = payload

        def __call__(self, request: object, timeout: float | None = None) -> object:
            if self._payload is None:
                raise TimeoutError("timed out")
            body = _json.dumps(self._payload).encode()

            class _Response:
                status = 200

                def read(self) -> bytes:
                    return body

                def __enter__(self) -> "_Response":
                    return self

                def __exit__(self, *exc: object) -> bool:
                    return False

            return _Response()

    def _verify(payload: dict | None):
        client = HttpClient(opener=_Opener(payload), max_attempts=1, timeout=1.0)
        return verify_destination_delivery(
            chain="eth",
            tx_hash=tx_hash,
            recipient=intended,
            token_contract=token,
            expected_amount="1000",
            client=client,
        )

    wrong_recipient = _verify(_receipt(other))
    if wrong_recipient.level is not DestinationVerdict.CONTRADICTORY:
        return InvariantResult(
            name,
            False,
            "a successful transaction paying a different recipient was not a contradiction",
        )

    unavailable = _verify(None)
    if unavailable.level is not DestinationVerdict.UNAVAILABLE:
        return InvariantResult(
            name, False, "an unreachable destination source was not UNAVAILABLE"
        )

    verified = _verify(_receipt(intended))
    if verified.level is not DestinationVerdict.VERIFIED:
        return InvariantResult(
            name, False, "a correctly-directed, successful delivery was not verified"
        )

    return InvariantResult(
        name,
        True,
        "a destination delivery is verified only from the chain: a wrong recipient is "
        "CONTRADICTORY, an unreachable source is UNAVAILABLE, and only a correct transfer verifies",
    )


def _near_chain_is_derived_from_the_origin_asset():
    """The guard must evaluate the chain the origin asset is actually on.

    A caller can omit ``chain`` or supply one that disagrees with the origin
    asset. Either way the guard evaluates its chain allowlist against a value the
    caller influenced, so a service permitted on one chain could fund a transfer
    on another. The lifecycle derives the chain from the origin asset (via the
    canonical parser) and refuses a contradicting explicit value. This checks the
    real derivation and the real refusal, not a restatement of them.
    """
    from ..near.lifecycle import LifecycleError, _chain_of

    name = "near_chain_is_derived_from_the_origin_asset"
    # A native bridged asset names its real chain, not "near".
    if _chain_of("nep141:eth.omft.near") != "eth":
        return InvariantResult(
            name, False, "a native ETH origin asset did not derive the chain 'eth'"
        )
    if _chain_of("nep141:base-0x833589fcd6edb6e08f4c7c32d4f71b54bda02913.omft.near") != "base":
        return InvariantResult(name, False, "a Base ERC-20 origin asset did not derive 'base'")

    # An explicit chain that contradicts the origin asset must be refused, never
    # silently accepted. This drives the real lifecycle.
    import tempfile
    from pathlib import Path

    from ..intents_store import IntentStore
    from ..httpclient import HttpClient
    from ..near.lifecycle import NearIntentsLifecycle
    from .service import GuardService

    store = IntentStore(Path(tempfile.mkdtemp()) / "inv.db")
    try:
        lifecycle = NearIntentsLifecycle(
            guard_service=GuardService(),
            http_client=HttpClient(opener=lambda *a, **k: None),
            store=store,
        )
        payload = {
            "service_id": "treasury-agent",
            "operation": "SETTLEMENT",
            "chain": "near",  # disagrees with the ETH origin asset below
            "asset": "ETH",
            "amount": "1",
            "recipient": "0x4e6d3A556e485188E9C9a528bc72c88BD92BD735",
            "refund_to": "0x4e6d3A556e485188E9C9a528bc72c88BD92BD735",
            "origin_asset": "nep141:eth.omft.near",
            "destination_asset": (
                "nep141:base-0x833589fcd6edb6e08f4c7c32d4f71b54bda02913.omft.near"
            ),
            "scope": "INTENTS",
        }
        try:
            lifecycle.create_and_authorize(
                owner="treasury-agent", payload=payload, policy_read=None, access_key=None
            )
        except LifecycleError:
            return InvariantResult(
                name,
                True,
                "the evaluated chain is derived from the origin asset, and an explicit chain that "
                "disagrees with it is refused rather than evaluated",
            )
        return InvariantResult(
            name,
            False,
            "a request whose declared chain contradicted its origin asset was accepted",
        )
    finally:
        store.close()


def _near_execution_never_signs_without_a_valid_authorization():
    """The execution boundary must not sign or broadcast without an authorization.

    A real boundary is driven with a policy that blocks the destination. The
    transaction is built and evaluated (so the real controls run), but the
    decision is BLOCK, so no authorization exists and a broadcast attempt must be
    refused with nothing submitted to the RPC. This is the same fail-closed
    guarantee as ``refusal_never_reaches_the_executor``, proved for the live NEAR
    path specifically.
    """
    from ..near.execution import ExecutionError, NearExecutionBoundary
    from ..near.networks import NETWORKS, NearNetwork

    class _RecordingRpc:
        """Minimal RPC: records broadcasts, answers identity/asset queries."""

        def __init__(self, config):
            self.config = config
            self.broadcasts: list[str] = []

        def status(self):
            from ..near.rpc import RpcResult
            from ..model import SourceStatus

            return RpcResult(
                SourceStatus.OK,
                {"chain_id": self.config.chain_id, "genesis_hash": self.config.genesis_hash},
            )

        def block_hash(self, *, finality="final"):
            from ..near.rpc import RpcResult
            from ..model import SourceStatus

            return RpcResult(
                SourceStatus.OK,
                {"hash": "9Gq9bHtf6SKUuWLbzgPMVedA3BtYbYVwb5NVUrQyzoE9", "height": 1},
            )

        def view_access_key(self, account_id, public_key):
            from ..near.rpc import RpcResult
            from ..model import SourceStatus

            return RpcResult(SourceStatus.OK, {"nonce": 1, "permission": "FullAccess"})

        def call_function(self, account_id, method_name, args=None, *, finality="final"):
            from ..near.rpc import RpcResult
            from ..model import SourceStatus

            return RpcResult(SourceStatus.OK, {"decimals": 24})

        def send_tx(self, signed_transaction_b64, *, wait_until="INCLUDED_FINAL"):
            self.broadcasts.append(signed_transaction_b64)
            from ..near.rpc import RpcResult
            from ..model import SourceStatus

            return RpcResult(SourceStatus.OK, {})

        def tx_status(self, tx_hash, sender_account_id):
            from ..near.rpc import RpcResult
            from ..model import SourceStatus

            return RpcResult(SourceStatus.OK, {})

    from .policy import PolicyConfig, ServicePolicy
    from ..near import ed25519

    seed = bytes(range(32))
    signer = "agent.testnet"
    config = NETWORKS[NearNetwork.TESTNET]
    policy = PolicyConfig(
        policy_id="near-exec-invariant",
        name="near exec invariant",
        version="1",
        approved_destinations=frozenset({"approved.testnet"}),
        services={
            "svc": ServicePolicy(
                service_id="svc",
                allowed_operations=frozenset({"WITHDRAWAL"}),
                allowed_chains=frozenset({"near-testnet"}),
                allowed_assets=frozenset({"NEAR:NATIVE"}),
                max_amount_per_transaction=Decimal("100"),
                approval_threshold=Decimal("1000"),
            )
        },
        per_transaction_limit=Decimal("100"),
        approval_threshold=Decimal("1000"),
        allow_unlisted_destinations=False,
    )
    guard = GuardService(
        policy=policy,
        authority=AuthorizationAuthority(
            key=_INVARIANT_KEY, key_id="i", ephemeral=False, replay_store=InMemoryReplayStore()
        ),
    )
    rpc = _RecordingRpc(config)
    boundary = NearExecutionBoundary(guard, config, rpc=rpc)
    pub = "ed25519:" + _b58(ed25519.public_key(seed))
    prepared = boundary.prepare(
        service_id="svc",
        account_id=signer,
        public_key=pub,
        receiver_id="attacker.testnet",  # not approved -> BLOCK
        asset_identifier="near:native",
        amount_human="1",
    )
    if prepared.authorized:
        return InvariantResult(
            "near_execution_never_signs_without_authorization",
            False,
            "a blocked destination still produced an authorization",
        )
    import base64 as _base64

    sig = _base64.b64encode(ed25519.sign(prepared.transaction.tx_hash_bytes, seed)).decode()
    refused = False
    try:
        boundary.broadcast(prepared, sig)
    except ExecutionError:
        refused = True
    if not refused or rpc.broadcasts:
        return InvariantResult(
            "near_execution_never_signs_without_authorization",
            False,
            "the boundary signed or broadcast without an authorization",
        )
    return InvariantResult(
        "near_execution_never_signs_without_authorization",
        True,
        "a transaction without an authorization is never signed or broadcast",
    )


def _near_execution_binding_covers_the_bytes():
    """The authorization must cover the exact bytes that would be broadcast.

    An authorized transaction is prepared and then *tampered* (the transfer
    amount is changed by one unit) while keeping the original authorization. The
    boundary must refuse: the binding is derived from the amount that goes into
    the bytes, so a change to the bytes changes the binding. A boundary that
    verified only the presence of a token would accept the tampered transaction.
    """
    from ..near.execution import ExecutionError, NearExecutionBoundary
    from ..near.networks import NETWORKS, NearNetwork
    from ..near import ed25519
    import base64 as _base64
    import dataclasses

    seed = bytes(range(32))
    signer = "agent.testnet"
    receiver = "approved.testnet"
    config = NETWORKS[NearNetwork.TESTNET]

    class _Rpc:
        def __init__(self):
            self.broadcasts: list[str] = []

        def status(self):
            from ..near.rpc import RpcResult
            from ..model import SourceStatus

            return RpcResult(
                SourceStatus.OK,
                {"chain_id": config.chain_id, "genesis_hash": config.genesis_hash},
            )

        def block_hash(self, *, finality="final"):
            from ..near.rpc import RpcResult
            from ..model import SourceStatus

            return RpcResult(
                SourceStatus.OK,
                {"hash": "9Gq9bHtf6SKUuWLbzgPMVedA3BtYbYVwb5NVUrQyzoE9", "height": 1},
            )

        def view_access_key(self, account_id, public_key):
            from ..near.rpc import RpcResult
            from ..model import SourceStatus

            return RpcResult(SourceStatus.OK, {"nonce": 1, "permission": "FullAccess"})

        def call_function(self, account_id, method_name, args=None, *, finality="final"):
            from ..near.rpc import RpcResult
            from ..model import SourceStatus

            return RpcResult(SourceStatus.OK, {"decimals": 24})

        def send_tx(self, signed_transaction_b64, *, wait_until="INCLUDED_FINAL"):
            self.broadcasts.append(signed_transaction_b64)
            from ..near.rpc import RpcResult
            from ..model import SourceStatus

            return RpcResult(SourceStatus.OK, {})

        def tx_status(self, tx_hash, sender_account_id):
            from ..near.rpc import RpcResult
            from ..model import SourceStatus

            return RpcResult(SourceStatus.OK, {})

    from .policy import PolicyConfig, ServicePolicy

    policy = PolicyConfig(
        policy_id="near-bind-invariant",
        name="near bind invariant",
        version="1",
        approved_destinations=frozenset({receiver}),
        services={
            "svc": ServicePolicy(
                service_id="svc",
                allowed_operations=frozenset({"WITHDRAWAL"}),
                allowed_chains=frozenset({"near-testnet"}),
                allowed_assets=frozenset({"NEAR:NATIVE"}),
                max_amount_per_transaction=Decimal("100"),
                approval_threshold=Decimal("1000"),
            )
        },
        per_transaction_limit=Decimal("100"),
        approval_threshold=Decimal("1000"),
        allow_unlisted_destinations=False,
    )
    guard = GuardService(
        policy=policy,
        authority=AuthorizationAuthority(
            key=_INVARIANT_KEY, key_id="i", ephemeral=False, replay_store=InMemoryReplayStore()
        ),
    )
    boundary = NearExecutionBoundary(guard, config, rpc=_Rpc())
    pub = "ed25519:" + _b58(ed25519.public_key(seed))
    prepared = boundary.prepare(
        service_id="svc",
        account_id=signer,
        public_key=pub,
        receiver_id=receiver,
        asset_identifier="near:native",
        amount_human="1",
    )
    if not prepared.authorized:
        return InvariantResult(
            "near_execution_binding_covers_the_bytes",
            False,
            "the invariant's own authorized prepare did not authorize",
        )
    tampered = dataclasses.replace(
        prepared,
        transaction=dataclasses.replace(
            prepared.transaction, amount_base=prepared.transaction.amount_base + 1
        ),
    )
    sig = _base64.b64encode(ed25519.sign(prepared.transaction.tx_hash_bytes, seed)).decode()
    refused = False
    try:
        boundary.accept_signature(tampered, sig)
    except ExecutionError:
        refused = True
    if not refused:
        return InvariantResult(
            "near_execution_binding_covers_the_bytes",
            False,
            "a tampered transaction passed the authorization binding",
        )
    return InvariantResult(
        "near_execution_binding_covers_the_bytes",
        True,
        "the authorization is bound to the exact bytes; a tampered amount is refused",
    )


def _tee_fixture_quote() -> tuple[bytes, bytes, bytes, bytes, list]:
    """Load the captured genuine NEAR AI Cloud attestation shipped with the package.

    The fixture is real hardware attestation captured live from the public gateway
    endpoint, kept inside the package so the invariant is checkable from a
    package-only copy.
    """
    import json
    import pathlib

    path = pathlib.Path(__file__).resolve().parents[1] / "near" / "fixtures" / "attestation_nearai_cloud.json"
    data = json.loads(path.read_text(encoding="utf-8"))
    return (
        bytes.fromhex(data["intel_quote"]),
        bytes.fromhex(data["request_nonce"]),
        bytes.fromhex(data["signing_address"]),
        bytes.fromhex(data["tls_cert_fingerprint"]),
        data["event_log"],
    )


def _tee_attestation_verification_is_genuine():
    """A genuine TDX quote must verify; a tampered quote must not."""
    from ..near import tdx

    quote, nonce, signing, tls, log = _tee_fixture_quote()
    good = tdx.verify_tdx_quote(
        quote, nonce=nonce, signing_address=signing, tls_cert_fingerprint=tls, event_log=log
    )
    if not good.verified:
        return InvariantResult(
            "tee_attestation_verification_is_genuine",
            False,
            "the captured genuine quote did not verify: " + "; ".join(good.failures),
        )
    tampered = bytearray(quote)
    tampered[48 + 520] ^= 0x01  # flip a bit inside report_data
    bad = tdx.verify_tdx_quote(bytes(tampered), nonce=nonce)
    if bad.verified:
        return InvariantResult(
            "tee_attestation_verification_is_genuine",
            False,
            "a tampered quote verified; the signature check is not effective",
        )
    return InvariantResult(
        "tee_attestation_verification_is_genuine",
        True,
        "the genuine quote verifies against the pinned Intel root and a tampered quote is refused",
    )


def _tee_attestation_is_bound_to_the_decision_nonce():
    """A quote obtained for one nonce must not verify for another."""
    import secrets

    from ..near import tdx

    quote, nonce, signing, tls, log = _tee_fixture_quote()
    other = secrets.token_bytes(32)
    if other == nonce:
        other = bytes(a ^ 0xFF for a in nonce)
    wrong = tdx.verify_tdx_quote(
        quote, nonce=other, signing_address=signing, tls_cert_fingerprint=tls, event_log=log
    )
    if wrong.verified:
        return InvariantResult(
            "tee_attestation_is_bound_to_the_decision_nonce",
            False,
            "a quote verified against a different nonce; the binding is not enforced",
        )
    return InvariantResult(
        "tee_attestation_is_bound_to_the_decision_nonce",
        True,
        "a quote for a different nonce is refused, so an attestation cannot be replayed for another decision",
    )


def _tee_execution_requires_a_bound_attestation():
    """A transaction must not be signable without a verified, bound attestation.

    The gate is exercised end to end on the real boundary: an authorized
    transaction is prepared with the TEE gate enabled and an attempt to accept a
    signature is made *without* an attestation. It must be refused, and the RPC
    transport must record no broadcast. A boundary that treated the attestation
    as advisory would accept the signature here.
    """
    from ..near.execution import ExecutionError, NearExecutionBoundary
    from ..near.networks import NETWORKS, NearNetwork
    from ..near.tee_execution import ExecutionRecordStore, TeeExecutionAuthorizer
    from ..near import ed25519
    import base64 as _base64

    seed = bytes(range(32))
    signer = "agent.testnet"
    receiver = "approved.testnet"
    config = NETWORKS[NearNetwork.TESTNET]
    rpc = _InvariantRpc(config)
    policy = _near_invariant_policy(receiver)
    guard = GuardService(
        policy=policy,
        authority=AuthorizationAuthority(
            key=_INVARIANT_KEY, key_id="i", ephemeral=False, replay_store=InMemoryReplayStore()
        ),
    )
    authorizer = TeeExecutionAuthorizer(
        store=ExecutionRecordStore(), require_attestation=True, ttl_seconds=90
    )
    boundary = NearExecutionBoundary(guard, config, rpc=rpc, tee_authorizer=authorizer)
    pub = "ed25519:" + _b58(ed25519.public_key(seed))
    prepared = boundary.prepare(
        service_id="svc",
        account_id=signer,
        public_key=pub,
        receiver_id=receiver,
        asset_identifier="near:native",
        amount_human="1",
    )
    if not prepared.authorized:
        return InvariantResult(
            "tee_execution_requires_a_bound_attestation",
            False,
            "the invariant's own authorized prepare did not authorize",
        )
    sig = _base64.b64encode(ed25519.sign(prepared.transaction.tx_hash_bytes, seed)).decode()
    refused = False
    try:
        boundary.accept_signature(prepared, sig)
    except ExecutionError:
        refused = True
    if not refused or rpc.broadcasts:
        return InvariantResult(
            "tee_execution_requires_a_bound_attestation",
            False,
            "a signature was accepted without a bound attestation",
        )
    return InvariantResult(
        "tee_execution_requires_a_bound_attestation",
        True,
        "with the gate on, a transaction cannot be signed until a verified attestation is bound",
    )


def _tee_execution_cannot_be_skipped_by_the_state_machine():
    """SIGNING_PENDING must be reachable only from TEE_VERIFIED.

    This is a structural check on the transition table: no pre-TEE state may
    reach signing, and no state may jump straight to a success state. A single
    illegal edge added to the table would make this fail.
    """
    from ..near.tee_execution import ExecutionState, can_transition

    pre_tee = (
        ExecutionState.RECEIVED,
        ExecutionState.AUTHORIZATION_PENDING,
        ExecutionState.AUTHORIZED,
        ExecutionState.TEE_VERIFICATION_PENDING,
    )
    for state in pre_tee:
        if can_transition(state, ExecutionState.SIGNING_PENDING):
            return InvariantResult(
                "tee_execution_cannot_be_skipped_by_the_state_machine",
                False,
                f"{state} can reach SIGNING_PENDING without TEE verification",
            )
    for state in pre_tee + (
        ExecutionState.TEE_VERIFIED,
        ExecutionState.SIGNING_PENDING,
        ExecutionState.SIGNED,
    ):
        if can_transition(state, ExecutionState.SETTLEMENT_VERIFIED):
            return InvariantResult(
                "tee_execution_cannot_be_skipped_by_the_state_machine",
                False,
                f"{state} can jump straight to SETTLEMENT_VERIFIED",
            )
    if not can_transition(ExecutionState.TEE_VERIFIED, ExecutionState.SIGNING_PENDING):
        return InvariantResult(
            "tee_execution_cannot_be_skipped_by_the_state_machine",
            False,
            "TEE_VERIFIED cannot reach SIGNING_PENDING, so the gate could never be passed",
        )
    return InvariantResult(
        "tee_execution_cannot_be_skipped_by_the_state_machine",
        True,
        "SIGNING_PENDING is reachable only from TEE_VERIFIED, and no state jumps to a success state",
    )


def _tee_execution_record_is_transaction_bound():
    """An attestation bound to one transaction must not authorize another.

    A record is created and TEE-verified, then the transaction digest is changed
    (a different payload). ``enforce`` must refuse. A gate that checked only that
    *an* attestation existed would accept the substituted transaction.
    """
    from ..near.tee_execution import TeeExecutionAuthorizer, TeeExecutionError

    authorizer = TeeExecutionAuthorizer(require_attestation=True)
    record = authorizer.create(
        service_id="svc",
        network="testnet",
        transaction_digest="ab" * 32,
        signer_id="agent.testnet",
        receiver_id="approved.testnet",
        operation="WITHDRAWAL",
        asset="NEAR:NATIVE",
        amount="1",
        destination="approved.testnet",
        authorization_id="auth",
        authorization_nonce="11" * 32,
        policy_version="1",
    )
    authorizer.bind_attestation(
        record.execution_id,
        _InvariantAttestation(nonce=record.authorization_nonce),
        expected_nonce=record.authorization_nonce,
        expected_transaction_digest=record.transaction_digest,
    )
    refused = False
    try:
        authorizer.enforce(record.execution_id, transaction_digest="cd" * 32)
    except TeeExecutionError:
        refused = True
    if not refused:
        return InvariantResult(
            "tee_execution_record_is_transaction_bound",
            False,
            "a TEE-verified record authorized a different transaction digest",
        )
    # The exact digest still passes, so the check is not vacuously refusing.
    if not authorizer.enforce(record.execution_id, transaction_digest=record.transaction_digest):
        return InvariantResult(
            "tee_execution_record_is_transaction_bound",
            False,
            "the record refused its own transaction digest",
        )
    return InvariantResult(
        "tee_execution_record_is_transaction_bound",
        True,
        "a TEE-verified record authorizes only the exact transaction digest it was bound to",
    )


class _InvariantAttestation:
    """A minimal verified attestation for the structural invariants."""

    def __init__(self, *, nonce: str, status: str = "VERIFIED") -> None:
        self.status = _AttestationStatusValue(status)
        self.detail = "invariant"
        self.nonce = nonce
        self.provider = "invariant"
        self.verification = {"measurement": {"rt_mr0": "aa" * 48}}
        self.fetched = True
        self.source_status = "OK"


class _AttestationStatusValue:
    def __init__(self, value: str) -> None:
        self.value = value


class _InvariantRpc:
    """A minimal RPC transport for the invariant checks, recording broadcasts."""

    def __init__(self, config) -> None:
        self.config = config
        self.broadcasts: list[str] = []

    def status(self):
        from ..near.rpc import RpcResult
        from ..model import SourceStatus

        return RpcResult(
            SourceStatus.OK,
            {"chain_id": self.config.chain_id, "genesis_hash": self.config.genesis_hash},
        )

    def block_hash(self, *, finality="final"):
        from ..near.rpc import RpcResult
        from ..model import SourceStatus

        return RpcResult(
            SourceStatus.OK,
            {"hash": "9Gq9bHtf6SKUuWLbzgPMVedA3BtYbYVwb5NVUrQyzoE9", "height": 1},
        )

    def view_access_key(self, account_id, public_key):
        from ..near.rpc import RpcResult
        from ..model import SourceStatus

        return RpcResult(SourceStatus.OK, {"nonce": 1, "permission": "FullAccess"})

    def call_function(self, account_id, method_name, args=None, *, finality="final"):
        from ..near.rpc import RpcResult
        from ..model import SourceStatus

        return RpcResult(SourceStatus.OK, {"decimals": 24})

    def send_tx(self, signed_transaction_b64, *, wait_until="INCLUDED_FINAL"):
        self.broadcasts.append(signed_transaction_b64)
        from ..near.rpc import RpcResult
        from ..model import SourceStatus

        return RpcResult(SourceStatus.OK, {})

    def tx_status(self, tx_hash, sender_account_id):
        from ..near.rpc import RpcResult
        from ..model import SourceStatus

        return RpcResult(SourceStatus.OK, {})


def _near_invariant_policy(receiver: str):
    from .policy import PolicyConfig, ServicePolicy

    return PolicyConfig(
        policy_id="near-tee-invariant",
        name="near tee invariant",
        version="1",
        approved_destinations=frozenset({receiver}),
        services={
            "svc": ServicePolicy(
                service_id="svc",
                allowed_operations=frozenset({"WITHDRAWAL"}),
                allowed_chains=frozenset({"near-testnet"}),
                allowed_assets=frozenset({"NEAR:NATIVE"}),
                max_amount_per_transaction=Decimal("100"),
                approval_threshold=Decimal("1000"),
            )
        },
        per_transaction_limit=Decimal("100"),
        approval_threshold=Decimal("1000"),
        allow_unlisted_destinations=False,
    )


def _b58(raw: bytes) -> str:
    alphabet = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz"
    n = int.from_bytes(raw, "big")
    out = ""
    while n:
        n, r = divmod(n, 58)
        out = alphabet[r] + out
    pad = len(raw) - len(raw.lstrip(b"\x00"))
    return "1" * pad + (out or "")


class _PermissionRpc:
    """An RPC transport whose access-key permission the caller controls."""

    def __init__(self, config, permission):
        self.config = config
        self.permission = permission
        self.broadcasts: list[str] = []

    def status(self):
        from ..near.rpc import RpcResult
        from ..model import SourceStatus

        return RpcResult(
            SourceStatus.OK,
            {"chain_id": self.config.chain_id, "genesis_hash": self.config.genesis_hash},
        )

    def block_hash(self, *, finality="final"):
        from ..near.rpc import RpcResult
        from ..model import SourceStatus

        return RpcResult(
            SourceStatus.OK,
            {"hash": "9Gq9bHtf6SKUuWLbzgPMVedA3BtYbYVwb5NVUrQyzoE9", "height": 1},
        )

    def view_access_key(self, account_id, public_key):
        from ..near.rpc import RpcResult
        from ..model import SourceStatus

        return RpcResult(SourceStatus.OK, {"nonce": 1, "permission": self.permission})

    def call_function(self, account_id, method_name, args=None, *, finality="final"):
        from ..near.rpc import RpcResult
        from ..model import SourceStatus

        return RpcResult(SourceStatus.OK, {"decimals": 24})

    def send_tx(self, signed_transaction_b64, *, wait_until="INCLUDED_FINAL"):
        self.broadcasts.append(signed_transaction_b64)
        from ..near.rpc import RpcResult
        from ..model import SourceStatus

        return RpcResult(SourceStatus.OK, {})

    def tx_status(self, tx_hash, sender_account_id):
        from ..near.rpc import RpcResult
        from ..model import SourceStatus

        return RpcResult(SourceStatus.OK, {})


def _near_execution_requires_access_key_permission():
    """The key's on-chain permission must cover the transaction, or it is refused.

    The boundary is driven twice with a key that on-chain is a *function-call* key
    (which can never move native NEAR): a native transfer must be refused before
    any signature, while the same key with a full-access permission must be
    accepted. This proves the permission check is real and specific, not a
    blanket refusal.
    """
    from ..near.execution import ExecutionError, NearExecutionBoundary
    from ..near.networks import NETWORKS, NearNetwork
    from ..near import ed25519

    seed = bytes(range(32))
    pub = "ed25519:" + _b58(ed25519.public_key(seed))
    config = NETWORKS[NearNetwork.TESTNET]
    guard = GuardService(
        policy=_near_invariant_policy("ok.testnet"),
        authority=AuthorizationAuthority(
            key=_INVARIANT_KEY, key_id="i", ephemeral=False, replay_store=InMemoryReplayStore()
        ),
    )

    # A function-call key must be refused for a native transfer.
    fc_rpc = _PermissionRpc(
        config, {"FunctionCall": {"receiver_id": "ok.testnet", "method_names": []}}
    )
    fc_boundary = NearExecutionBoundary(guard, config, rpc=fc_rpc)
    refused = False
    try:
        fc_boundary.prepare(
            service_id="svc",
            account_id="agent.testnet",
            public_key=pub,
            receiver_id="ok.testnet",
            asset_identifier="near:native",
            amount_human="1",
        )
    except ExecutionError:
        refused = True
    if not refused or fc_rpc.broadcasts:
        return InvariantResult(
            "near_execution_requires_access_key_permission",
            False,
            "a function-call key was allowed to move native NEAR",
        )

    # The same operation with a full-access key must be authorized.
    fa_rpc = _PermissionRpc(config, "FullAccess")
    fa_boundary = NearExecutionBoundary(guard, config, rpc=fa_rpc)
    prepared = fa_boundary.prepare(
        service_id="svc",
        account_id="agent.testnet",
        public_key=pub,
        receiver_id="ok.testnet",
        asset_identifier="near:native",
        amount_human="1",
    )
    if not prepared.authorized:
        return InvariantResult(
            "near_execution_requires_access_key_permission",
            False,
            "a full-access key was refused a permitted transfer",
        )
    return InvariantResult(
        "near_execution_requires_access_key_permission",
        True,
        "the key's on-chain permission is required: a function-call key cannot move NEAR, "
        "a full-access key can",
    )


def _near_submission_is_durable_and_recovery_never_resubmits():
    """An unknown submission outcome is durable, resolved from the chain, and
    never blindly resubmitted.

    The pipeline is driven with a transport whose send *times out* (the outcome is
    genuinely unknown). It must record ``UNKNOWN`` - never ``FAILED`` - and send
    exactly once. When the chain later knows the transaction, ``recover`` must
    resolve it to a verified settlement *without* sending anything again.
    """
    from ..near.networks import NETWORKS, NearNetwork
    from ..near.pipeline import NearExecutionPipeline
    from ..near.ledger import SubmissionLedger, SubmissionState
    from ..near.execution import NearExecutionBoundary
    from ..near import ed25519

    seed = bytes(range(32))
    pub = "ed25519:" + _b58(ed25519.public_key(seed))
    config = NETWORKS[NearNetwork.TESTNET]

    class _FlakyRpc(_PermissionRpc):
        def __init__(self, config):
            super().__init__(config, "FullAccess")
            self.send_status = "TIMEOUT"
            self.status_result: dict | None = None

        def send_tx(self, signed_transaction_b64, *, wait_until="INCLUDED_FINAL"):
            self.broadcasts.append(signed_transaction_b64)
            from ..near.rpc import RpcResult
            from ..model import SourceStatus

            return RpcResult(SourceStatus.TIMEOUT, None, error="connection timed out")

        def tx_status(self, tx_hash, sender_account_id):
            from ..near.rpc import RpcResult
            from ..model import SourceStatus

            if self.status_result is None:
                return RpcResult(SourceStatus.NOT_FOUND, None, error="unknown transaction")
            return RpcResult(SourceStatus.OK, self.status_result)

    guard = GuardService(
        policy=_near_invariant_policy("ok.testnet"),
        authority=AuthorizationAuthority(
            key=_INVARIANT_KEY, key_id="i", ephemeral=False, replay_store=InMemoryReplayStore()
        ),
    )
    rpc = _FlakyRpc(config)
    boundary = NearExecutionBoundary(guard, config, rpc=rpc)
    pipeline = NearExecutionPipeline(boundary, ledger=SubmissionLedger())
    prepared = boundary.prepare(
        service_id="svc",
        account_id="agent.testnet",
        public_key=pub,
        receiver_id="ok.testnet",
        asset_identifier="near:native",
        amount_human="1",
    )
    if not prepared.authorized:
        return InvariantResult(
            "near_submission_is_durable_and_recovery_never_resubmits",
            False,
            "the invariant could not be exercised: the operation was not authorized",
        )

    class _Signer:
        public_key = pub

        def sign(self, message):
            return ed25519.sign(message, seed)

    result = pipeline.execute(prepared, _Signer())
    if result.state != SubmissionState.UNKNOWN:
        return InvariantResult(
            "near_submission_is_durable_and_recovery_never_resubmits",
            False,
            f"an unknown submission outcome was recorded as {result.state}, not UNKNOWN",
        )
    if len(rpc.broadcasts) != 1:
        return InvariantResult(
            "near_submission_is_durable_and_recovery_never_resubmits",
            False,
            "an unknown submission outcome was retried",
        )

    # The chain now knows it and the execution is final.
    rpc.status_result = {
        "final_execution_status": "FINAL",
        "status": {"SuccessValue": ""},
        "transaction": {
            "hash": prepared.transaction.tx_hash,
            "signer_id": prepared.transaction.signer_id,
            "receiver_id": prepared.transaction.receiver_id,
            "nonce": prepared.transaction.nonce,
            "actions": [{"Transfer": {"deposit": str(prepared.transaction.amount_base)}}],
        },
        "transaction_outcome": {"outcome": {"logs": []}},
        "receipts_outcome": [],
    }
    resolved = pipeline.resolve_unknown(prepared.transaction.tx_hash, prepared=prepared)
    if resolved is None or resolved.state != SubmissionState.SETTLED:
        return InvariantResult(
            "near_submission_is_durable_and_recovery_never_resubmits",
            False,
            "recovery did not resolve the unknown submission from the chain",
        )
    if len(rpc.broadcasts) != 1:
        return InvariantResult(
            "near_submission_is_durable_and_recovery_never_resubmits",
            False,
            "recovery re-broadcast the transaction",
        )
    return InvariantResult(
        "near_submission_is_durable_and_recovery_never_resubmits",
        True,
        "an unknown submission outcome is durable, resolved from the chain, and never blindly resubmitted",
    )


INVARIANTS: dict[str, Callable[[], InvariantResult]] = {
    "non_allow_never_authorizes": _non_allow_never_authorizes,
    "refusal_never_reaches_the_executor": _refusal_never_reaches_the_executor,
    "authorization_is_bound_to_parameters": _authorization_is_bound_to_parameters,
    "authorization_is_single_use": _authorization_is_single_use,
    "expiry_is_enforced": _expiry_is_enforced,
    "client_assertions_never_allow": _client_assertions_never_allow,
    "audit_chain_detects_modification": _audit_chain_detects_modification,
    "configured_audit_log_is_persistent": _configured_audit_log_is_persistent,
    "no_key_material_in_output": _no_key_material_in_output,
    "unregistered_identity_never_executes": _unregistered_identity_never_executes,
    "amounts_are_exact_decimals": _amounts_are_exact_decimals,
    "service_identity_cannot_be_forged": _service_identity_cannot_be_forged,
    "service_credentials_are_hashed_at_rest": _service_credentials_are_hashed_at_rest,
    "durable_nonce_is_single_use_across_restart": _durable_nonce_is_single_use_across_restart,
    "durable_counters_survive_restart": _durable_counters_survive_restart,
    "state_store_failure_fails_closed": _state_store_failure_fails_closed,
    "learning_loop_only_tightens": _learning_loop_only_tightens_and_survives_restart,
    "learning_never_relaxes_policy": _learning_never_relaxes_the_operators_policy,
    "postgres_shared_state_refuses_cross_instance_replay": (
        _postgres_shared_state_refuses_cross_instance_replay
    ),
    "near_policy_must_be_in_force": _near_policy_must_be_in_force,
    "near_policy_selection_is_not_client_controlled": (
        _near_policy_selection_is_not_client_controlled
    ),
    "near_native_scope_gap_is_always_stated": _near_native_scope_gap_is_always_stated,
    "near_function_call_key_cannot_transfer_near": _near_function_call_key_cannot_transfer_near,
    "near_unrecognised_access_key_never_allows": _near_unrecognised_access_key_never_allows,
    "near_provider_success_is_never_verified_without_evidence": (
        _near_provider_success_is_never_verified_without_evidence
    ),
    "near_partial_settlement_is_never_verified": _near_partial_settlement_is_never_verified,
    "near_terminal_states_are_evidence_distinguished": (
        _near_terminal_states_are_evidence_distinguished
    ),
    "near_destination_delivery_requires_the_destination_chain": (
        _near_destination_delivery_requires_the_destination_chain
    ),
    "near_chain_is_derived_from_the_origin_asset": _near_chain_is_derived_from_the_origin_asset,
    "near_execution_never_signs_without_authorization": (
        _near_execution_never_signs_without_a_valid_authorization
    ),
    "near_execution_binding_covers_the_bytes": _near_execution_binding_covers_the_bytes,
    "tee_attestation_verification_is_genuine": _tee_attestation_verification_is_genuine,
    "tee_attestation_is_bound_to_the_decision_nonce": (
        _tee_attestation_is_bound_to_the_decision_nonce
    ),
    "tee_execution_requires_a_bound_attestation": (
        _tee_execution_requires_a_bound_attestation
    ),
    "tee_execution_cannot_be_skipped_by_the_state_machine": (
        _tee_execution_cannot_be_skipped_by_the_state_machine
    ),
    "tee_execution_record_is_transaction_bound": _tee_execution_record_is_transaction_bound,
    "near_execution_requires_access_key_permission": (
        _near_execution_requires_access_key_permission
    ),
    "near_submission_is_durable_and_recovery_never_resubmits": (
        _near_submission_is_durable_and_recovery_never_resubmits
    ),
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
    "configured_audit_log_is_persistent": "A configured audit-log path is kept by the guard and each record is written to disk, so durable audit evidence is never silently dropped.",
    "no_key_material_in_output": "No response body or metric carries the authorization signing key.",
    "unregistered_identity_never_executes": "An unregistered service identity is blocked and never reaches the executor.",
    "amounts_are_exact_decimals": "Amounts are compared as exact decimals, never as binary floats.",
    "service_identity_cannot_be_forged": "A service credential authenticates exactly one identity; a request declaring another service is refused.",
    "service_credentials_are_hashed_at_rest": "Service credentials are stored only as one-way hashes; the plaintext secret never appears in a store or a public view.",
    "durable_nonce_is_single_use_across_restart": "A nonce consumed before a process restart is refused as a replay after it.",
    "durable_counters_survive_restart": "Window-volume and velocity counters persist across a restart; a limit is not reset by a bounce.",
    "state_store_failure_fails_closed": "An unreadable durable state store yields HOLD with no authorization, never ALLOW.",
    "learning_loop_only_tightens": "A durable safeguard learned from a security failure tightens later decisions and survives a restart; it can never relax one.",
    "learning_never_relaxes_policy": "A learned safeguard can only ever make a decision stricter; none can override or weaken the operator's configured policy.",
    "postgres_shared_state_refuses_cross_instance_replay": "With the PostgreSQL backend, a nonce spent by one instance is refused as a replay by another.",
    "near_policy_must_be_in_force": "A NEAR Intents policy update that is signed or requested but not APPLIED and provider-synced is never treated as active.",
    "near_policy_selection_is_not_client_controlled": "A request cannot choose the NEAR Intents policy it is evaluated against; the operator's configuration governs.",
    "near_native_scope_gap_is_always_stated": "A native NEAR/EVM/Solana request is never described as protected by the Intents destinations, budget, timelock, schedule or owner approval.",
    "near_function_call_key_cannot_transfer_near": "A NEAR function-call key is never treated as able to transfer NEAR or attach NEAR tokens to a call.",
    "near_unrecognised_access_key_never_allows": "An access key whose permission shape is neither FullAccess nor FunctionCall is never treated as safe; the request requires review rather than ALLOW.",
    "near_provider_success_is_never_verified_without_evidence": "A provider success status never yields an independently-verified settlement level without decisive on-chain evidence.",
    "near_partial_settlement_is_never_verified": "A destination that received less than the quote's expected output is classified PARTIAL and is never independently verified.",
    "near_terminal_states_are_evidence_distinguished": "A reported failure or refund never reads as a definitive FAILED/REFUNDED state, and a confirmed refund is REFUNDED rather than a verified settlement.",
    "near_destination_delivery_requires_the_destination_chain": "A destination delivery is verified only by reading the destination chain and matching the intended recipient; a provider success claim and a confirmed origin deposit never confirm it.",
    "near_chain_is_derived_from_the_origin_asset": "The chain the guard evaluates is derived from the origin asset, and an explicit chain that disagrees with it is refused; a caller cannot steer a chain-scoped policy to the wrong chain.",
    "near_execution_never_signs_without_authorization": "The NEAR execution boundary never signs or broadcasts a transaction that did not receive an authorization.",
    "near_execution_binding_covers_the_bytes": "The authorization is bound to the exact bytes that would be broadcast; changing the amount after authorization is refused.",
    "tee_attestation_verification_is_genuine": "A genuine Intel TDX quote verifies against the pinned Intel SGX Root CA, and a tampered quote is refused.",
    "tee_attestation_is_bound_to_the_decision_nonce": "A TDX quote obtained for one decision nonce does not verify for another, so an attestation cannot be replayed.",
    "tee_execution_requires_a_bound_attestation": "With the TEE gate enabled, the execution boundary refuses to accept a signature until a verified attestation is bound to the transaction.",
    "tee_execution_cannot_be_skipped_by_the_state_machine": "The execution lifecycle reaches signing only from TEE_VERIFIED, and no state can jump straight to a success state.",
    "tee_execution_record_is_transaction_bound": "A TEE-verified execution record authorizes only the exact transaction digest it was bound to; a substituted transaction is refused.",
    "near_execution_requires_access_key_permission": "The signer's on-chain access-key permission must cover the transaction; a function-call key can never move NEAR, and an unrecognised permission shape is never treated as safe.",
    "near_submission_is_durable_and_recovery_never_resubmits": "A submission whose outcome is unknown is recorded UNKNOWN (never FAILED) and resolved from the chain; it is never blindly resubmitted.",
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
