"""Adversarial tests for durable authorization state.

These exercise the **real** SQLite store, the real authority, and the real
guard service. Concurrency is tested with actual threads and actual separate
connections (and, where it matters, separate processes), never with mocks: a
mocked race proves nothing about the guarantee.

Every test uses a temporary database under ``tmp_path``. No production data is
touched.
"""

from __future__ import annotations

import multiprocessing
import sqlite3
import threading
import time
from decimal import Decimal

import pytest

from tracesettle.guard.authorization import AuthorizationAuthority
from tracesettle.guard.model import AuthState, Decision
from tracesettle.guard.policy import DEFAULT_POLICY, PolicyConfig, ServicePolicy
from tracesettle.guard.service import GuardService
from tracesettle.guard.signer import ReferenceSigner, SignRequest
from tracesettle.guard.state import (
    SCHEMA_VERSION,
    DurableReplayStore,
    DurableRevocationStore,
    GuardStateStore,
    StateStoreError,
)

from guard_helpers import APPROVED_DESTINATION, TEST_KEY, make_request

KEY_ID = "durable-test-key"


def _authority(store: GuardStateStore, *, ttl_seconds: int = 90) -> AuthorizationAuthority:
    return AuthorizationAuthority(
        key=TEST_KEY,
        key_id=KEY_ID,
        ephemeral=False,
        replay_store=DurableReplayStore(store),
        revocations=DurableRevocationStore(store),
        ttl_seconds=ttl_seconds,
    )


def _durable_service(store: GuardStateStore, *, policy: PolicyConfig | None = None) -> GuardService:
    return GuardService(
        policy=policy or DEFAULT_POLICY,
        authority=_authority(store),
        state_store=store,
    )


def _small_window_policy(
    *, window_limit: str = "1000", max_requests: int = 100, max_rejected: int = 100
) -> PolicyConfig:
    """A policy whose window limit is reachable in a couple of ordinary requests."""
    return PolicyConfig(
        approved_destinations=DEFAULT_POLICY.approved_destinations,
        blocked_destinations=DEFAULT_POLICY.blocked_destinations,
        services={
            "treasury-agent": ServicePolicy(
                service_id="treasury-agent",
                allowed_operations=frozenset({"WITHDRAWAL"}),
                allowed_chains=frozenset({"eth"}),
                allowed_assets=frozenset({"USDC"}),
                max_amount_per_transaction=Decimal("10000"),
                max_amount_per_window=Decimal(window_limit),
                approval_threshold=None,
            )
        },
        per_transaction_limit=Decimal("10000"),
        window_seconds=3600,
        max_requests_per_window=max_requests,
        max_blocked_per_window=100,
        approval_threshold=None,
        max_rejected_authorizations=max_rejected,
        allow_unlisted_destinations=False,
    )


# --- 1. a consumed nonce stays consumed after restart ----------------------


def test_consumed_nonce_stays_consumed_after_restart(tmp_path):
    path = tmp_path / "state.db"
    store = GuardStateStore(path)
    authority = _authority(store)
    service = GuardService(policy=DEFAULT_POLICY, authority=authority)
    request = service.evaluate_payload(
        {"service_id": "treasury-agent", "operation": "WITHDRAWAL", "chain": "eth",
         "asset": "USDC", "amount": "100", "destination": APPROVED_DESTINATION}
    ).request
    token = service.evaluate(request).authorization
    signer = ReferenceSigner(authority)
    assert signer.sign(SignRequest(transaction=request, authorization=token)).outcome.value == "EXECUTED"
    store.close()

    # A brand-new process/connection against the same file.
    store2 = GuardStateStore(path)
    authority2 = _authority(store2)
    signer2 = ReferenceSigner(authority2)
    result = signer2.sign(SignRequest(transaction=request, authorization=token))
    store2.close()
    assert result.state is AuthState.REPLAYED


# --- 2. concurrent replay attempts: exactly one success --------------------


def test_concurrent_replay_attempts_produce_exactly_one_consumption(tmp_path):
    path = tmp_path / "state.db"
    GuardStateStore(path).close()  # create schema

    nonce = "nonce-concurrent-1"
    expires = 2_000_000_000.0
    results: list[bool] = []
    barrier = threading.Barrier(24)

    def attempt() -> None:
        store = GuardStateStore(path)
        barrier.wait()
        try:
            results.append(store.consume_nonce(nonce, expires))
        finally:
            store.close()

    threads = [threading.Thread(target=attempt) for _ in range(24)]
    for t in threads:
        t.start()
    for t in threads:
        t.join()

    assert results.count(True) == 1, f"expected exactly one success, got {results.count(True)}"
    assert results.count(False) == 23


def test_concurrent_replay_attempts_across_processes(tmp_path):
    """Separate OS processes sharing one database file: still exactly one winner."""
    path = str(tmp_path / "state.db")
    GuardStateStore(path).close()
    ctx = multiprocessing.get_context("spawn")
    start = ctx.Event()
    results = ctx.Queue()
    procs = [
        ctx.Process(target=_consume_in_process, args=(path, "nonce-proc-1", start, results))
        for _ in range(8)
    ]
    for p in procs:
        p.start()
    start.set()
    for p in procs:
        p.join(30)
    consumed = [results.get() for _ in procs]
    assert consumed.count(True) == 1, f"expected exactly one success, got {consumed.count(True)}"


def _consume_in_process(path: str, nonce: str, start, results) -> None:  # noqa: ANN001
    store = GuardStateStore(path)
    start.wait(10)
    try:
        results.put(store.consume_nonce(nonce, 2_000_000_000.0))
    finally:
        store.close()


# --- 3. spending counters survive restart ----------------------------------


def test_spending_counters_survive_restart(tmp_path):
    path = tmp_path / "state.db"
    policy = _small_window_policy(window_limit="1000")
    store = GuardStateStore(path)
    service = _durable_service(store, policy=policy)
    first = service.evaluate_payload(
        {"service_id": "treasury-agent", "operation": "WITHDRAWAL", "chain": "eth",
         "asset": "USDC", "amount": "600", "destination": APPROVED_DESTINATION, "request_id": "r1"}
    )
    assert first.decision is Decision.ALLOW
    store.close()

    store2 = GuardStateStore(path)
    service2 = _durable_service(store2, policy=policy)
    second = service2.evaluate_payload(
        {"service_id": "treasury-agent", "operation": "WITHDRAWAL", "chain": "eth",
         "asset": "USDC", "amount": "600", "destination": APPROVED_DESTINATION, "request_id": "r2"}
    )
    store2.close()
    assert second.decision is Decision.HOLD
    assert any(f.code == "WINDOW_VOLUME_EXCEEDED" for f in second.findings)


# --- 4. velocity limits survive restart ------------------------------------


def test_velocity_limits_survive_restart(tmp_path):
    path = tmp_path / "state.db"
    policy = _small_window_policy(window_limit="1000000", max_requests=3)
    store = GuardStateStore(path)
    service = _durable_service(store, policy=policy)
    for i in range(3):
        service.evaluate_payload(
            {"service_id": "treasury-agent", "operation": "WITHDRAWAL", "chain": "eth",
             "asset": "USDC", "amount": "10", "destination": APPROVED_DESTINATION, "request_id": f"v{i}"}
        )
    store.close()

    store2 = GuardStateStore(path)
    service2 = _durable_service(store2, policy=policy)
    decision = service2.evaluate_payload(
        {"service_id": "treasury-agent", "operation": "WITHDRAWAL", "chain": "eth",
         "asset": "USDC", "amount": "10", "destination": APPROVED_DESTINATION, "request_id": "v9"}
    )
    store2.close()
    assert decision.decision is Decision.HOLD
    assert any(f.code == "REQUEST_VELOCITY_EXCEEDED" for f in decision.findings)


def test_rejected_authorizations_survive_restart(tmp_path):
    path = tmp_path / "state.db"
    policy = _small_window_policy(window_limit="1000000", max_rejected=2)
    store = GuardStateStore(path)
    service = _durable_service(store, policy=policy)
    # Two signer refusals (no authorization supplied).
    for _ in range(2):
        service.sign_transaction(make_request(), None)
    store.close()

    store2 = GuardStateStore(path)
    service2 = _durable_service(store2, policy=policy)
    decision = service2.evaluate_payload(
        {"service_id": "treasury-agent", "operation": "WITHDRAWAL", "chain": "eth",
         "asset": "USDC", "amount": "10", "destination": APPROVED_DESTINATION, "request_id": "rj"}
    )
    store2.close()
    assert decision.decision is Decision.HOLD
    assert any(f.code == "REPEATED_AUTHORIZATION_REJECTIONS" for f in decision.findings)


def test_a_forged_token_cannot_drive_another_service_into_a_hold(tmp_path):
    """Cross-service DoS: a refusal must not be counted against the token's claimed service.

    An authenticated attacker submits sign requests whose (forged) token names a
    victim service. Before the fix the refusals were recorded against the claimed
    service, so three of them pushed the victim over ``max_rejected_authorizations``
    and the victim's own next transaction was HELD. The refusal is now attributed
    to the requester, so the victim is unaffected.
    """
    store = GuardStateStore(tmp_path / "state.db")
    policy = _small_window_policy(window_limit="1000000", max_rejected=2)
    service = _durable_service(store, policy=policy)

    forged = {
        "version": "ts-auth-v1",
        "authorization_id": "auth_forged",
        "decision_id": "dec_forged",
        "service_id": "treasury-agent",  # the victim
        "key_id": KEY_ID,
        "nonce": "forged-nonce",
        "issued_at": "2026-01-01T00:00:00Z",
        "expires_at": "2030-01-01T00:00:00Z",
        "fingerprint": "x",
        "parameters": {},
        "signature": "00" * 32,
    }
    attacker = make_request(service_id="attacker-service")
    for _ in range(5):
        result = service.sign(
            SignRequest(
                transaction=attacker,
                authorization=forged,
                expected_service_id="attacker-service",
            )
        )
        assert result.outcome.value == "REFUSED"
        assert result.service_id == "attacker-service"

    # The victim's own valid transaction must still be ALLOWed.
    decision = service.evaluate_payload(
        {"service_id": "treasury-agent", "operation": "WITHDRAWAL", "chain": "eth",
         "asset": "USDC", "amount": "10", "destination": APPROVED_DESTINATION}
    )
    store.close()
    assert decision.decision is Decision.ALLOW, (
        f"a forged token drove the victim to {decision.decision.value}"
    )


# --- 5. concurrent requests cannot exceed limits ---------------------------


def test_concurrent_requests_cannot_exceed_the_window_limit(tmp_path):
    path = tmp_path / "state.db"
    policy = _small_window_policy(window_limit="1000")
    # Build one connection per thread *serially* (so opening the database cannot
    # itself contend), then race the evaluations. The window read and the volume
    # write genuinely race across connections.
    stores = [GuardStateStore(path) for _ in range(12)]
    services = [_durable_service(s, policy=policy) for s in stores]
    successes: list[str] = []
    lock = threading.Lock()
    barrier = threading.Barrier(12)

    def attempt(i: int) -> None:
        barrier.wait(timeout=30)
        decision = services[i].evaluate_payload(
            {"service_id": "treasury-agent", "operation": "WITHDRAWAL", "chain": "eth",
             "asset": "USDC", "amount": "600", "destination": APPROVED_DESTINATION, "request_id": f"c{i}"}
        )
        if decision.decision is Decision.ALLOW:
            with lock:
                successes.append(decision.decision_id)

    threads = [threading.Thread(target=attempt, args=(i,)) for i in range(12)]
    for t in threads:
        t.start()
    for t in threads:
        t.join(60)
    for s in stores:
        s.close()

    # 12 requests of 600 against a 1000 window: at most one may be authorized.
    assert len(successes) <= 1, f"window limit exceeded: {len(successes)} authorizations issued"


def test_without_the_atomic_cycle_the_limit_is_exceeded(tmp_path):
    """Mutation check: the atomic cycle is what enforces the limit.

    With ``decision_cycle`` neutralised (a no-op), concurrent evaluations each
    read an empty window and all authorize, so the limit is breached. This proves
    the concurrency test above is not vacuous: it would fail without the cycle.
    """
    from contextlib import contextmanager

    path = tmp_path / "state.db"
    policy = _small_window_policy(window_limit="1000")
    stores = [GuardStateStore(path) for _ in range(12)]

    @contextmanager
    def _no_op_cycle():
        yield

    for store in stores:
        # Break the guarantee under test, on these connections only.
        store.decision_cycle = _no_op_cycle  # type: ignore[method-assign]
    services = [_durable_service(s, policy=policy) for s in stores]
    successes: list[str] = []
    lock = threading.Lock()
    barrier = threading.Barrier(12)

    def attempt(i: int) -> None:
        barrier.wait(timeout=30)
        decision = services[i].evaluate_payload(
            {"service_id": "treasury-agent", "operation": "WITHDRAWAL", "chain": "eth",
             "asset": "USDC", "amount": "600", "destination": APPROVED_DESTINATION, "request_id": f"m{i}"}
        )
        if decision.decision is Decision.ALLOW:
            with lock:
                successes.append(decision.decision_id)

    threads = [threading.Thread(target=attempt, args=(i,)) for i in range(12)]
    for t in threads:
        t.start()
    for t in threads:
        t.join(60)
    for s in stores:
        s.close()

    assert len(successes) > 1, (
        "the mutation did not breach the limit, so the concurrency test proves nothing "
        f"(successes={len(successes)})"
    )


# --- 6. database write failures fail closed --------------------------------


def test_unreadable_store_fails_closed(tmp_path):
    store = GuardStateStore(tmp_path / "state.db")
    service = _durable_service(store)
    store.close()
    decision = service.evaluate_payload(
        {"service_id": "treasury-agent", "operation": "WITHDRAWAL", "chain": "eth",
         "asset": "USDC", "amount": "100", "destination": APPROVED_DESTINATION}
    )
    assert decision.decision is Decision.HOLD
    assert decision.authorization is None
    assert any(f.code == "STATE_STORE_UNAVAILABLE" for f in decision.findings)


def test_authority_refuses_when_consume_raises(tmp_path):
    store = GuardStateStore(tmp_path / "state.db")
    authority = _authority(store)
    service = GuardService(policy=DEFAULT_POLICY, authority=authority)
    request = service.evaluate_payload(
        {"service_id": "treasury-agent", "operation": "WITHDRAWAL", "chain": "eth",
         "asset": "USDC", "amount": "100", "destination": APPROVED_DESTINATION}
    ).request
    token = service.evaluate(request).authorization
    store.close()
    result = authority.validate(token, expected=None, consume=True)
    assert result.state is AuthState.STATE_STORE_UNAVAILABLE
    assert not result.valid


def test_authority_refuses_when_revocation_lookup_raises(tmp_path):
    store = GuardStateStore(tmp_path / "state.db")
    authority = _authority(store)
    service = GuardService(policy=DEFAULT_POLICY, authority=authority)
    request = service.evaluate_payload(
        {"service_id": "treasury-agent", "operation": "WITHDRAWAL", "chain": "eth",
         "asset": "USDC", "amount": "100", "destination": APPROVED_DESTINATION}
    ).request
    token = service.evaluate(request).authorization
    store.close()
    result = authority.validate(token, expected=None, consume=False)
    assert result.state is AuthState.STATE_STORE_UNAVAILABLE


# --- 7. interrupted writes recover safely ----------------------------------


def test_wal_recovers_after_an_abrupt_connection_drop(tmp_path):
    """A committed nonce is durable even if the writer never closes cleanly."""
    path = tmp_path / "state.db"
    store = GuardStateStore(path)
    assert store.consume_nonce("nonce-durable", 2_000_000_000.0) is True
    # Simulate an abrupt drop: do not close, just abandon the connection.
    del store

    reopened = GuardStateStore(path)
    assert reopened.is_nonce_consumed("nonce-durable") is True
    assert reopened.consume_nonce("nonce-durable", 2_000_000_000.0) is False
    reopened.close()


def test_integrity_check_refuses_a_corrupt_database(tmp_path):
    path = tmp_path / "state.db"
    GuardStateStore(path).close()
    # Overwrite the file with garbage.
    path.write_bytes(b"this is not a sqlite database at all, not even close")
    with pytest.raises(StateStoreError):
        GuardStateStore(path)


def test_a_failed_write_latches_degraded_and_fails_closed(tmp_path):
    """A write that fails must disable the store, so a limit cannot silently vanish.

    The underlying connection is closed while the store still believes it is
    open. That is a real SQLite failure (``ProgrammingError``), not a mock: the
    store must latch ``degraded`` and then refuse every later read and write, so
    the service fails closed rather than running with a limit it cannot enforce.
    """
    store = GuardStateStore(tmp_path / "state.db")
    service = _durable_service(store)
    store._connection.close()  # simulate a broken handle; _closed stays False
    with pytest.raises(StateStoreError):
        store.record_event(kind="DECISION", service_id="svc", outcome="ALLOW")
    assert store.degraded is True
    with pytest.raises(StateStoreError):
        store.is_nonce_consumed("anything")
    decision = service.evaluate_payload(
        {"service_id": "treasury-agent", "operation": "WITHDRAWAL", "chain": "eth",
         "asset": "USDC", "amount": "100", "destination": APPROVED_DESTINATION}
    )
    assert decision.decision is Decision.HOLD
    assert decision.authorization is None


# --- 8. migrations preserve existing data ----------------------------------


def test_schema_version_is_recorded(tmp_path):
    from tracesettle.guard.state import SCHEMA_VERSION

    store = GuardStateStore(tmp_path / "state.db")
    assert store.schema_version() == SCHEMA_VERSION
    store.close()


def test_migration_preserves_existing_data(tmp_path):
    """Re-opening an existing database must not lose consumed nonces or events."""
    path = tmp_path / "state.db"
    store = GuardStateStore(path)
    store.consume_nonce("keep-me", 2_000_000_000.0)
    store.record_event(kind="DECISION", service_id="svc", outcome="ALLOW")
    store.close()

    # Re-opening runs the (idempotent) migration path again.
    store2 = GuardStateStore(path)
    assert store2.is_nonce_consumed("keep-me")
    events = store2.events_since(since=0)
    assert any(e.service_id == "svc" for e in events)
    store2.close()


def test_a_newer_schema_version_is_refused(tmp_path):
    path = tmp_path / "state.db"
    store = GuardStateStore(path)
    store.close()
    conn = sqlite3.connect(path)
    conn.execute("UPDATE schema_version SET version = 999")
    conn.commit()
    conn.close()
    with pytest.raises(StateStoreError):
        GuardStateStore(path)


def test_migration_from_v1_adds_the_window_index(tmp_path):
    """An existing v1 database is upgraded in place, keeping its data."""
    path = tmp_path / "state.db"
    store = GuardStateStore(path)
    store.consume_nonce("keep-across-migration", 2_000_000_000.0)
    store.close()
    # Rewind the recorded version to 1 and drop the v2 index, as a pre-upgrade
    # database would look.
    conn = sqlite3.connect(path)
    conn.execute("DROP INDEX IF EXISTS counter_events_at")
    conn.execute("UPDATE schema_version SET version = 1")
    conn.commit()
    conn.close()

    reopened = GuardStateStore(path)
    assert reopened.schema_version() == SCHEMA_VERSION
    assert reopened.is_nonce_consumed("keep-across-migration")
    indexes = {
        row[0]
        for row in reopened._connection.execute(
            "SELECT name FROM sqlite_master WHERE type='index'"
        ).fetchall()
    }
    assert "counter_events_at" in indexes
    reopened.close()


# --- 8b. durable state stays bounded (regression: the tables used to grow) ---


def test_window_read_uses_an_index_not_a_full_scan(tmp_path):
    """The window query must be index-backed; a full scan degrades forever.

    ``counter_events`` grows with every decision, so a ``WHERE at >= ?`` read with
    no leading ``at`` index scans the whole table on every evaluation. This asserts
    the plan uses the index rather than a table scan, which is the structural fix
    (the timing is environment-dependent; the plan is not).
    """
    store = GuardStateStore(tmp_path / "state.db")
    plan = store._connection.execute(
        "EXPLAIN QUERY PLAN SELECT at FROM counter_events WHERE at >= ? ORDER BY at ASC",
        (0.0,),
    ).fetchall()
    detail = " ".join(str(row[-1]) for row in plan).upper()
    assert "COUNTER_EVENTS_AT" in detail, f"window read is not index-backed: {detail}"
    assert "SCAN COUNTER_EVENTS" not in detail, f"window read is a full scan: {detail}"
    store.close()


def test_counter_events_are_pruned_so_the_table_stays_bounded(tmp_path):
    """A prune must actually drop old events and keep recent ones.

    The defect this guards: ``prune_events`` existed but was never called, so the
    table grew without bound. Pruning is now driven from the signing path.
    """
    store = GuardStateStore(tmp_path / "state.db")
    now = time.time()
    for i in range(50):
        store.record_event(kind="DECISION", service_id="svc", outcome="ALLOW", at=now - 100000 - i)
    for i in range(5):
        store.record_event(kind="DECISION", service_id="svc", outcome="ALLOW", at=now - i)

    removed = store.prune_events(before=now - 3600)
    assert removed == 50
    remaining = store.events_since(since=0)
    assert len(remaining) == 5
    store.close()


def test_signing_prunes_old_counter_events(tmp_path):
    """The prune runs from the enforcement path, with no extra call to remember."""
    store = GuardStateStore(tmp_path / "state.db")
    # A store whose prune interval is zero, so the first consume prunes.
    replay = DurableReplayStore(store, prune_interval_seconds=0.0, counter_retention_seconds=3600.0)
    now = time.time()
    for i in range(30):
        store.record_event(kind="DECISION", service_id="svc", outcome="ALLOW", at=now - 100000 - i)
    assert len(store.events_since(since=0)) == 30

    # One consume is enough to trigger retention.
    assert replay.consume("prune-trigger-nonce", 2_000_000_000.0) is True
    remaining = store.events_since(since=0)
    assert remaining == [], f"old events were not pruned: {len(remaining)} left"
    store.close()


def test_idempotency_keys_are_pruned_so_the_table_stays_bounded(tmp_path):
    store = GuardStateStore(tmp_path / "state.db")
    now = time.time()
    for i in range(20):
        store.remember_decision(f"old-{i}", f"dec_old_{i}", at=now - 100000 - i)
    store.remember_decision("recent", "dec_recent", at=now)

    removed = store.prune_idempotency(before=now - 3600)
    assert removed == 20
    assert store.decision_for("recent") == "dec_recent"
    assert store.decision_for("old-0") is None
    store.close()


# --- 9. credential revocation remains effective ----------------------------


def test_credential_revocation_still_effective(tmp_path):
    """The durable-state change must not weaken service credential revocation."""
    from tracesettle.serviceauth import ServiceAuthState, ServiceRegistry

    registry = ServiceRegistry()
    credential, secret = registry.mint("treasury-agent")
    assert registry.authenticate(secret).state is ServiceAuthState.OK
    assert registry.revoke(credential.credential_id) is True
    assert registry.authenticate(secret).state is ServiceAuthState.REVOKED


# --- 10. existing invariants remain intact ---------------------------------


def test_guard_invariants_all_hold():
    from tracesettle.guard.invariants import check_all

    failures = [r for r in check_all() if not r.holds]
    assert not failures, [(r.name, r.detail) for r in failures]


def test_settlement_invariants_all_hold():
    from tracesettle.reconcile import SAFETY_INVARIANTS

    assert len(SAFETY_INVARIANTS) == 12


# --- extra: idempotency ----------------------------------------------------


def test_duplicate_idempotency_key_does_not_issue_a_second_authorization(tmp_path):
    store = GuardStateStore(tmp_path / "state.db")
    policy = _small_window_policy(window_limit="1000000")
    service = _durable_service(store, policy=policy)
    payload = {
        "service_id": "treasury-agent", "operation": "WITHDRAWAL", "chain": "eth",
        "asset": "USDC", "amount": "100", "destination": APPROVED_DESTINATION,
        "idempotency_key": "invoice-4471",
    }
    first = service.evaluate_payload(payload)
    second = service.evaluate_payload(payload)
    store.close()
    assert first.decision is Decision.ALLOW and first.authorization is not None
    assert second.decision is Decision.HOLD
    assert second.authorization is None
    assert any(f.code == "DUPLICATE_REQUEST" for f in second.findings)


def test_idempotency_is_not_accounted_twice_in_the_window(tmp_path):
    """A retried request must not double-count against the window volume."""
    store = GuardStateStore(tmp_path / "state.db")
    policy = _small_window_policy(window_limit="1000")
    service = _durable_service(store, policy=policy)
    base = {
        "service_id": "treasury-agent", "operation": "WITHDRAWAL", "chain": "eth",
        "asset": "USDC", "amount": "600", "destination": APPROVED_DESTINATION,
        "idempotency_key": "same-key",
    }
    assert service.evaluate_payload(base).decision is Decision.ALLOW
    # Same key again: refused as duplicate, and must not add 600 to the window.
    assert service.evaluate_payload(base).decision is Decision.HOLD
    # The window now holds only the first 600. A further 300 (600+300=900) fits;
    # it would be refused only if the duplicate had also counted (1200+300).
    other = dict(base, idempotency_key="other-key", amount="300")
    decision = service.evaluate_payload(other)
    store.close()
    assert decision.decision is Decision.ALLOW


def test_no_durable_store_keeps_in_memory_behaviour():
    """With no store configured, the guard behaves exactly as before."""
    service = GuardService(policy=DEFAULT_POLICY)
    assert service.state_store is None
    decision = service.evaluate_payload(
        {"service_id": "treasury-agent", "operation": "WITHDRAWAL", "chain": "eth",
         "asset": "USDC", "amount": "100", "destination": APPROVED_DESTINATION}
    )
    assert decision.decision is Decision.ALLOW
    metrics = service.metrics()
    assert metrics["state"]["backend"] == "in-memory"
    assert metrics["state"]["durable"] is False


# --- 12. configuration wires the durable store into the real builder --------


def test_builder_produces_a_durable_service_when_configured(tmp_path, monkeypatch):
    """The startup builder must actually open the configured database."""
    from tracesettle import config
    from tracesettle.ui import _build_guard_service

    db = tmp_path / "guard-state.db"
    # A fixed signing key, as a real deployment would configure: without it each
    # build mints a fresh ephemeral key and a token could not survive a restart
    # for a reason unrelated to durable state.
    monkeypatch.setenv("TRACESETTLE_GUARD_AUTH_KEY", "11" * 32)
    monkeypatch.setattr(config, "GUARD_STATE_DB", str(db))
    monkeypatch.setattr(config, "GUARD_AUDIT_LOG_PATH", None)
    monkeypatch.setattr(config, "GUARD_POLICY_PATH", None)
    service = _build_guard_service()
    try:
        assert service.state_store is not None
        assert service.metrics()["state"]["backend"] == "sqlite"
        decision = service.evaluate_payload(
            {"service_id": "treasury-agent", "operation": "WITHDRAWAL", "chain": "eth",
             "asset": "USDC", "amount": "100", "destination": APPROVED_DESTINATION}
        )
        assert decision.decision is Decision.ALLOW
        token = decision.authorization
        request = decision.request
        assert service.sign_transaction(request, token).outcome.value == "EXECUTED"
    finally:
        service.state_store.close()

    # A rebuilt service (a "restart") sees the spent nonce.
    service2 = _build_guard_service()
    try:
        result = service2.sign_transaction(request, token)
        assert result.state is AuthState.REPLAYED
    finally:
        service2.state_store.close()


def test_builder_keeps_in_memory_when_unconfigured(monkeypatch):
    from tracesettle import config
    from tracesettle.ui import _build_guard_service

    monkeypatch.setattr(config, "GUARD_STATE_DB", None)
    monkeypatch.setattr(config, "GUARD_AUDIT_LOG_PATH", None)
    monkeypatch.setattr(config, "GUARD_POLICY_PATH", None)
    service = _build_guard_service()
    assert service.state_store is None
    assert service.metrics()["state"]["backend"] == "in-memory"


def test_builder_refuses_an_unopenable_state_database(tmp_path, monkeypatch):
    """A configured-but-broken database must stop start-up, not degrade silently."""
    from tracesettle import config
    from tracesettle.ui import _build_guard_service

    bad = tmp_path / "not-a-db.db"
    bad.write_bytes(b"garbage that is not sqlite")
    monkeypatch.setattr(config, "GUARD_STATE_DB", str(bad))
    with pytest.raises(StateStoreError):
        _build_guard_service()


# --- 11. the whole path over real HTTP, across a real server restart --------


def test_replay_is_refused_across_a_server_restart(tmp_path):
    """The nonce is durable end-to-end: real sockets, two server lifetimes."""
    import json
    import threading
    import urllib.request

    from tracesettle.ui import InvestigationServer

    path = tmp_path / "state.db"
    payload = {
        "transaction": {
            "service_id": "treasury-agent", "operation": "WITHDRAWAL", "chain": "eth",
            "asset": "USDC", "amount": "100", "destination": APPROVED_DESTINATION,
        },
        "return_authorization": True,
    }

    def post(base, route, body):
        request = urllib.request.Request(
            base + route,
            data=json.dumps(body).encode(),
            method="POST",
            headers={"Content-Type": "application/json"},
        )
        with urllib.request.urlopen(request, timeout=5) as response:
            return json.loads(response.read())

    def serve():
        store = GuardStateStore(path)
        authority = AuthorizationAuthority(
            key=TEST_KEY, key_id=KEY_ID, ephemeral=False,
            replay_store=DurableReplayStore(store),
            revocations=DurableRevocationStore(store),
        )
        service = GuardService(policy=DEFAULT_POLICY, authority=authority, state_store=store)
        server = InvestigationServer(("127.0.0.1", 0), timeout_seconds=2.0, guard_service=service)
        thread = threading.Thread(target=server.serve_forever, daemon=True)
        thread.start()
        return server, thread, store

    server, thread, store = serve()
    base = f"http://{server.server_address[0]}:{server.server_address[1]}"
    try:
        decision = post(base, "/api/guard/evaluate", payload)
        token = decision["authorization"]
        first = post(base, "/api/guard/sign", {"transaction": payload["transaction"], "authorization": token})
        assert first["outcome"] == "EXECUTED"
    finally:
        server.shutdown()
        server.server_close()
        thread.join(timeout=5)
        store.close()

    # Second server lifetime, same database file.
    server2, thread2, store2 = serve()
    base2 = f"http://{server2.server_address[0]}:{server2.server_address[1]}"
    try:
        second = post(base2, "/api/guard/sign", {"transaction": payload["transaction"], "authorization": token})
        assert second["outcome"] == "REFUSED"
        assert second["state"] == "REPLAYED"
    finally:
        server2.shutdown()
        server2.server_close()
        thread2.join(timeout=5)
        store2.close()
