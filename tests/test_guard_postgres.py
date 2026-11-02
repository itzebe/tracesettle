"""Distributed security tests for the PostgreSQL guard-state backend.

Every test here talks to a **real** PostgreSQL server (``TRACESETTLE_TEST_PG_DSN``)
and, where a claim is about multiple instances, uses separate connections and
separate OS processes. SQLite is never substituted: the guarantee under test is a
property of the shared database, not of a process-local lock.

Skipped when no DSN is configured, so ``pytest tests/`` stays green without a
server; CI runs them against a real PostgreSQL service.
"""

from __future__ import annotations

import multiprocessing
import threading
import time
from decimal import Decimal

import pytest

from guard_helpers import APPROVED_DESTINATION, TEST_KEY
from pg_helpers import _truncate, build_service, pg_available, pg_dsn
from tracesettle.guard.model import AuthState, Decision
from tracesettle.guard.policy import DEFAULT_POLICY, PolicyConfig, ServicePolicy
from tracesettle.guard.signer import ReferenceSigner, SignRequest
from tracesettle.guard.state import StateStoreError

pytestmark = pytest.mark.skipif(
    not pg_available(),
    reason="requires a real PostgreSQL server (TRACESETTLE_TEST_PG_DSN)",
)


@pytest.fixture(scope="session")
def pg_dsn_value() -> str:
    """The configured DSN, or skip the whole module when there is none."""
    dsn = pg_dsn()
    if dsn is None:
        pytest.skip("TRACESETTLE_TEST_PG_DSN is not set; PostgreSQL tests skipped")
    return dsn

_PAYLOAD = {
    "service_id": "treasury-agent",
    "operation": "WITHDRAWAL",
    "chain": "eth",
    "asset": "USDC",
    "amount": "100",
    "destination": APPROVED_DESTINATION,
}


@pytest.fixture(autouse=True)
def _clean_state(pg_dsn_value):
    """Truncate the guard tables before and after every test in this module.

    Tests that build their own stores (not the ``pg_store`` fixture) still share
    one database, so an explicit clean-up keeps them independent.
    """
    from tracesettle.guard.state_pg import PostgresGuardStateStore

    store = PostgresGuardStateStore(pg_dsn_value)
    _truncate(store)
    try:
        yield
    finally:
        try:
            _truncate(store)
        finally:
            store.close()


def _small_window_policy(window_limit: str = "1000") -> PolicyConfig:
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
        max_requests_per_window=1000,
        max_blocked_per_window=100,
        approval_threshold=None,
        max_rejected_authorizations=100,
        allow_unlisted_destinations=False,
    )


# --- 1. two instances cannot consume the same authorization -----------------


def test_two_instances_cannot_consume_the_same_authorization(pg_dsn_value):
    """Instance A signs; instance B (its own connection) cannot replay the token."""
    from tracesettle.guard.state_pg import PostgresGuardStateStore

    store_a = PostgresGuardStateStore(pg_dsn_value)
    store_b = PostgresGuardStateStore(pg_dsn_value)
    try:
        service_a = build_service(store_a, key=TEST_KEY)
        service_b = build_service(store_b, key=TEST_KEY)

        decision = service_a.evaluate_payload(_PAYLOAD)
        token = decision.authorization
        request = decision.request

        first = ReferenceSigner(service_a.authority).sign(
            SignRequest(transaction=request, authorization=token)
        )
        assert first.outcome.value == "EXECUTED"

        # A *different* instance, different connection, same database.
        second = ReferenceSigner(service_b.authority).sign(
            SignRequest(transaction=request, authorization=token)
        )
        assert second.state is AuthState.REPLAYED
    finally:
        store_a.close()
        store_b.close()


# --- 2. concurrent transactions cannot exceed spending limits ---------------


def test_concurrent_requests_cannot_exceed_the_window_limit(pg_dsn_value):
    """Twelve instances race 600-unit requests against a 1000-unit window."""
    from tracesettle.guard.state_pg import PostgresGuardStateStore

    policy = _small_window_policy("1000")
    stores = [PostgresGuardStateStore(pg_dsn_value) for _ in range(12)]
    services = [build_service(s, key=TEST_KEY, policy=policy) for s in stores]
    results: list[str] = []
    barrier = threading.Barrier(len(services))

    def attempt(service) -> None:  # noqa: ANN001
        barrier.wait()
        decision = service.evaluate_payload(dict(_PAYLOAD, amount="600"))
        results.append(decision.decision.value)

    threads = [threading.Thread(target=attempt, args=(s,)) for s in services]
    for t in threads:
        t.start()
    for t in threads:
        t.join(30)

    try:
        assert results.count("ALLOW") <= 1, (
            f"the 1000-unit window admitted {results.count('ALLOW')} 600-unit "
            "requests; the shared limit was not enforced"
        )
        assert "HOLD" in results or "BLOCK" in results
    finally:
        for s in stores:
            s.close()


# --- 3. replay protection across instances (separate OS processes) ----------


def _evaluate_in_process(dsn: str, start, results, amount: str) -> None:  # noqa: ANN001
    from tracesettle.guard.state_pg import PostgresGuardStateStore

    store = PostgresGuardStateStore(dsn)
    try:
        service = build_service(store, key=TEST_KEY, policy=_small_window_policy("1000"))
        start.wait(15)
        decision = service.evaluate_payload(dict(_PAYLOAD, amount=amount))
        results.put(decision.decision.value)
    finally:
        store.close()


def test_limit_enforced_across_independent_processes(pg_dsn_value):
    """Six real processes race 600-unit requests; the shared window admits at most one."""
    ctx = multiprocessing.get_context("spawn")
    start = ctx.Event()
    results = ctx.Queue()
    procs = [
        ctx.Process(target=_evaluate_in_process, args=(pg_dsn_value, start, results, "600"))
        for _ in range(6)
    ]
    for p in procs:
        p.start()
    start.set()
    for p in procs:
        p.join(40)
    decisions = [results.get() for _ in procs]
    assert decisions.count("ALLOW") <= 1, (
        f"across processes the window admitted {decisions.count('ALLOW')} requests; "
        "the shared limit was not enforced"
    )


def _consume_in_process(dsn: str, nonce: str, start, results) -> None:  # noqa: ANN001
    from tracesettle.guard.state_pg import PostgresGuardStateStore

    store = PostgresGuardStateStore(dsn)
    try:
        start.wait(15)
        results.put(store.consume_nonce(nonce, 2_000_000_000.0))
    finally:
        store.close()


def test_nonce_consumption_across_processes_has_exactly_one_winner(pg_dsn_value):
    ctx = multiprocessing.get_context("spawn")
    start = ctx.Event()
    results = ctx.Queue()
    procs = [
        ctx.Process(target=_consume_in_process, args=(pg_dsn_value, "pg-nonce-proc", start, results))
        for _ in range(8)
    ]
    for p in procs:
        p.start()
    start.set()
    for p in procs:
        p.join(40)
    outcomes = [results.get() for _ in procs]
    assert outcomes.count(True) == 1, f"expected exactly one winner, got {outcomes.count(True)}"


# --- 4. revocation and expiration remain effective across instances ---------


def test_revocation_on_one_instance_blocks_another(pg_dsn_value):
    from tracesettle.guard.state_pg import PostgresGuardStateStore

    store_a = PostgresGuardStateStore(pg_dsn_value)
    store_b = PostgresGuardStateStore(pg_dsn_value)
    try:
        service_a = build_service(store_a, key=TEST_KEY)
        service_b = build_service(store_b, key=TEST_KEY)
        decision = service_a.evaluate_payload(_PAYLOAD)
        token = decision.authorization
        request = decision.request

        service_a.authority.revoke(token.authorization_id)

        result = ReferenceSigner(service_b.authority).sign(
            SignRequest(transaction=request, authorization=token)
        )
        assert result.state is AuthState.REVOKED
    finally:
        store_a.close()
        store_b.close()


def test_expired_authorization_is_refused_across_instances(pg_dsn_value):
    from tracesettle.guard.state_pg import PostgresGuardStateStore

    store_a = PostgresGuardStateStore(pg_dsn_value)
    store_b = PostgresGuardStateStore(pg_dsn_value)
    try:
        # Instance A issues with a 1-second TTL.
        service_a = build_service(store_a, key=TEST_KEY, ttl_seconds=1)
        decision = service_a.evaluate_payload(_PAYLOAD)
        token = decision.authorization
        request = decision.request
        time.sleep(1.3)

        # Instance B validates with the real clock; the token has expired.
        service_b = build_service(store_b, key=TEST_KEY)
        result = ReferenceSigner(service_b.authority).sign(
            SignRequest(transaction=request, authorization=token)
        )
        assert result.state is AuthState.EXPIRED
    finally:
        store_a.close()
        store_b.close()


# --- 5. idempotency is consistent across instances --------------------------


def test_idempotency_key_is_single_across_instances(pg_dsn_value):
    from tracesettle.guard.state_pg import PostgresGuardStateStore

    store_a = PostgresGuardStateStore(pg_dsn_value)
    store_b = PostgresGuardStateStore(pg_dsn_value)
    try:
        service_a = build_service(store_a, key=TEST_KEY)
        service_b = build_service(store_b, key=TEST_KEY)
        payload = dict(_PAYLOAD, request_id="idem-cross-1", idempotency_key="client-key-1")

        first = service_a.evaluate_payload(payload)
        assert first.decision is Decision.ALLOW
        # A second instance must see the key as already claimed.
        second = service_b.evaluate_payload(payload)
        assert second.decision is Decision.HOLD
        assert any(f.code == "DUPLICATE_REQUEST" for f in second.findings)
        assert second.authorization is None
    finally:
        store_a.close()
        store_b.close()


# --- 6. database outages fail closed ----------------------------------------


def test_closed_store_fails_closed(pg_dsn_value):
    from tracesettle.guard.state_pg import PostgresGuardStateStore

    store = PostgresGuardStateStore(pg_dsn_value)
    service = build_service(store, key=TEST_KEY)
    store.close()  # every later read/write raises
    decision = service.evaluate_payload(_PAYLOAD)
    assert decision.decision is not Decision.ALLOW
    assert decision.authorization is None


def test_unreachable_database_refuses_to_start():
    """A configured-but-unreachable PostgreSQL is a start-up failure, never a fallback."""
    from tracesettle.guard.state_pg import PostgresGuardStateStore

    # Port 1 is never a PostgreSQL server.
    with pytest.raises(StateStoreError):
        PostgresGuardStateStore(
            "host=127.0.0.1 port=1 dbname=none user=none password=none",
            connect_timeout_s=2,
        )


def test_no_in_memory_fallback_when_postgres_required(monkeypatch):
    """``require_postgres`` with no DSN must raise, not silently use memory/SQLite."""
    from tracesettle import config
    from tracesettle.guard.state import open_state_store

    with pytest.raises(StateStoreError):
        open_state_store(
            None,
            backend="memory",
            require_postgres=True,
        )
    with pytest.raises(StateStoreError):
        open_state_store(
            "/tmp/should-not-be-used.db",
            backend="sqlite",
            require_postgres=True,
        )
    # auto with no DSN and no path, but required, also refuses.
    with pytest.raises(StateStoreError):
        open_state_store(None, backend="auto", pg_dsn=None, require_postgres=True)
    _ = config  # keep the import meaningful for the reader


# --- 7. interrupted transactions recover safely -----------------------------


def test_aborted_decision_transaction_leaves_no_partial_state(pg_dsn_value):
    """A failure inside the decision cycle rolls the whole thing back."""
    from tracesettle.guard.state_pg import PostgresGuardStateStore

    store = PostgresGuardStateStore(pg_dsn_value)
    try:
        with pytest.raises(RuntimeError):
            with store.decision_cycle():
                store.record_event(kind="DECISION", service_id="svc", outcome="ALLOW")
                raise RuntimeError("boom")
        # Nothing committed.
        assert store.events_since(since=0) == []
        # The store is still usable afterwards.
        store.record_event(kind="DECISION", service_id="svc", outcome="ALLOW")
        assert len(store.events_since(since=0)) == 1
    finally:
        store.close()


def test_connection_recovers_after_a_dropped_connection(pg_dsn_value):
    """A dropped link is transparently re-established; the store is not latched dead."""
    from tracesettle.guard.state_pg import PostgresGuardStateStore

    store = PostgresGuardStateStore(pg_dsn_value)
    try:
        store.record_event(kind="DECISION", service_id="svc", outcome="ALLOW")
        store._connection.close()  # simulate a dropped link
        # The next call reconnects and still works, without latching degraded.
        assert len(store.events_since(since=0)) == 1
        assert not store.degraded
    finally:
        store.close()


def test_reconnect_to_an_unreachable_database_fails_closed():
    """If the link cannot be re-established, the call fails closed, not silently."""
    from tracesettle.guard.state_pg import PostgresGuardStateStore

    store = PostgresGuardStateStore(pg_dsn())
    try:
        store._connection.close()
        # Point the store at a dead endpoint and force a reconnect.
        store._dsn = "host=127.0.0.1 port=1 dbname=none user=none password=none"
        store._connect_kwargs = {"connect_timeout": 2}
        with pytest.raises(StateStoreError):
            store.events_since(since=0)
    finally:
        store.close()
def test_connection_drop_mid_decision_fails_closed_without_partial_state(pg_dsn_value):
    """A link lost *inside* a decision must fail closed, never split the transaction.

    Regression for a real defect: ``_prepare`` used to reconnect whenever the
    connection was closed, including mid-decision. A drop after the idempotency
    claim then re-ran the remaining writes on a *new* transaction (without the
    advisory lock) and the decision still returned ALLOW — the claim was lost, so
    the same idempotency key was authorized a second time. The fix makes a
    mid-decision drop fail closed.
    """
    from tracesettle.guard.state_pg import PostgresGuardStateStore

    store = PostgresGuardStateStore(pg_dsn_value)
    service = build_service(store, key=TEST_KEY)
    original_remember = store.remember_decision

    dropped = {"done": False}

    def drop_after_claim(request_key, decision_id, **kwargs):  # noqa: ANN001
        recorded = original_remember(request_key, decision_id, **kwargs)
        if not dropped["done"]:
            dropped["done"] = True
            store._connection.close()  # simulate the link dropping mid-decision
        return recorded

    store.remember_decision = drop_after_claim  # type: ignore[assignment]
    try:
        decision = service.evaluate_payload(
            {
                "service_id": "treasury-agent",
                "operation": "WITHDRAWAL",
                "chain": "eth",
                "asset": "USDC",
                "amount": "100",
                "destination": APPROVED_DESTINATION,
                "idempotency_key": "mid-decision-drop",
            }
        )
    finally:
        store.remember_decision = original_remember  # type: ignore[assignment]
        store.close()

    assert decision.decision is Decision.HOLD, (
        f"a mid-decision connection drop yielded {decision.decision.value}; it must "
        "fail closed"
    )
    assert decision.authorization is None, "no authorization may be issued on a failed decision"

    # The claim must not have leaked: a fresh instance sees the key as unused, so a
    # legitimate retry is possible, and no counter event was committed either.
    fresh = PostgresGuardStateStore(pg_dsn_value)
    try:
        assert fresh.decision_for("treasury-agent:mid-decision-drop") is None
        assert fresh.events_since(since=0) == []
    finally:
        fresh.close()


def test_a_mid_decision_drop_does_not_leave_the_store_usable_for_partial_writes(pg_dsn_value):
    """After a mid-decision drop the connection is dead; the next call reconnects safely.

    The point is that the *decision* fails closed while an ordinary later call
    (outside any decision) still reconnects — the reconnect policy is unchanged
    for non-decision work.
    """
    from tracesettle.guard.state_pg import PostgresGuardStateStore

    store = PostgresGuardStateStore(pg_dsn_value)
    try:
        with pytest.raises(StateStoreError):
            with store.decision_cycle():
                store._connection.close()
                store.remember_decision("svc:partial", "dec-x")
        # Outside a decision the store still reconnects and works.
        assert store.remember_decision("svc:after-drop", "dec-y") is True
        assert not store.degraded
    finally:
        store.close()


# --- 8. migrations preserve existing data -----------------------------------


def test_schema_version_is_recorded(pg_dsn_value):
    from tracesettle.guard.state import SCHEMA_VERSION
    from tracesettle.guard.state_pg import PostgresGuardStateStore

    store = PostgresGuardStateStore(pg_dsn_value)
    try:
        assert store.schema_version() == SCHEMA_VERSION
    finally:
        store.close()


def test_migration_is_idempotent_and_preserves_data(pg_dsn_value):
    """Reopening an initialised database must not lose rows or re-run migrations."""
    from tracesettle.guard.state_pg import PostgresGuardStateStore

    store = PostgresGuardStateStore(pg_dsn_value)
    try:
        store.record_event(kind="DECISION", service_id="svc", outcome="ALLOW", amount=Decimal("1"))
        store.consume_nonce("migrate-nonce", 2_000_000_000.0)
    finally:
        store.close()

    store2 = PostgresGuardStateStore(pg_dsn_value)  # runs migrations again
    try:
        assert store2.is_nonce_consumed("migrate-nonce")
        assert len(store2.events_since(since=0)) == 1
    finally:
        store2.close()


def test_newer_schema_version_is_refused(pg_dsn_value):
    from tracesettle.guard.state import SCHEMA_VERSION
    from tracesettle.guard.state_pg import PostgresGuardStateStore

    store = PostgresGuardStateStore(pg_dsn_value)
    try:
        with store._connection.cursor() as cur:
            cur.execute("DELETE FROM schema_version")
            cur.execute("INSERT INTO schema_version(version) VALUES (%s)", (SCHEMA_VERSION + 1,))
        with pytest.raises(StateStoreError):
            PostgresGuardStateStore(pg_dsn_value)
    finally:
        with store._connection.cursor() as cur:
            cur.execute("DELETE FROM schema_version")
            cur.execute("INSERT INTO schema_version(version) VALUES (%s)", (SCHEMA_VERSION,))
        store.close()


# --- 9. retention cleanup does not delete active state ----------------------


def test_retention_keeps_active_state_and_drops_old(pg_dsn_value):
    from tracesettle.guard.state_pg import PostgresGuardStateStore

    store = PostgresGuardStateStore(pg_dsn_value)
    try:
        now = time.time()
        # An unexpired nonce and a fresh counter event must survive.
        store.consume_nonce("active-nonce", now + 3600)
        store.record_event(kind="DECISION", service_id="svc", outcome="ALLOW", at=now)
        # An expired nonce and an old counter event must be pruned.
        store.consume_nonce("expired-nonce", now - 3600)
        store.record_event(kind="DECISION", service_id="svc", outcome="ALLOW", at=now - 100000)

        store.prune_nonces(now=now)
        store.prune_events(before=now - 86400)

        assert store.is_nonce_consumed("active-nonce")
        assert not store.is_nonce_consumed("expired-nonce")
        remaining = store.events_since(since=0)
        assert len(remaining) == 1
    finally:
        store.close()


# --- 10. no in-memory fallback bypasses a PostgreSQL failure ----------------


def test_postgres_failure_never_falls_back_to_memory(pg_dsn_value):
    """With the shared store broken, evaluation holds; it does not use process memory."""
    from tracesettle.guard.state_pg import PostgresGuardStateStore

    store = PostgresGuardStateStore(pg_dsn_value)
    service = build_service(store, key=TEST_KEY)
    # A first allow records durable state.
    assert service.evaluate_payload(_PAYLOAD).decision is Decision.ALLOW
    # Break the shared database beyond recovery (point at a dead endpoint) and drop
    # the live connection, so the next decision cannot read or write shared state.
    store._connection.close()
    store._dsn = "host=127.0.0.1 port=1 dbname=none user=none password=none"
    store._connect_kwargs = {"connect_timeout": 2}
    decision = service.evaluate_payload(dict(_PAYLOAD, request_id="after-outage"))
    assert decision.decision is not Decision.ALLOW
    assert decision.authorization is None
    store.close()


# --- schema parity between SQLite and PostgreSQL ----------------------------


def test_postgres_and_sqlite_satisfy_the_same_contract(pg_dsn_value, tmp_path):
    """Both backends expose the identical surface and behave the same on it."""
    from tracesettle.guard.state import GuardStateStore, StateStore
    from tracesettle.guard.state_pg import PostgresGuardStateStore

    pg = PostgresGuardStateStore(pg_dsn_value)
    sq = GuardStateStore(tmp_path / "parity.db")
    try:
        for store in (pg, sq):
            assert isinstance(store, StateStore)
            assert store.schema_version() == 2
            assert store.consume_nonce("p", 2_000_000_000.0) is True
            assert store.consume_nonce("p", 2_000_000_000.0) is False
            assert store.remember_decision("k", "d1") is True
            assert store.remember_decision("k", "d2") is False
            assert store.decision_for("k") == "d1"
            store.revoke_authorization("a", 2_000_000_000.0)
            assert store.is_authorization_revoked("a") is True
            store.record_event(kind="DECISION", service_id="s", outcome="ALLOW",
                               asset="USDC", amount=Decimal("12.500000000000000001"))
            events = store.events_since(since=0)
            assert events[0].amount == Decimal("12.500000000000000001")
    finally:
        pg.close()
        sq.close()


def test_backend_label_differs(pg_dsn_value, tmp_path):
    from tracesettle.guard.state import GuardStateStore
    from tracesettle.guard.state_pg import PostgresGuardStateStore

    pg = PostgresGuardStateStore(pg_dsn_value)
    sq = GuardStateStore(tmp_path / "label.db")
    try:
        assert pg.backend == "postgresql"
        assert sq.backend == "sqlite"
    finally:
        pg.close()
        sq.close()


def test_postgres_invariant_holds_against_a_live_server(pg_dsn_value, monkeypatch):
    """The shared-state invariant is exercised for real when a server is configured."""
    from tracesettle.guard.invariants import INVARIANTS

    monkeypatch.setenv("TRACESETTLE_GUARD_STATE_PG_DSN", pg_dsn_value)
    result = INVARIANTS["postgres_shared_state_refuses_cross_instance_replay"]()
    assert result.holds, result.detail
