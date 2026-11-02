"""Shared helpers for the PostgreSQL guard-state integration tests.

These tests require a **real** PostgreSQL server: the whole point is that
distributed correctness comes from the database (row locks, unique constraints,
advisory locks), which SQLite cannot stand in for. The connection string is read
from ``TRACESETTLE_TEST_PG_DSN``; when it is unset the tests skip, so the default
``pytest tests/`` run stays green without a database, while CI (and any developer
with a server) exercises them for real.

The tests never assume a credential and never print one.
"""

from __future__ import annotations

import os

#: Set this to a libpq connection string, e.g.
#: ``postgresql://user:pass@127.0.0.1:5432/tracesettle_test``.
PG_DSN_ENV = "TRACESETTLE_TEST_PG_DSN"

#: Every table the store owns, in a safe truncation order.
_TABLES = (
    "counter_events",
    "consumed_nonces",
    "revoked_authorizations",
    "idempotency",
)


def pg_dsn() -> str | None:
    value = os.environ.get(PG_DSN_ENV)
    return value if value and value.strip() else None


def pg_available() -> bool:
    if pg_dsn() is None:
        return False
    try:
        from tracesettle.guard.state_pg import PostgresGuardStateStore
    except Exception:  # pragma: no cover - only without psycopg
        return False
    try:
        store = PostgresGuardStateStore(pg_dsn(), check_connection=True)
    except Exception:
        return False
    store.close()
    return True


def _truncate(store) -> None:  # noqa: ANN001
    with store._connection.cursor() as cur:
        cur.execute("TRUNCATE " + ", ".join(_TABLES))


def build_service(store, *, key: bytes, ttl_seconds: int = 90, policy=None):  # noqa: ANN001
    """A guard service whose authority and counters are backed by ``store``."""
    from tracesettle.guard.authorization import AuthorizationAuthority
    from tracesettle.guard.policy import DEFAULT_POLICY
    from tracesettle.guard.service import GuardService
    from tracesettle.guard.state import DurableReplayStore, DurableRevocationStore

    authority = AuthorizationAuthority(
        key=key,
        key_id="pg-test-key",
        ephemeral=False,
        replay_store=DurableReplayStore(store),
        revocations=DurableRevocationStore(store),
        ttl_seconds=ttl_seconds,
    )
    return GuardService(
        policy=policy or DEFAULT_POLICY,
        authority=authority,
        state_store=store,
    )
