"""Backend-selection tests for the guard state store.

These exercise the selection policy in ``open_state_store`` without a database, so
they run everywhere. The policy is fail-closed: a configured backend that cannot
be opened raises rather than silently degrading, and ``require_postgres`` refuses
any non-PostgreSQL selection.
"""

from __future__ import annotations

import subprocess
import sys

import pytest

from tracesettle.guard.state import GuardStateStore, StateStoreError, open_state_store


def test_auto_without_configuration_is_in_memory():
    assert open_state_store(None, backend="auto") is None


def test_auto_with_a_path_is_sqlite(tmp_path):
    store = open_state_store(tmp_path / "s.db", backend="auto")
    try:
        assert isinstance(store, GuardStateStore)
        assert store.backend == "sqlite"
    finally:
        store.close()


def test_explicit_memory_backend_is_in_memory():
    assert open_state_store("/tmp/ignored.db", backend="memory") is None


def test_explicit_sqlite_without_a_path_raises():
    with pytest.raises(StateStoreError):
        open_state_store(None, backend="sqlite")


def test_explicit_postgres_without_a_dsn_raises():
    with pytest.raises(StateStoreError):
        open_state_store(None, backend="postgresql", pg_dsn=None)


def test_unknown_backend_raises(tmp_path):
    with pytest.raises(StateStoreError):
        open_state_store(tmp_path / "s.db", backend="mysql")


def test_require_postgres_refuses_sqlite(tmp_path):
    with pytest.raises(StateStoreError):
        open_state_store(tmp_path / "s.db", backend="sqlite", require_postgres=True)


def test_require_postgres_refuses_memory():
    with pytest.raises(StateStoreError):
        open_state_store(None, backend="memory", require_postgres=True)


def test_require_postgres_refuses_auto_without_dsn():
    with pytest.raises(StateStoreError):
        open_state_store(None, backend="auto", pg_dsn=None, require_postgres=True)


def test_require_postgres_with_missing_dsn_raises_even_when_selected():
    with pytest.raises(StateStoreError):
        open_state_store(None, backend="postgresql", pg_dsn=None, require_postgres=True)


def test_auto_prefers_postgres_when_a_dsn_is_present(tmp_path):
    """auto with a DSN selects PostgreSQL, not the SQLite path also configured.

    The DSN points at a closed port, so opening raises — which proves the
    PostgreSQL branch was taken (a SQLite fallback would have succeeded).
    """
    with pytest.raises(StateStoreError):
        open_state_store(
            tmp_path / "would-be-sqlite.db",
            backend="auto",
            pg_dsn="host=127.0.0.1 port=1 dbname=none user=none password=none",
            pg_connect_timeout_s=2,
        )


def test_postgres_module_imports_without_psycopg():
    """The optional driver is imported lazily, so the package never needs it.

    A fresh interpreter that blocks ``psycopg`` must still import the module and
    construct nothing; the error surfaces only when a PostgreSQL store is opened.
    """
    script = (
        "import builtins, sys\n"
        "real = builtins.__import__\n"
        "def guard(name, *a, **k):\n"
        "    if name == 'psycopg' or name.startswith('psycopg.'):\n"
        "        raise ImportError('blocked for test')\n"
        "    return real(name, *a, **k)\n"
        "builtins.__import__ = guard\n"
        "import tracesettle.guard.state_pg as m\n"
        "from tracesettle.guard.state import StateStoreError\n"
        "try:\n"
        "    m.PostgresGuardStateStore('host=127.0.0.1 port=1')\n"
        "except StateStoreError:\n"
        "    print('lazy-ok')\n"
        "else:\n"
        "    print('unexpectedly-constructed')\n"
    )
    result = subprocess.run(
        [sys.executable, "-c", script],
        capture_output=True,
        text=True,
        cwd=__file__.rsplit("/tests/", 1)[0],
        check=False,
    )
    assert result.returncode == 0, result.stderr
    assert "lazy-ok" in result.stdout, result.stdout + result.stderr
