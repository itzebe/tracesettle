"""Tests for the durable settlement-investigation store.

These prove the property that matters for the product: an investigation produced
before a restart is retrievable afterward, with its evidence and its conclusion
intact, and a conclusion is reproducible from what was recorded rather than
re-derived from live sources.
"""

from __future__ import annotations

import pytest

from tracesettle.investigation_store import (
    SCHEMA_VERSION,
    InvestigationStore,
    InvestigationStoreError,
)


def _report(investigation_id="ts-abc", identifier="0xB741c00f6D63b6dEd0cCADA1a82bCBADc38A572B", outcome="SETTLED_VERIFIED"):
    return {
        "investigation_id": investigation_id,
        "input": {"identifier": identifier, "identifier_type": "DEPOSIT_ADDRESS"},
        "outcome": outcome,
        "created_at": "2026-11-03T00:00:00Z",
        "evidence": [
            {"stage": "SOURCE_CHAIN_DEPOSIT", "classification": "CONFIRMED", "summary": "deposit confirmed"}
        ],
        "settlement_assurance": {"level": "VERIFIED", "independently_verified": True},
    }


@pytest.fixture
def store(tmp_path):
    s = InvestigationStore(tmp_path / "investigations.db")
    yield s
    s.close()


def test_schema_version_is_recorded(store):
    assert store.schema_version == SCHEMA_VERSION


def test_a_report_round_trips_losslessly(store):
    report = _report()
    store.save(report)
    loaded = store.get("ts-abc")
    assert loaded == report


def test_a_report_survives_a_restart(tmp_path):
    path = tmp_path / "investigations.db"
    first = InvestigationStore(path)
    first.save(_report())
    first.close()

    second = InvestigationStore(path)
    loaded = second.get("ts-abc")
    second.close()
    assert loaded is not None
    assert loaded["outcome"] == "SETTLED_VERIFIED"
    assert loaded["evidence"][0]["classification"] == "CONFIRMED"


def test_a_re_run_replaces_the_same_investigation(store):
    store.save(_report(outcome="UNKNOWN"))
    store.save(_report(outcome="SETTLED_VERIFIED"))
    assert store.get("ts-abc")["outcome"] == "SETTLED_VERIFIED"
    assert len(store.list_for_owner()) == 1


def test_cross_owner_isolation(store):
    store.save(_report(), owner="service-a")
    assert store.get("ts-abc", owner="service-a") is not None
    assert store.get("ts-abc", owner="service-b") is None
    assert store.list_for_owner("service-b") == []


def test_list_returns_newest_first(store):
    store.save(_report("ts-1", outcome="UNKNOWN"))
    newer = _report("ts-2", outcome="SETTLED_VERIFIED")
    newer["created_at"] = "2026-11-04T00:00:00Z"
    store.save(newer)
    ids = [row["investigation_id"] for row in store.list_for_owner()]
    assert ids[0] == "ts-2"


def test_a_report_without_an_id_is_refused(store):
    with pytest.raises(InvestigationStoreError):
        store.save({"outcome": "UNKNOWN"})


def test_a_newer_schema_is_refused(tmp_path):
    path = tmp_path / "investigations.db"
    first = InvestigationStore(path)
    with first._transaction() as conn:
        conn.execute("DELETE FROM schema_version")
        conn.execute("INSERT INTO schema_version (version) VALUES (?)", (SCHEMA_VERSION + 1,))
    first.close()
    with pytest.raises(InvestigationStoreError):
        InvestigationStore(path)


def test_an_unopenable_path_is_a_hard_error(tmp_path):
    with pytest.raises(InvestigationStoreError):
        InvestigationStore(tmp_path / "missing" / "nested" / "investigations.db")
