"""Tests for the ``credentials`` CLI subcommand.

These run the real parser and the real command functions against a temporary
store. They check the operational properties: the secret is printed once, the
store holds only hashes, the store is written owner-only, and revocation sticks.
"""

from __future__ import annotations

import json
import os
import stat

import pytest

from tracesettle.__main__ import build_parser, main


def _run(argv, capsys):
    code = main(argv)
    captured = capsys.readouterr()
    return code, captured.out


def test_mint_prints_the_secret_once_and_writes_a_hashed_store(tmp_path, capsys):
    store = tmp_path / "creds.json"
    code, out = _run(["credentials", "mint", "treasury-agent", "--store", str(store)], capsys)
    assert code == 0
    payload = json.loads(out)
    assert payload["service_id"] == "treasury-agent"
    secret = payload["secret"]
    assert secret

    raw = store.read_text()
    assert secret not in raw, "the plaintext secret was written to the store"
    stored = json.loads(raw)
    assert stored["credentials"][0]["secret_hash"].startswith("sha256:")
    assert stored["credentials"][0]["service_id"] == "treasury-agent"


def test_store_is_written_owner_only(tmp_path, capsys):
    store = tmp_path / "creds.json"
    _run(["credentials", "mint", "treasury-agent", "--store", str(store)], capsys)
    mode = stat.S_IMODE(os.stat(store).st_mode)
    assert mode == 0o600


def test_list_never_prints_a_secret(tmp_path, capsys):
    store = tmp_path / "creds.json"
    _, out = _run(["credentials", "mint", "treasury-agent", "--store", str(store)], capsys)
    secret = json.loads(out)["secret"]
    code, listed = _run(["credentials", "list", "--store", str(store)], capsys)
    assert code == 0
    assert secret not in listed
    data = json.loads(listed)
    assert data["active_service_ids"] == ["treasury-agent"]
    assert "secret_hash" not in json.dumps(data)


def test_revoke_persists(tmp_path, capsys):
    store = tmp_path / "creds.json"
    _, out = _run(["credentials", "mint", "treasury-agent", "--store", str(store)], capsys)
    secret = json.loads(out)["secret"]
    credential_id = json.loads(out)["credential_id"]

    code, revoked = _run(["credentials", "revoke", credential_id, "--store", str(store)], capsys)
    assert code == 0
    assert json.loads(revoked)["revoked"] is True

    stored = json.loads(store.read_text())
    assert stored["credentials"][0]["revoked"] is True
    # And the secret is no longer usable through a fresh registry.
    from tracesettle.serviceauth import ServiceRegistry

    registry = ServiceRegistry.load(store.read_text())
    assert registry.authenticate(secret).state.value == "REVOKED"


def test_mint_without_a_store_does_not_write_anything(tmp_path, capsys):
    code, out = _run(["credentials", "mint", "treasury-agent"], capsys)
    assert code == 0
    assert json.loads(out)["store_written"] is None
    assert list(tmp_path.iterdir()) == []


def test_two_mints_append_to_the_same_store(tmp_path, capsys):
    store = tmp_path / "creds.json"
    _run(["credentials", "mint", "treasury-agent", "--store", str(store)], capsys)
    _run(["credentials", "mint", "settlement-agent", "--store", str(store)], capsys)
    stored = json.loads(store.read_text())
    services = sorted(c["service_id"] for c in stored["credentials"])
    assert services == ["settlement-agent", "treasury-agent"]


def test_credentials_subcommand_requires_an_action():
    parser = build_parser()
    with pytest.raises(SystemExit):
        parser.parse_args(["credentials"])


# --- concurrency -----------------------------------------------------------


def test_concurrent_mints_do_not_lose_an_entry(tmp_path):
    """Concurrent read-modify-writes must all persist (the store lock serialises them).

    Regression: without the lock, two commands that read the same snapshot and
    write back would drop one another's credential.
    """
    import concurrent.futures

    from tracesettle.__main__ import _mutate_registry

    store = str(tmp_path / "creds.json")

    def mint(i):
        return _mutate_registry(store, lambda r: (r.mint(f"svc{i}")[0].credential_id, True))

    with concurrent.futures.ThreadPoolExecutor(max_workers=8) as ex:
        ids = list(ex.map(mint, range(8)))

    stored = json.loads((tmp_path / "creds.json").read_text())
    stored_ids = {c["credential_id"] for c in stored["credentials"]}
    assert stored_ids == set(ids)
    assert len(stored_ids) == 8


def test_a_concurrent_revoke_is_not_undone_by_a_mint(tmp_path):
    """A revoke must survive a concurrent mint; it must never be restored.

    Regression: an interleaved mint that read the pre-revoke snapshot would
    write the credential back as active, silently un-revoking it.
    """
    import concurrent.futures

    from tracesettle.__main__ import _mutate_registry

    store = str(tmp_path / "creds.json")
    victim_id = _mutate_registry(store, lambda r: (r.mint("victim")[0].credential_id, True))

    def do_mint(i):
        return _mutate_registry(store, lambda r: (r.mint(f"svc{i}")[0].credential_id, True))

    def do_revoke():
        return _mutate_registry(store, lambda r: (r.revoke(victim_id), True))

    with concurrent.futures.ThreadPoolExecutor(max_workers=6) as ex:
        futures = [ex.submit(do_mint, i) for i in range(5)]
        futures.append(ex.submit(do_revoke))
        for f in futures:
            f.result()

    stored = json.loads((tmp_path / "creds.json").read_text())
    victim = [c for c in stored["credentials"] if c["credential_id"] == victim_id][0]
    assert victim["revoked"] is True, "a concurrent mint restored a revoked credential"
    assert len(stored["credentials"]) == 6
