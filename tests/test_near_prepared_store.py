"""The prepared-operation store and the bounded finality wait.

The store is what makes prepare/submit safe: a signature is applied to the exact
operation that was authorized, the entry is single-use, owner-scoped, bounded and
expiring.
"""

from __future__ import annotations

import base64

from near_helpers import RECIPIENT, SIGNER, TEST_SEED, make_boundary, result_for
from tracesettle.near import ed25519
from tracesettle.near.execution import PreparedOperationStore
from tracesettle.near.verify import SettlementState


def _prepared(boundary):
    return boundary.prepare(
        service_id="treasury-agent",
        account_id=SIGNER,
        public_key="ed25519:" + _pk(),
        receiver_id=RECIPIENT,
        asset_identifier="near:native",
        amount_human="1",
    )


def _pk():
    from near_helpers import public_key_for_test

    return public_key_for_test().split(":", 1)[1]


# -- store --------------------------------------------------------------------


def test_store_round_trips_for_the_owner():
    store = PreparedOperationStore()
    boundary, _ = make_boundary()
    prepared = _prepared(boundary)
    pid = store.store(prepared, "svc-a")
    assert store.peek(pid, "svc-a") is prepared


def test_store_hides_entries_from_another_owner():
    store = PreparedOperationStore()
    boundary, _ = make_boundary()
    pid = store.store(_prepared(boundary), "svc-a")
    assert store.peek(pid, "svc-b") is None
    assert store.take(pid, "svc-b") is None
    # The real owner can still take it.
    assert store.take(pid, "svc-a") is not None


def test_take_is_single_use():
    store = PreparedOperationStore()
    boundary, _ = make_boundary()
    pid = store.store(_prepared(boundary), "svc-a")
    assert store.take(pid, "svc-a") is not None
    assert store.take(pid, "svc-a") is None


def test_store_is_bounded():
    store = PreparedOperationStore(max_entries=3)
    boundary, _ = make_boundary()
    ids = [store.store(_prepared(boundary), "svc-a") for _ in range(5)]
    assert store.peek(ids[0], "svc-a") is None  # evicted
    assert store.peek(ids[-1], "svc-a") is not None


def test_store_entries_expire():
    clock = {"t": 0.0}
    store = PreparedOperationStore(ttl_seconds=10, clock=lambda: clock["t"])
    boundary, _ = make_boundary()
    pid = store.store(_prepared(boundary), "svc-a")
    clock["t"] = 11.0
    assert store.peek(pid, "svc-a") is None


# -- finality wait ------------------------------------------------------------


def test_wait_for_final_returns_verified_when_the_record_becomes_final():
    boundary, rpc = make_boundary()
    prepared = _prepared(boundary)
    rpc.send_result = result_for(prepared.transaction)
    boundary.broadcast(prepared, _sign(prepared))
    rpc.tx_status_result = result_for(prepared.transaction, finality="FINAL")
    verification = boundary.wait_for_final(prepared, attempts=3, delay=0)
    assert verification.state is SettlementState.VERIFIED


def test_wait_for_final_never_fabricates_finality():
    """If the record never becomes final, the result stays non-final."""
    boundary, rpc = make_boundary()
    prepared = _prepared(boundary)
    rpc.send_result = result_for(prepared.transaction)
    boundary.broadcast(prepared, _sign(prepared))
    rpc.tx_status_result = result_for(prepared.transaction, finality="EXECUTED_OPTIMISTIC")
    verification = boundary.wait_for_final(prepared, attempts=3, delay=0)
    assert verification.state is SettlementState.PENDING


def _sign(prepared):
    return base64.b64encode(ed25519.sign(prepared.transaction.tx_hash_bytes, TEST_SEED)).decode()
