"""The NEAR execution boundary: the one path that may sign and broadcast.

Every test here drives the real serializer, the real transaction builder, the
real guard controls, and the real authorization authority. The only substitution
is the RPC transport (``FakeNearRpc``), which is a network boundary, not a logic
mock. "Nothing was broadcast" is asserted by inspecting the transport's recorded
submissions.
"""

from __future__ import annotations

import base64
import dataclasses
from decimal import Decimal

import pytest

from near_helpers import (
    BLOCK_HASH,
    RECIPIENT,
    SIGNER,
    TEST_SEED,
    FakeNearRpc,
    make_boundary,
    make_guard,
    near_policy,
    result_for,
    public_key_for_test,
)
from tracesettle.guard.model import Decision
from tracesettle.model import SourceStatus
from tracesettle.near import ed25519
from tracesettle.near.execution import ExecutionError, NearExecutionBoundary
from tracesettle.near.networks import NETWORKS, NearNetwork
from tracesettle.near.txbuild import OP_FT_TRANSFER, build_transfer
from tracesettle.near.verify import SettlementState


PUBLIC_KEY = public_key_for_test()


def _prepare(boundary, **overrides):
    kwargs = dict(
        service_id="treasury-agent",
        account_id=SIGNER,
        public_key=PUBLIC_KEY,
        receiver_id=RECIPIENT,
        asset_identifier="near:native",
        amount_human="1",
    )
    kwargs.update(overrides)
    return boundary.prepare(**kwargs)


def _sign(prepared):
    sig = ed25519.sign(prepared.transaction.tx_hash_bytes, TEST_SEED)
    return base64.b64encode(sig).decode()


# -- happy path ---------------------------------------------------------------


def test_authorized_transfer_reaches_verified():
    boundary, rpc = make_boundary()
    prepared = _prepare(boundary)
    assert prepared.decision.decision is Decision.ALLOW
    assert prepared.authorized
    rpc.send_result = result_for(prepared.transaction)
    executed = boundary.broadcast(prepared, _sign(prepared))
    assert executed.state is SettlementState.VERIFIED
    assert executed.verification.all_ok


def test_the_broadcast_is_the_exact_signed_transaction():
    """The bytes submitted are the bytes signed - not a re-built transaction."""
    boundary, rpc = make_boundary()
    prepared = _prepare(boundary)
    rpc.send_result = result_for(prepared.transaction)
    boundary.broadcast(prepared, _sign(prepared))
    assert len(rpc.broadcasts) == 1
    submitted = base64.b64decode(rpc.broadcasts[0])
    from tracesettle.near import borsh

    expected = prepared.transaction.unsigned_bytes() + borsh.signature_ed25519(
        ed25519.sign(prepared.transaction.tx_hash_bytes, TEST_SEED)
    )
    assert submitted == expected


def test_ft_transfer_builds_a_function_call_to_the_contract():
    boundary, rpc = make_boundary()
    prepared = _prepare(
        boundary,
        asset_identifier="usdc.fakes.testnet",
        amount_human="5",
    )
    assert prepared.decision.decision is Decision.ALLOW
    assert prepared.transaction.operation == OP_FT_TRANSFER
    assert prepared.transaction.receiver_id == "usdc.fakes.testnet"
    assert prepared.transaction.destination == RECIPIENT


# -- refusal: nothing is broadcast -------------------------------------------


def test_blocked_destination_is_never_broadcast():
    """An unapproved destination is BLOCK and no submission occurs."""
    guard = make_guard(near_policy(approved=frozenset({"someone-else.testnet"})))
    boundary, rpc = make_boundary(guard)
    prepared = _prepare(boundary)
    assert prepared.decision.decision is Decision.BLOCK
    assert not prepared.authorized
    with pytest.raises(ExecutionError):
        boundary.broadcast(prepared, "AAAA")
    assert rpc.broadcasts == []


def test_unlisted_destination_is_blocked_by_default():
    guard = make_guard(near_policy(approved=frozenset()))
    boundary, _ = make_boundary(guard)
    prepared = _prepare(boundary)
    assert prepared.decision.decision is Decision.BLOCK


def test_over_limit_amount_is_refused():
    guard = make_guard(near_policy(max_amount="1"))
    boundary, rpc = make_boundary(guard)
    prepared = _prepare(boundary, amount_human="2")
    assert prepared.decision.decision is Decision.BLOCK
    assert rpc.broadcasts == []


def test_over_approval_threshold_requires_approval_and_is_not_authorized():
    """A large-but-permitted amount is REQUIRE_APPROVAL, which cannot sign."""
    guard = make_guard(near_policy(max_amount="100", approval_threshold="0.5"))
    boundary, rpc = make_boundary(guard)
    prepared = _prepare(boundary, amount_human="10")
    assert prepared.decision.decision is Decision.REQUIRE_APPROVAL
    assert not prepared.authorized
    with pytest.raises(ExecutionError):
        boundary.accept_signature(prepared, _sign(prepared))
    assert rpc.broadcasts == []


def test_wrong_network_is_refused_before_anything_is_built():
    """A server configured for testnet refuses a mainnet operation."""
    boundary, _ = make_boundary(network=NearNetwork.TESTNET)
    with pytest.raises(ExecutionError):
        _prepare(boundary, network="mainnet")


def test_network_identity_mismatch_is_a_hard_error():
    """If the RPC claims a different chain, the boundary refuses."""
    guard = make_guard()
    rpc = FakeNearRpc(
        NETWORKS[NearNetwork.TESTNET],
        status_override={"chain_id": "mainnet", "genesis_hash": "EPnLgE7iEq9s7yTkos96M3cWymH5avBAPm3qx3NXqR8H"},
    )
    boundary = NearExecutionBoundary(guard, NETWORKS[NearNetwork.TESTNET], rpc=rpc)
    with pytest.raises(ExecutionError):
        _prepare(boundary)


def test_missing_access_key_is_refused():
    guard = make_guard()
    rpc = FakeNearRpc(NETWORKS[NearNetwork.TESTNET])
    rpc.access_key_missing = True
    boundary = NearExecutionBoundary(guard, NETWORKS[NearNetwork.TESTNET], rpc=rpc)
    with pytest.raises(ExecutionError):
        _prepare(boundary)


def test_unsupported_asset_is_refused():
    boundary, _ = make_boundary()
    with pytest.raises(ExecutionError):
        _prepare(boundary, asset_identifier="wNEAR")


def test_decimals_mismatch_is_refused_before_signing():
    """A contract reporting unexpected decimals must fail closed."""
    guard = make_guard()
    rpc = FakeNearRpc(NETWORKS[NearNetwork.TESTNET])
    rpc.decimals_override = {"decimals": 18}
    boundary = NearExecutionBoundary(guard, NETWORKS[NearNetwork.TESTNET], rpc=rpc)
    with pytest.raises(ExecutionError):
        _prepare(boundary, asset_identifier="usdc.fakes.testnet", amount_human="5")


# -- authorization binding ----------------------------------------------------


def _tamper(prepared, **tx_changes):
    new_tx = dataclasses.replace(prepared.transaction, **tx_changes)
    return dataclasses.replace(prepared, transaction=new_tx)


def test_amount_change_after_authorization_is_refused():
    boundary, rpc = make_boundary()
    prepared = _prepare(boundary)
    tampered = _tamper(prepared, amount_base=prepared.transaction.amount_base + 1)
    with pytest.raises(ExecutionError):
        boundary.accept_signature(tampered, _sign(prepared))
    assert rpc.broadcasts == []


def test_destination_change_after_authorization_is_refused():
    boundary, _ = make_boundary()
    prepared = _prepare(boundary)
    tampered = _tamper(prepared, destination="attacker.testnet")
    with pytest.raises(ExecutionError):
        boundary.accept_signature(tampered, _sign(prepared))


def test_asset_change_after_authorization_is_refused():
    from tracesettle.near.assets import resolve_asset

    boundary, _ = make_boundary()
    prepared = _prepare(boundary)
    other = resolve_asset(NearNetwork.TESTNET, "usdc.fakes.testnet")
    tampered = _tamper(prepared, asset=other, guard_asset=other.identifier.upper())
    with pytest.raises(ExecutionError):
        boundary.accept_signature(tampered, _sign(prepared))


def test_network_change_after_authorization_is_refused():
    """The chain carries the network, so a cross-network replay is a mismatch."""
    boundary, _ = make_boundary()
    prepared = _prepare(boundary)
    tampered = _tamper(prepared, guard_chain="near-mainnet")
    with pytest.raises(ExecutionError):
        boundary.accept_signature(tampered, _sign(prepared))


def test_service_change_after_authorization_is_refused():
    boundary, _ = make_boundary()
    prepared = _prepare(boundary)
    tampered = _tamper(prepared, service_id="another-agent")
    with pytest.raises(ExecutionError):
        boundary.accept_signature(tampered, _sign(prepared))


def test_an_unchanged_transaction_passes_the_binding():
    boundary, rpc = make_boundary()
    prepared = _prepare(boundary)
    rpc.send_result = result_for(prepared.transaction)
    # verify_only must not consume the token, so the real signature still works.
    boundary.verify_binding(prepared)
    executed = boundary.broadcast(prepared, _sign(prepared))
    assert executed.state is SettlementState.VERIFIED


def test_the_authorization_is_single_use():
    """A spent authorization cannot sign a second transaction (replay refused)."""
    boundary, rpc = make_boundary()
    prepared = _prepare(boundary)
    rpc.send_result = result_for(prepared.transaction)
    boundary.broadcast(prepared, _sign(prepared))
    with pytest.raises(ExecutionError):
        boundary.accept_signature(prepared, _sign(prepared))


def test_a_signature_for_another_transaction_is_refused():
    boundary, _ = make_boundary()
    prepared = _prepare(boundary)
    other = build_transfer(
        network=NearNetwork.TESTNET,
        signer_id=SIGNER,
        public_key=PUBLIC_KEY,
        nonce=999,
        receiver_id=RECIPIENT,
        block_hash=BLOCK_HASH,
        amount_human=Decimal("2"),
    )
    wrong_sig = base64.b64encode(ed25519.sign(other.tx_hash_bytes, TEST_SEED)).decode()
    with pytest.raises(ExecutionError):
        boundary.accept_signature(prepared, wrong_sig)


def test_a_malformed_signature_is_refused():
    boundary, _ = make_boundary()
    prepared = _prepare(boundary)
    for bad in ("not-base64!!", "", base64.b64encode(b"short").decode()):
        with pytest.raises(ExecutionError):
            boundary.accept_signature(prepared, bad)


# -- settlement verification --------------------------------------------------


def test_onchain_failure_is_failed_not_verified():
    boundary, rpc = make_boundary()
    prepared = _prepare(boundary)
    rpc.send_result = result_for(prepared.transaction, status_kind="failure")
    executed = boundary.broadcast(prepared, _sign(prepared))
    assert executed.state is SettlementState.FAILED


def test_wrong_amount_on_chain_is_disputed():
    boundary, rpc = make_boundary()
    prepared = _prepare(boundary)
    rpc.send_result = result_for(prepared.transaction, deposit="123")
    executed = boundary.broadcast(prepared, _sign(prepared))
    assert executed.state is SettlementState.DISPUTED


def test_non_final_transaction_is_pending():
    boundary, rpc = make_boundary()
    prepared = _prepare(boundary)
    rpc.send_result = result_for(prepared.transaction, finality="EXECUTED_OPTIMISTIC")
    executed = boundary.broadcast(prepared, _sign(prepared))
    assert executed.state is SettlementState.PENDING


def test_source_outage_is_insufficient_evidence_not_success():
    boundary, rpc = make_boundary()
    prepared = _prepare(boundary)
    rpc.send_status = SourceStatus.TIMEOUT
    rpc.send_result = None
    executed = boundary.broadcast(prepared, _sign(prepared))
    assert executed.state is SettlementState.INSUFFICIENT_EVIDENCE


def test_provider_success_alone_is_never_verified():
    """A success status with no matching on-chain record is not VERIFIED."""
    boundary, rpc = make_boundary()
    prepared = _prepare(boundary)
    rpc.send_result = {
        "final_execution_status": "FINAL",
        "status": {"SuccessValue": ""},
        "transaction": {"hash": "adifferenthash", "signer_id": SIGNER, "receiver_id": RECIPIENT, "nonce": 1, "actions": []},
        "transaction_outcome": {"block_hash": BLOCK_HASH, "outcome": {"logs": []}},
        "receipts_outcome": [],
    }
    executed = boundary.broadcast(prepared, _sign(prepared))
    assert executed.state is not SettlementState.VERIFIED
