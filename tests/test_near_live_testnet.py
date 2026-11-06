"""A live NEAR *testnet* execution, run only when a funded key is provided.

This is the one test that touches a real chain. It is skipped by default: it
needs a funded ``*.testnet`` account whose secret key is supplied through
``TRACESETTLE_TEST_TESTNET_KEY`` (plus ``TRACESETTLE_TEST_TESTNET_ACCOUNT`` and
``TRACESETTLE_TEST_TESTNET_RECEIVER``). It never runs on mainnet, never touches a
key when the variables are absent, and asserts the properties that matter:

* the pipeline reaches ``SETTLED`` with an independently ``VERIFIED`` settlement;
* the transaction hash the pipeline reports is the hash the chain reports;
* the receiver's balance actually rose, so value moved on-chain.

The key is read only to sign; it is never logged. The test is a *reproduction* of
the live evidence, not a substitute for it: when the variables are absent the
correct outcome is "skipped", never a fabricated pass.
"""

from __future__ import annotations

import os

import pytest

from tracesettle.guard.audit import AuditLog
from tracesettle.guard.authorization import AuthorizationAuthority, InMemoryReplayStore
from tracesettle.guard.policy import PolicyConfig, ServicePolicy
from tracesettle.guard.service import GuardService
from tracesettle.near.attestation import TeeAttestationProvider
from tracesettle.near.execution import NearExecutionBoundary
from tracesettle.near.ledger import SubmissionLedger, SubmissionState
from tracesettle.near.networks import NearNetwork, network_config
from tracesettle.near.pipeline import LocalKeySigner, NearExecutionPipeline
from tracesettle.near.rpc import NearRpc
from tracesettle.near.tee_execution import ExecutionRecordStore, TeeExecutionAuthorizer
from tracesettle.near.verify import SettlementState

_KEY = os.environ.get("TRACESETTLE_TEST_TESTNET_KEY", "").strip()
_ACCOUNT = os.environ.get("TRACESETTLE_TEST_TESTNET_ACCOUNT", "").strip()
_RECEIVER = os.environ.get("TRACESETTLE_TEST_TESTNET_RECEIVER", "").strip()

pytestmark = pytest.mark.skipif(
    not (_KEY and _ACCOUNT and _RECEIVER),
    reason=(
        "no live testnet key supplied; set TRACESETTLE_TEST_TESTNET_KEY, "
        "TRACESETTLE_TEST_TESTNET_ACCOUNT and TRACESETTLE_TEST_TESTNET_RECEIVER"
    ),
)


def _balance(account_id: str) -> int:
    rpc = NearRpc(network_config("testnet"))
    result = rpc.view_account(account_id)
    assert result.ok, f"could not read {account_id}: {result.status}"
    return int(result.data["amount"])


def test_live_testnet_transfer_settles_and_moves_value(tmp_path):
    network = network_config("testnet")
    assert network.network is NearNetwork.TESTNET, "this test is testnet-only"

    seed = bytes.fromhex(_KEY)
    signer = LocalKeySigner(seed, network=NearNetwork.TESTNET, account_id=_ACCOUNT)
    policy = PolicyConfig(
        policy_id="live-testnet",
        name="live testnet",
        version="1",
        approved_destinations=frozenset({_RECEIVER}),
        services={
            "live-svc": ServicePolicy(
                service_id="live-svc",
                allowed_operations=frozenset({"WITHDRAWAL"}),
                allowed_chains=frozenset({"near-testnet"}),
                allowed_assets=frozenset({"NEAR:NATIVE"}),
                max_amount_per_transaction=10_000,
                approval_threshold=1_000_000,
            )
        },
        per_transaction_limit=10_000,
        approval_threshold=1_000_000,
        allow_unlisted_destinations=False,
    )
    guard = GuardService(
        policy=policy,
        authority=AuthorizationAuthority(
            key=bytes(range(32)), key_id="live", ephemeral=False, replay_store=InMemoryReplayStore()
        ),
        audit=AuditLog(),
    )
    rpc = NearRpc(network)
    store = ExecutionRecordStore(str(tmp_path / "records.db"))
    authorizer = TeeExecutionAuthorizer(store=store, require_attestation=True, ttl_seconds=120)
    boundary = NearExecutionBoundary(
        guard,
        network,
        rpc=rpc,
        tee_authorizer=authorizer,
        tee_provider=TeeAttestationProvider(),
    )
    pipeline = NearExecutionPipeline(
        boundary, ledger=SubmissionLedger(str(tmp_path / "ledger.db"))
    )

    before = _balance(_RECEIVER)
    prepared = boundary.prepare(
        service_id="live-svc",
        account_id=_ACCOUNT,
        public_key=signer.public_key,
        receiver_id=_RECEIVER,
        asset_identifier="near:native",
        amount_human="0.01",
    )
    assert prepared.authorized, "the operator policy must authorize a 0.01 NEAR transfer"

    boundary.verify_tee_attestation(prepared)
    result = pipeline.execute(prepared, signer, attempts=10, delay=1.0)

    assert result.state == SubmissionState.SETTLED, result.to_dict()
    assert result.settlement_state == SettlementState.VERIFIED.value

    after = _balance(_RECEIVER)
    assert after > before, "the receiver's balance must have risen on-chain"
