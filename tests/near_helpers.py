"""Helpers for the real-NEAR-integration tests.

The tests exercise the real serializer, the real transaction builder, the real
execution boundary, and the real guard. The only substitution is the **RPC
transport**: a :class:`FakeNearRpc` returns recorded/constructed RPC results so
the boundary's decision logic can be driven deterministically. That is a network
boundary, not a logic mock - every line of ``execution.py`` runs.
"""

from __future__ import annotations

from decimal import Decimal

from tracesettle.guard.audit import AuditLog
from tracesettle.guard.authorization import AuthorizationAuthority, InMemoryReplayStore
from tracesettle.guard.monitor import SecurityMonitor
from tracesettle.guard.policy import PolicyConfig, ServicePolicy
from tracesettle.guard.service import GuardService
from tracesettle.model import SourceStatus
from tracesettle.near import ed25519
from tracesettle.near.networks import NETWORKS, NearNetwork
from tracesettle.near.rpc import RpcResult

#: Deterministic test key material. Test-only; a deployment never holds a key.
TEST_SEED = bytes(range(32))
RECIPIENT = "alice.testnet"
SIGNER = "agent.testnet"
BLOCK_HASH = "9Gq9bHtf6SKUuWLbzgPMVedA3BtYbYVwb5NVUrQyzoE9"


def b58encode(raw: bytes) -> str:
    alphabet = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz"
    n = int.from_bytes(raw, "big")
    out = ""
    while n:
        n, r = divmod(n, 58)
        out = alphabet[r] + out
    pad = len(raw) - len(raw.lstrip(b"\x00"))
    return "1" * pad + (out or "")


def public_key_for_test() -> str:
    return "ed25519:" + b58encode(ed25519.public_key(TEST_SEED))


def near_policy(
    *,
    network_chain: str = "near-testnet",
    approved: frozenset[str] = frozenset({RECIPIENT}),
    allow_unlisted: bool = False,
    max_amount: str = "100",
    approval_threshold: str = "50",
    service_id: str = "treasury-agent",
) -> PolicyConfig:
    return PolicyConfig(
        policy_id="near-test",
        name="NEAR test policy",
        version="1",
        approved_destinations=approved,
        services={
            service_id: ServicePolicy(
                service_id=service_id,
                allowed_operations=frozenset({"WITHDRAWAL", "SETTLEMENT"}),
                allowed_chains=frozenset({network_chain}),
                allowed_assets=frozenset({"NEAR:NATIVE", "NEAR:USDC.FAKES.TESTNET"}),
                max_amount_per_transaction=Decimal(max_amount),
                max_amount_per_window=Decimal("1000"),
                approval_threshold=Decimal(approval_threshold),
            )
        },
        per_transaction_limit=Decimal(max_amount),
        window_seconds=3600,
        max_requests_per_window=30,
        max_blocked_per_window=5,
        approval_threshold=Decimal(approval_threshold),
        min_approvals=1,
        max_rejected_authorizations=3,
        authorization_ttl_seconds=90,
        allow_unlisted_destinations=allow_unlisted,
    )


def make_guard(policy: PolicyConfig | None = None) -> GuardService:
    return GuardService(
        policy=policy or near_policy(),
        authority=AuthorizationAuthority(
            key=TEST_SEED, key_id="test", ephemeral=False,
            replay_store=InMemoryReplayStore(), ttl_seconds=90,
        ),
        monitor=SecurityMonitor(),
        audit=AuditLog(),
    )


class FakeNearRpc:
    """A NEAR RPC transport driven by supplied results.

    Every method mirrors :class:`tracesettle.near.rpc.NearRpc` so the boundary
    calls it unchanged. ``broadcasts`` records the exact base64 that would have
    been submitted, so a test can assert that *nothing* was broadcast.
    """

    def __init__(self, config, *, nonce: int = 42, status_override: dict | None = None):
        self.config = config
        self.nonce = nonce
        self.broadcasts: list[str] = []
        self.status_override = status_override
        self.block_hash_value = BLOCK_HASH
        self.decimals_override: dict | None = None
        self.access_key_missing = False
        self.send_result: dict | None = None
        self.send_status = SourceStatus.OK
        self.tx_status_result: dict | None = None
        self.tx_status_status = SourceStatus.OK

    def status(self) -> RpcResult:
        if self.status_override is not None:
            return RpcResult(SourceStatus.OK, self.status_override)
        return RpcResult(SourceStatus.OK, {"chain_id": self.config.chain_id, "genesis_hash": self.config.genesis_hash})

    def block_hash(self, *, finality: str = "final") -> RpcResult:
        return RpcResult(SourceStatus.OK, {"hash": self.block_hash_value, "height": 1})

    def view_access_key(self, account_id: str, public_key: str) -> RpcResult:
        if self.access_key_missing:
            return RpcResult(SourceStatus.NOT_FOUND, error="unknown access key")
        return RpcResult(SourceStatus.OK, {"nonce": self.nonce})

    def call_function(self, account_id, method_name, args=None, *, finality="final") -> RpcResult:
        if self.decimals_override is not None:
            return RpcResult(SourceStatus.OK, self.decimals_override)
        # The registry's verified decimals, so the boundary's on-chain check
        # passes for the tokens the tests use.
        decimals = {"usdc.fakes.testnet": 6, "wrap.testnet": 24}.get(account_id, 24)
        return RpcResult(SourceStatus.OK, {"decimals": decimals})

    def send_tx(self, signed_transaction_b64: str, *, wait_until: str = "INCLUDED_FINAL") -> RpcResult:
        self.broadcasts.append(signed_transaction_b64)
        if self.send_result is not None:
            return RpcResult(self.send_status, self.send_result)
        return RpcResult(self.send_status, {})

    def tx_status(self, tx_hash: str, sender_account_id: str) -> RpcResult:
        if self.tx_status_result is not None:
            return RpcResult(self.tx_status_status, self.tx_status_result)
        return RpcResult(self.tx_status_status, {})


def result_for(tx, *, deposit: str | None = None, status_kind: str = "success", finality: str = "FINAL", receiver: str | None = None):
    """Build an RPC ``tx`` result matching a built transaction."""
    if deposit is None:
        deposit = str(tx.amount_base)
    status = {"SuccessValue": ""} if status_kind == "success" else {"Failure": {"error_message": "x"}}
    return {
        "final_execution_status": finality,
        "status": status,
        "transaction": {
            "hash": tx.tx_hash,
            "signer_id": tx.signer_id,
            "receiver_id": receiver if receiver is not None else tx.receiver_id,
            "nonce": tx.nonce,
            "actions": [{"Transfer": {"deposit": deposit}}] if tx.operation == "TRANSFER" else [],
        },
        "transaction_outcome": {"block_hash": BLOCK_HASH, "outcome": {"logs": []}},
        "receipts_outcome": [],
    }


def make_boundary(guard: GuardService | None = None, *, network: NearNetwork = NearNetwork.TESTNET, **rpc_kwargs):
    from tracesettle.near.execution import NearExecutionBoundary

    config = NETWORKS[network]
    rpc = FakeNearRpc(config, **rpc_kwargs)
    return NearExecutionBoundary(guard or make_guard(), config, rpc=rpc), rpc


class FakeTeeProvider:
    """A TEE provider whose verdict the test controls.

    It returns an :class:`~tracesettle.near.attestation.AttestationResult`-shaped
    object, so the real ``TeeExecutionAuthorizer`` binding logic runs unchanged.
    The default is a *verified* attestation whose nonce the caller supplies; a
    test can flip ``verified`` off or return a wrong nonce to drive the refusal
    paths. It is a transport stand-in for the gateway, not a logic mock: every
    line of ``tee_execution.py`` and ``execution.py`` runs.
    """

    def __init__(self, *, verified: bool = True, nonce_override: str | None = None, measurement: dict | None = None):
        from tracesettle.near.attestation import AttestationResult
        from tracesettle.near.tee import AttestationStatus

        self._verified = verified
        self._nonce_override = nonce_override
        self._measurement = measurement if measurement is not None else {"rt_mr0": "aa" * 48}
        self._result_cls = AttestationResult
        self._status = AttestationStatus
        self.calls = 0

    def attest(self, nonce: bytes):
        self.calls += 1
        nonce_hex = self._nonce_override if self._nonce_override is not None else nonce.hex()
        return self._result_cls(
            status=self._status.VERIFIED if self._verified else self._status.UNVERIFIABLE,
            detail="test attestation",
            nonce=nonce_hex,
            provider="test-provider",
            verification={"measurement": self._measurement, "verified": self._verified},
            fetched=True,
            source_status="OK",
        )


def make_tee_boundary(guard: GuardService | None = None, *, provider=None, expected_measurement: str = "", **kwargs):
    """A boundary with the TEE gate enabled, plus its authorizer and provider."""
    from tracesettle.near.execution import NearExecutionBoundary
    from tracesettle.near.tee_execution import ExecutionRecordStore, TeeExecutionAuthorizer

    config = NETWORKS[kwargs.pop("network", NearNetwork.TESTNET)]
    rpc = FakeNearRpc(config, **kwargs)
    authorizer = TeeExecutionAuthorizer(
        store=ExecutionRecordStore(),
        require_attestation=True,
        expected_measurement=expected_measurement,
        ttl_seconds=90,
    )
    provider = provider or FakeTeeProvider()
    boundary = NearExecutionBoundary(
        guard or make_guard(),
        config,
        rpc=rpc,
        tee_authorizer=authorizer,
        tee_provider=provider,
    )
    return boundary, rpc, authorizer, provider
