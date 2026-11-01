"""Shared helpers for the transaction-security tests.

The guard layer has no network dependency, so these tests exercise the real
controls, the real authorization authority, the real replay store, and the real
reference signer. Nothing is mocked.
"""

from __future__ import annotations

from decimal import Decimal

import pytest

from tracesettle.guard.audit import AuditLog
from tracesettle.guard.authorization import AuthorizationAuthority, InMemoryReplayStore
from tracesettle.guard.model import TransactionRequest
from tracesettle.guard.monitor import SecurityMonitor
from tracesettle.guard.policy import DEFAULT_POLICY, PolicyConfig, ServicePolicy
from tracesettle.guard.service import GuardService
from tracesettle.guard.signer import ReferenceSigner

#: A fixed 32-byte key so authorization tests are deterministic. This is test
#: material only; it is never used by a deployment.
TEST_KEY = bytes(range(32))

APPROVED_DESTINATION = "0x4e6d3A556e485188E9C9a528bc72c88BD92BD735"
OTHER_APPROVED_DESTINATION = "0xb741c00f6d63b6ded0ccada1a82bcbadc38a572b"
UNAPPROVED_DESTINATION = "0x9f8A2c4b7e6D1f03aB5C8e2947D6f10B3aE4c5D6"
DENIED_DESTINATION = "0x000000000000000000000000000000000000dEaD"


def make_request(**overrides) -> TransactionRequest:
    base = {
        "request_id": "req-test-1",
        "service_id": "treasury-agent",
        "operation": "WITHDRAWAL",
        "chain": "eth",
        "asset": "USDC",
        "amount": Decimal("100"),
        "destination": APPROVED_DESTINATION,
        "amount_raw": "100",
    }
    base.update(overrides)
    return TransactionRequest(**base)


def make_authority(*, ttl_seconds: int = 90, clock=None) -> AuthorizationAuthority:
    return AuthorizationAuthority(
        key=TEST_KEY,
        key_id="test-key",
        ephemeral=False,
        replay_store=InMemoryReplayStore(),
        ttl_seconds=ttl_seconds,
        clock=clock,
    )


def make_service(
    *,
    policy: PolicyConfig | None = None,
    authority: AuthorizationAuthority | None = None,
    monitor: SecurityMonitor | None = None,
    audit: AuditLog | None = None,
    signer: ReferenceSigner | None = None,
) -> GuardService:
    return GuardService(
        policy=policy or DEFAULT_POLICY,
        authority=authority or make_authority(),
        monitor=monitor or SecurityMonitor(),
        audit=audit or AuditLog(),
        signer=signer,
    )


def make_signer(service: GuardService) -> ReferenceSigner:
    return ReferenceSigner(service.authority)


@pytest.fixture
def authority() -> AuthorizationAuthority:
    return make_authority()


@pytest.fixture
def service() -> GuardService:
    return make_service()


@pytest.fixture
def policy() -> PolicyConfig:
    return DEFAULT_POLICY


@pytest.fixture
def treasury_policy() -> ServicePolicy:
    return DEFAULT_POLICY.services["treasury-agent"]
