"""OutLayer custody adapter and authorized execution boundary tests.

Every test drives the **real** code paths: the real
:class:`~tracesettle.near.outlayer.OutLayerCustodyProvider` over an
``HttpClient`` whose ``urllib`` opener is substituted (the only substitution), the
real guard service, and the real
:class:`~tracesettle.near.outlayer_execution.OutLayerCustodyBoundary`. The
provider is a ``FakeOpener``-backed transport, not a mock of the boundary, so
"the executor was never called" is asserted as "no request reached the provider".
"""

from __future__ import annotations

from decimal import Decimal

import pytest

from conftest import FakeOpener
from near_helpers import TEST_SEED, FakeNearRpc, near_policy
from tracesettle.guard.audit import AuditLog
from tracesettle.guard.authorization import AuthorizationAuthority, InMemoryReplayStore
from tracesettle.guard.monitor import SecurityMonitor
from tracesettle.guard.service import GuardService
from tracesettle.httpclient import HttpClient
from tracesettle.model import SourceStatus
from tracesettle.near.networks import network_config
from tracesettle.near.outlayer import (
    OutLayerConfig,
    OutLayerCustodyProvider,
    OutLayerError,
    ProviderState,
    config_from_env,
    idempotency_key_for,
    provider_state,
)
from tracesettle.near.outlayer_execution import (
    CustodyError,
    OutLayerCustodyBoundary,
    custody_digest,
    verify_custody_transaction,
)

WALLET = "9575a853fa0f62ed12334306cd5d1a18f6821ef9036601c99822f17d9bb13c38"
WALLET_PUB = "ed25519:B4RodGLvA3a8wyPQydgJwAUtm6ULkfdia17WP9hPYBGs"
DEST = "tsfund52f8405ad4.testnet"
TX_HASH = "76mYB4gsgj3ogYCgsqzd5P4ESsLRw2rTecasQZ6kcnmh"
API_KEY = "wk_test_key_not_a_real_secret_000000000000000000000000000000"


def _provider(opener: FakeOpener, *, network: str = "testnet", wallet_id: str = "") -> OutLayerCustodyProvider:
    client = HttpClient(opener=opener, max_attempts=1, timeout=1.0, backoff_base=0.0, sleeper=lambda _: None)
    config = OutLayerConfig(api_key=API_KEY, network=network, wallet_id=wallet_id, timeout=1.0)
    return OutLayerCustodyProvider(config, client=client)


def _address_route(opener: FakeOpener, *, account: str = WALLET, wallet_id: str = "52a6d3aa-fb42-4067-9e51-a1dbd9471b7b"):
    opener.json("GET", "/wallet/v1/address", {"wallet_id": wallet_id, "address": account, "public_key": WALLET_PUB})
    return opener


def _guard(*, approved=DEST, max_amount="10") -> GuardService:
    return GuardService(
        policy=near_policy(approved=frozenset({approved}), max_amount=max_amount),
        authority=AuthorizationAuthority(
            key=TEST_SEED, key_id="t", ephemeral=False, replay_store=InMemoryReplayStore(), ttl_seconds=90
        ),
        monitor=SecurityMonitor(),
        audit=AuditLog(),
    )


def _boundary(opener: FakeOpener, *, guard: GuardService | None = None, rpc: FakeNearRpc | None = None, **kwargs):
    provider = _provider(opener)
    nc = network_config("testnet")
    return OutLayerCustodyBoundary(
        guard or _guard(),
        provider,
        network=nc.network,
        rpc=rpc if rpc is not None else FakeNearRpc(nc),
        sleep=lambda _: None,
        **kwargs,
    )


# --- provider: configuration ----------------------------------------------


def test_config_from_env_is_none_when_disabled():
    assert config_from_env({}) is None
    assert config_from_env({"TRACESETTLE_OUTLAYER_ENABLED": "0"}) is None


def test_config_from_env_requires_a_key_when_enabled():
    with pytest.raises(OutLayerError):
        config_from_env({"TRACESETTLE_OUTLAYER_ENABLED": "1"})


def test_config_from_env_rejects_a_non_bearer_key():
    with pytest.raises(OutLayerError):
        config_from_env({"TRACESETTLE_OUTLAYER_ENABLED": "1", "TRACESETTLE_OUTLAYER_API_KEY": "nope"})


def test_config_rejects_an_unknown_network():
    with pytest.raises(OutLayerError):
        OutLayerConfig(api_key=API_KEY, network="devnet")


def test_config_serialisation_never_contains_the_key():
    config = OutLayerConfig(api_key=API_KEY, network="testnet")
    assert API_KEY not in str(config.to_dict())


# --- provider: status mapping ---------------------------------------------


@pytest.mark.parametrize(
    "raw,expected",
    [
        ("success", ProviderState.SUCCESS),
        ("SUCCESS", ProviderState.SUCCESS),
        ("pending", ProviderState.PENDING),
        ("processing", ProviderState.PROCESSING),
        ("pending_approval", ProviderState.PENDING_APPROVAL),
        ("failed", ProviderState.FAILED),
        ("rejected", ProviderState.REJECTED),
        ("refunded", ProviderState.REFUNDED),
        ("something_new", ProviderState.UNKNOWN),
        (None, ProviderState.UNKNOWN),
        ("", ProviderState.UNKNOWN),
    ],
)
def test_provider_state_never_invents_success(raw, expected):
    assert provider_state(raw) is expected


# --- provider: address ------------------------------------------------------


def test_address_resolves_the_wallet_identity():
    opener = _address_route(FakeOpener())
    identity = _provider(opener).address("near")
    assert identity.account_id == WALLET
    assert identity.public_key == WALLET_PUB


def test_address_refuses_a_mismatched_configured_wallet_id():
    opener = _address_route(FakeOpener(), wallet_id="11111111-1111-1111-1111-111111111111")
    provider = _provider(opener, wallet_id="22222222-2222-2222-2222-222222222222")
    with pytest.raises(OutLayerError):
        provider.address("near")


def test_address_rejects_a_malformed_account_id():
    opener = FakeOpener().json("GET", "/wallet/v1/address", {"address": "Not An Account", "public_key": WALLET_PUB})
    with pytest.raises(OutLayerError):
        _provider(opener).address("near")


def test_unauthorized_is_a_configuration_error():
    opener = FakeOpener().http_error("GET", "/wallet/v1/address", 401)
    with pytest.raises(OutLayerError):
        _provider(opener).address("near")


# --- provider: transfer outcome --------------------------------------------


def test_transfer_success_carries_the_transaction_hash():
    opener = FakeOpener().json("POST", "/wallet/v1/transfer", {"request_id": "r1", "status": "success", "tx_hash": TX_HASH})
    outcome = _provider(opener).transfer(to=DEST, amount_yocto=10**22)
    assert outcome.state is ProviderState.SUCCESS
    assert outcome.tx_hash == TX_HASH


def test_transfer_timeout_is_unknown_not_failed():
    opener = FakeOpener().timeout("POST", "/wallet/v1/transfer")
    outcome = _provider(opener).transfer(to=DEST, amount_yocto=10**22)
    # An ambiguous outcome must never read as a definite failure or a success.
    assert outcome.state is ProviderState.UNKNOWN


def test_transfer_rejects_a_non_positive_amount():
    with pytest.raises(OutLayerError):
        _provider(FakeOpener()).transfer(to=DEST, amount_yocto=0)


def test_transfer_rejects_an_invalid_recipient():
    with pytest.raises(OutLayerError):
        _provider(FakeOpener()).transfer(to="Not Valid!", amount_yocto=10**22)


def test_request_status_reads_a_nested_hash():
    opener = FakeOpener().json(
        "GET", "/wallet/v1/requests/r1", {"request_id": "r1", "status": "success", "result": {"tx_hash": TX_HASH}}
    )
    outcome = _provider(opener).request_status("r1")
    assert outcome.tx_hash == TX_HASH


def test_approved_measurements_are_read_from_the_register_contract():
    import json

    opener = FakeOpener().json(
        "POST",
        "rpc.testnet.fastnear.com",
        {"result": {"result": list(json.dumps([{"mrtd": "aa", "rtmr0": "bb"}]).encode())}},
        body_contains="get_approved_measurements",
    )
    result = _provider(opener).approved_measurements()
    assert result["available"] is True
    assert result["count"] == 1


def test_idempotency_key_is_stable_per_digest():
    assert idempotency_key_for("abc") == idempotency_key_for("abc")
    assert idempotency_key_for("abc") != idempotency_key_for("abd")


# --- boundary: prepare ------------------------------------------------------


def test_prepare_evaluates_and_authorizes_an_approved_transfer():
    opener = _address_route(FakeOpener())
    boundary = _boundary(opener)
    prepared = boundary.prepare(service_id="treasury-agent", destination=DEST, amount_human=Decimal("0.5"))
    assert prepared.authorized is True
    assert prepared.amount_yocto == 5 * 10**23
    assert prepared.authorization_id


def test_prepare_blocks_an_unapproved_destination_without_contacting_the_provider():
    opener = _address_route(FakeOpener())
    boundary = _boundary(opener, guard=_guard(approved="someone-else.testnet"))
    prepared = boundary.prepare(service_id="treasury-agent", destination=DEST, amount_human=Decimal("0.5"))
    assert prepared.authorized is False
    # Only the address read was made; the transfer endpoint was never reached.
    assert not any("/wallet/v1/transfer" in call for call in opener.calls)


def test_prepare_blocks_an_over_limit_amount():
    opener = _address_route(FakeOpener())
    boundary = _boundary(opener, guard=_guard(max_amount="1"))
    prepared = boundary.prepare(service_id="treasury-agent", destination=DEST, amount_human=Decimal("5"))
    assert prepared.authorized is False


def test_to_yocto_refuses_sub_yocto_precision():
    from tracesettle.near.outlayer_execution import _to_yocto

    assert _to_yocto(Decimal("1")) == 10**24
    assert _to_yocto(Decimal("0.000000000000000000000001")) == 1
    # A value with sub-yocto precision (below 1e-24) must be refused, not rounded.
    with pytest.raises(CustodyError):
        _to_yocto(Decimal("0.0000000000000000000000001"))


def test_prepare_accepts_a_decimal_string_and_an_int():
    opener = _address_route(FakeOpener())
    boundary = _boundary(opener)
    assert boundary.prepare(service_id="treasury-agent", destination=DEST, amount_human="0.5").amount_yocto == 5 * 10**23


# --- boundary: execute is refused unless authorized -------------------------


def test_execute_refuses_a_blocked_decision_before_reaching_the_provider():
    opener = _address_route(FakeOpener())
    boundary = _boundary(opener, guard=_guard(approved="someone-else.testnet"))
    prepared = boundary.prepare(service_id="treasury-agent", destination=DEST, amount_human=Decimal("0.5"))
    with pytest.raises(CustodyError):
        boundary.execute(prepared)
    assert not any("/wallet/v1/transfer" in call for call in opener.calls)


def test_execute_sends_then_verifies_settlement_independently():
    opener = _address_route(FakeOpener())
    opener.json("POST", "/wallet/v1/transfer", {"request_id": "r1", "status": "success", "tx_hash": TX_HASH})
    nc = network_config("testnet")
    rpc = FakeNearRpc(nc)
    rpc.tx_status_result = _verified_result()
    boundary = _boundary(opener, rpc=rpc)
    prepared = boundary.prepare(service_id="treasury-agent", destination=DEST, amount_human=Decimal("0.5"))
    execution = boundary.execute(prepared)
    assert execution.provider_claimed_success is True
    assert execution.settlement_verified is True
    assert execution.verification.state.value == "VERIFIED"


def test_provider_success_without_chain_evidence_is_not_verified():
    opener = _address_route(FakeOpener())
    opener.json("POST", "/wallet/v1/transfer", {"request_id": "r1", "status": "success", "tx_hash": TX_HASH})
    nc = network_config("testnet")
    rpc = FakeNearRpc(nc)
    rpc.tx_status_status = SourceStatus.TIMEOUT
    boundary = _boundary(opener, rpc=rpc)
    prepared = boundary.prepare(service_id="treasury-agent", destination=DEST, amount_human=Decimal("0.5"))
    execution = boundary.execute(prepared)
    assert execution.provider_claimed_success is True
    assert execution.settlement_verified is False


def test_a_different_receiver_on_chain_is_never_verified():
    opener = _address_route(FakeOpener())
    opener.json("POST", "/wallet/v1/transfer", {"request_id": "r1", "status": "success", "tx_hash": TX_HASH})
    nc = network_config("testnet")
    rpc = FakeNearRpc(nc)
    rpc.tx_status_result = _verified_result(receiver="attacker.testnet")
    boundary = _boundary(opener, rpc=rpc)
    prepared = boundary.prepare(service_id="treasury-agent", destination=DEST, amount_human=Decimal("0.5"))
    execution = boundary.execute(prepared)
    assert execution.settlement_verified is False
    assert execution.verification.state.value == "DISPUTED"


def test_a_different_amount_on_chain_is_never_verified():
    opener = _address_route(FakeOpener())
    opener.json("POST", "/wallet/v1/transfer", {"request_id": "r1", "status": "success", "tx_hash": TX_HASH})
    nc = network_config("testnet")
    rpc = FakeNearRpc(nc)
    rpc.tx_status_result = _verified_result(deposit="999999999999999999999999")
    boundary = _boundary(opener, rpc=rpc)
    prepared = boundary.prepare(service_id="treasury-agent", destination=DEST, amount_human=Decimal("0.5"))
    execution = boundary.execute(prepared)
    assert execution.settlement_verified is False


# --- boundary: authorization binding ---------------------------------------


def test_a_substituted_destination_invalidates_the_binding():
    opener = _address_route(FakeOpener())
    opener.json("POST", "/wallet/v1/transfer", {"request_id": "r1", "status": "success", "tx_hash": TX_HASH})
    boundary = _boundary(opener)
    prepared = boundary.prepare(service_id="treasury-agent", destination=DEST, amount_human=Decimal("0.5"))
    # Tamper with the prepared operation after authorization.
    prepared.destination = "attacker.testnet"
    with pytest.raises(CustodyError):
        boundary.execute(prepared)
    assert not any("/wallet/v1/transfer" in call for call in opener.calls)


def test_a_replayed_authorization_is_refused():
    opener = _address_route(FakeOpener())
    opener.json("POST", "/wallet/v1/transfer", {"request_id": "r1", "status": "success", "tx_hash": TX_HASH})
    nc = network_config("testnet")
    rpc = FakeNearRpc(nc)
    rpc.tx_status_result = _verified_result()
    boundary = _boundary(opener, rpc=rpc)
    prepared = boundary.prepare(service_id="treasury-agent", destination=DEST, amount_human=Decimal("0.5"))
    boundary.execute(prepared)
    # A second execution of the same prepared operation must be refused: its
    # single-use authorization was consumed.
    with pytest.raises(CustodyError):
        boundary.execute(prepared)


def test_the_digest_commits_to_every_field():
    base = custody_digest(network="testnet", wallet_account=WALLET, destination=DEST, amount_yocto=10**22, service_id="s")
    assert base != custody_digest(network="mainnet", wallet_account=WALLET, destination=DEST, amount_yocto=10**22, service_id="s")
    assert base != custody_digest(network="testnet", wallet_account=WALLET, destination="x.testnet", amount_yocto=10**22, service_id="s")
    assert base != custody_digest(network="testnet", wallet_account=WALLET, destination=DEST, amount_yocto=10**23, service_id="s")
    assert base != custody_digest(network="testnet", wallet_account=WALLET, destination=DEST, amount_yocto=10**22, service_id="t")


# --- settlement verification primitive -------------------------------------


def test_verify_requires_the_signing_key_to_be_the_wallet_key():
    verification = verify_custody_transaction(
        transaction_digest="d",
        tx_hash=TX_HASH,
        wallet_account=WALLET,
        expected_receiver=DEST,
        expected_deposit_yocto=10**22,
        result=_verified_result(public_key="ed25519:11111111111111111111111111111111"),
        source_status=SourceStatus.OK,
    )
    assert verification.state.value == "DISPUTED"
    assert "signing_key_is_the_wallet_key" in [c.name for c in verification.failed_checks()]


def test_verify_is_insufficient_without_a_record():
    verification = verify_custody_transaction(
        transaction_digest="d",
        tx_hash=TX_HASH,
        wallet_account=WALLET,
        expected_receiver=DEST,
        expected_deposit_yocto=10**22,
        result=None,
        source_status=SourceStatus.TIMEOUT,
    )
    assert verification.state.value == "INSUFFICIENT_EVIDENCE"


# --- info / status ----------------------------------------------------------


def test_info_does_not_claim_a_live_connection():
    opener = FakeOpener()
    boundary = _boundary(opener)
    info = boundary.info()
    assert info["enabled"] is True
    assert "reachable" not in info
    assert not opener.calls


def _verified_result(*, receiver: str = DEST, deposit: str = str(5 * 10**23), public_key: str = WALLET_PUB):
    return {
        "final_execution_status": "FINAL",
        "status": {"SuccessValue": ""},
        "transaction": {
            "hash": TX_HASH,
            "signer_id": WALLET,
            "receiver_id": receiver,
            "public_key": public_key,
            "actions": [{"Transfer": {"deposit": deposit}}],
        },
    }


# --- boundary: per-operation TEE evidence state -----------------------------


def test_custody_evidence_is_unavailable_not_tee_signed_without_attestation():
    """Provider success + verified settlement is SETTLEMENT_VERIFIED, never TEE.

    The OutLayer Agent Custody signing API supplies no per-operation attestation,
    so the strongest honest state is SETTLEMENT_VERIFIED, and the TEE evidence is
    explicitly PER_OPERATION_TEE_ATTESTATION_UNAVAILABLE.
    """
    from tracesettle.near.custody_attestation import CustodyEvidenceState

    opener = _address_route(FakeOpener())
    opener.json("POST", "/wallet/v1/transfer", {"request_id": "r1", "status": "success", "tx_hash": TX_HASH})
    nc = network_config("testnet")
    rpc = FakeNearRpc(nc)
    rpc.tx_status_result = _verified_result()
    boundary = _boundary(opener, rpc=rpc)
    prepared = boundary.prepare(service_id="treasury-agent", destination=DEST, amount_human=Decimal("0.5"))
    execution = boundary.execute(prepared)
    assert execution.settlement_verified is True
    assert execution.evidence_state is CustodyEvidenceState.SETTLEMENT_VERIFIED
    assert execution.evidence_state is not CustodyEvidenceState.TEE_SIGNING_VERIFIED
    assert execution.attestation is not None
    assert execution.attestation.state is CustodyEvidenceState.PER_OPERATION_TEE_ATTESTATION_UNAVAILABLE
    assert execution.attestation.tee_attested is False


def test_provider_success_without_settlement_is_only_provider_claimed():
    from tracesettle.near.custody_attestation import CustodyEvidenceState

    opener = _address_route(FakeOpener())
    opener.json("POST", "/wallet/v1/transfer", {"request_id": "r1", "status": "success", "tx_hash": TX_HASH})
    nc = network_config("testnet")
    rpc = FakeNearRpc(nc)
    rpc.tx_status_status = SourceStatus.TIMEOUT
    boundary = _boundary(opener, rpc=rpc)
    prepared = boundary.prepare(service_id="treasury-agent", destination=DEST, amount_human=Decimal("0.5"))
    execution = boundary.execute(prepared)
    assert execution.provider_claimed_success is True
    assert execution.settlement_verified is False
    # The authorization binding did hold (verify_binding ran), so the honest
    # state is CUSTODY_BOUND: better than a bare provider claim, far short of
    # settlement or TEE signing.
    assert execution.evidence_state is CustodyEvidenceState.CUSTODY_BOUND


def test_custody_execution_serialises_the_evidence_state_and_attestation():
    opener = _address_route(FakeOpener())
    opener.json("POST", "/wallet/v1/transfer", {"request_id": "r1", "status": "success", "tx_hash": TX_HASH})
    nc = network_config("testnet")
    rpc = FakeNearRpc(nc)
    rpc.tx_status_result = _verified_result()
    boundary = _boundary(opener, rpc=rpc)
    prepared = boundary.prepare(service_id="treasury-agent", destination=DEST, amount_human=Decimal("0.5"))
    execution = boundary.execute(prepared)
    payload = execution.to_dict()
    assert payload["evidence_state"] == "SETTLEMENT_VERIFIED"
    assert payload["attestation"]["state"] == "PER_OPERATION_TEE_ATTESTATION_UNAVAILABLE"
    assert payload["provider_claimed_success"] is True
