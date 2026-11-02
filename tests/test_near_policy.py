"""Tests for the NEAR policy model, adapter, and scope analysis.

These exercise the real parsing and scope logic against the documented shapes.
No network call is made: the provider adapter is exercised with a fake HTTP
client that returns a captured-shaped response.
"""

from __future__ import annotations

import json
import pathlib

import pytest

from tracesettle.near.policy import (
    PolicyAdapter,
    PolicyAvailability,
    PolicyParseError,
    PolicyScope,
    PolicyStatus,
    RequiredApproval,
    controls_applicable_to,
    controls_not_applicable_to,
    load_fixture,
    parse_policy,
)

FIXTURE_DIR = pathlib.Path(__file__).resolve().parent.parent / "tracesettle" / "near" / "fixtures"


def load(name: str) -> dict:
    return json.loads((FIXTURE_DIR / name).read_text())


# --- parsing ---------------------------------------------------------------


def test_in_force_policy_is_parsed_and_in_force():
    policy = parse_policy(load("policy_in_force.json"))
    assert policy.status is PolicyStatus.APPLIED
    assert policy.provider_policy_synced is True
    assert policy.in_force is True
    assert policy.actions == frozenset({"swap", "transfer", "withdraw"})
    assert policy.required_approval is RequiredApproval.NONE


def test_a_signed_update_is_not_in_force():
    """The core honesty rule: a requested/signed update is not an applied policy."""
    policy = parse_policy(load("policy_not_applied.json"))
    assert policy.status is PolicyStatus.SIGNED
    assert policy.provider_policy_synced is False
    assert policy.in_force is False


def test_applied_but_not_synced_is_not_in_force():
    raw = load("policy_in_force.json")
    raw["provider_policy_synced"] = False
    policy = parse_policy(raw)
    assert policy.status is PolicyStatus.APPLIED
    assert policy.in_force is False


def test_per_asset_limits_are_exact_decimals():
    policy = parse_policy(load("policy_in_force.json"))
    assert str(policy.limits.limit_for("per_transaction", "nep141:usdc.near")) == "100000000"
    assert policy.limits.max_actions_per_hour == 20


def test_a_float_limit_is_rejected_not_silently_accepted():
    """A JSON float for money is a defect, not a value to coerce."""
    raw = load("policy_in_force.json")
    raw["limits"]["per_transaction"]["nep141:usdc.near"] = 1.5
    with pytest.raises(PolicyParseError):
        parse_policy(raw)


def test_unknown_status_becomes_unknown_and_not_in_force():
    raw = load("policy_in_force.json")
    raw["status"] = "SOMETHING_NEW"
    policy = parse_policy(raw)
    assert policy.status is PolicyStatus.UNKNOWN
    assert policy.in_force is False


def test_native_methods_default_off_when_a_chain_is_present():
    """A missing method inside a switched-on chain is OFF, never assumed on."""
    raw = load("policy_in_force.json")
    raw["native"] = {"near": {"transfer": True}}
    policy = parse_policy(raw)
    assert policy.native_method_enabled("near", "transfer") is True
    assert policy.native_method_enabled("near", "call") is False
    assert policy.native_method_enabled("near", "sign_message") is False


def test_an_unsupported_native_chain_is_rejected():
    raw = load("policy_in_force.json")
    raw["native"] = {"dogecoin": {"transfer": True}}
    with pytest.raises(PolicyParseError):
        parse_policy(raw)


def test_non_object_policy_is_rejected():
    with pytest.raises(PolicyParseError):
        parse_policy([1, 2, 3])


def test_asset_allowlist_is_enforced():
    raw = load("policy_in_force.json")
    raw["assets"] = ["nep141:usdc.near"]
    policy = parse_policy(raw)
    assert policy.asset_allowed("nep141:usdc.near") is True
    assert policy.asset_allowed("nep141:usdt.near") is False


def test_destination_mode_only_rejects_an_unlisted_address():
    policy = parse_policy(load("policy_in_force.json"))
    assert policy.destination_allowed(
        action="withdraw", chain="base", address="0x1111111111111111111111111111111111111111"
    )
    assert not policy.destination_allowed(
        action="withdraw", chain="base", address="0xdeadbeefdeadbeefdeadbeefdeadbeefdeadbeef"
    )


# --- scope -----------------------------------------------------------------


def test_intents_scope_is_protected_by_the_money_controls():
    controls = controls_applicable_to(PolicyScope.INTENTS)
    assert "destinations" in controls
    assert "budget_usd" in controls
    assert "owner_approval" in controls
    assert controls_not_applicable_to(PolicyScope.INTENTS) == ()


def test_native_scope_is_not_protected_by_the_money_controls():
    """The scope gap the mission requires us to surface, asserted directly."""
    controls = controls_applicable_to(PolicyScope.NATIVE_NEAR)
    assert "native_method_switch" in controls
    for control in ("destinations", "budget_usd", "timelock_ms", "schedule", "owner_approval"):
        assert control not in controls
        assert control in controls_not_applicable_to(PolicyScope.NATIVE_NEAR)


def test_every_native_scope_has_the_same_gap():
    for scope in (PolicyScope.NATIVE_NEAR, PolicyScope.NATIVE_EVM, PolicyScope.NATIVE_SOLANA):
        assert scope.native is True
        assert "destinations" in controls_not_applicable_to(scope)


# --- adapter ---------------------------------------------------------------


class _FakeResult:
    def __init__(self, *, ok, data=None, http_status=None, status=None):
        self.ok = ok
        self.data = data
        self.http_status = http_status
        self.status = status


class _FakeClient:
    def __init__(self, result):
        self._result = result
        self.calls: list[str] = []

    def get_json(self, url):
        self.calls.append(url)
        return self._result


def test_unconfigured_adapter_reports_unconfigured_without_calling_anything():
    adapter = PolicyAdapter()
    read = adapter.read_policy("demo-agent.near")
    assert read.availability is PolicyAvailability.UNCONFIGURED
    assert read.policy is None


def test_configured_adapter_reads_a_policy():
    client = _FakeClient(_FakeResult(ok=True, data=load("policy_in_force.json"), http_status=200))
    adapter = PolicyAdapter(base_url="https://example.invalid", api_key="secret", http_client=client)
    read = adapter.read_policy("demo-agent.near")
    assert read.availability is PolicyAvailability.AVAILABLE
    assert read.policy.in_force is True
    assert client.calls == ["https://example.invalid/v1/agents/demo-agent.near/policy"]


def test_adapter_reports_unauthenticated_on_401():
    client = _FakeClient(_FakeResult(ok=False, http_status=401, status="SourceStatus.UNAUTHORIZED"))
    adapter = PolicyAdapter(base_url="https://example.invalid", http_client=client)
    read = adapter.read_policy("demo-agent.near")
    assert read.availability is PolicyAvailability.UNAUTHENTICATED


def test_adapter_reports_not_found_on_404():
    client = _FakeClient(_FakeResult(ok=False, http_status=404))
    adapter = PolicyAdapter(base_url="https://example.invalid", http_client=client)
    read = adapter.read_policy("demo-agent.near")
    assert read.availability is PolicyAvailability.NOT_FOUND


def test_adapter_reports_unavailable_on_a_transport_failure():
    class _Boom:
        def get_json(self, url):
            raise TimeoutError("no route")

    adapter = PolicyAdapter(base_url="https://example.invalid", http_client=_Boom())
    read = adapter.read_policy("demo-agent.near")
    assert read.availability is PolicyAvailability.UNAVAILABLE


def test_adapter_reports_malformed_on_a_bad_shape():
    client = _FakeClient(_FakeResult(ok=True, data={"limits": {"per_transaction": {"x": 1.5}}}, http_status=200))
    adapter = PolicyAdapter(base_url="https://example.invalid", http_client=client)
    read = adapter.read_policy("demo-agent.near")
    assert read.availability is PolicyAvailability.MALFORMED


def test_fixture_read_is_marked_local():
    read = PolicyAdapter.from_fixture(load("policy_in_force.json"))
    assert read.local_fixture is True
    assert "fixture" in read.detail


def test_load_fixture_from_path():
    read = load_fixture(str(FIXTURE_DIR / "policy_in_force.json"))
    assert read.ok is True
    assert read.policy.in_force is True


def test_policy_dict_round_trips_the_key_facts():
    policy = parse_policy(load("policy_in_force.json"))
    data = policy.to_dict()
    assert data["in_force"] is True
    assert data["provider_policy_synced"] is True
    assert data["required_approval"] == "NONE"
    assert data["limits"]["max_actions_per_hour"] == 20
