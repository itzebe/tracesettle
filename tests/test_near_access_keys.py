"""Tests for the NEAR access-key permission analysis.

These assert the documented facts that people get wrong: a function-call key
cannot transfer NEAR, an omitted ``method_names`` means every method on the
contract, and an omitted ``allowance`` means unlimited gas.
"""

from __future__ import annotations

import json
import pathlib

import pytest

from tracesettle.near.access_keys import (
    AccessKeyPermission,
    AccessKeyRisk,
    analyze_access_keys,
    key_supports_operation,
    parse_access_key,
    worst_risk,
)

FIXTURE_DIR = pathlib.Path(__file__).resolve().parent / "fixtures" / "near"


def load_keys() -> dict:
    return json.loads((FIXTURE_DIR / "access_keys.json").read_text())["keys"]


def test_full_access_key_is_critical_and_unrestricted():
    analysis = parse_access_key(load_keys()["full_access"])
    assert analysis.permission is AccessKeyPermission.FULL_ACCESS
    assert analysis.risk is AccessKeyRisk.CRITICAL
    assert analysis.can_transfer_near is True
    assert analysis.can_add_keys is True
    assert analysis.restricted is False
    assert analysis.warnings


def test_function_call_key_cannot_transfer_near():
    """The documented limitation, asserted as a property."""
    analysis = parse_access_key(load_keys()["function_call_scoped"])
    assert analysis.permission is AccessKeyPermission.FUNCTION_CALL
    assert analysis.can_transfer_near is False
    assert analysis.can_add_keys is False
    assert analysis.restricted is True
    assert any("cannot transfer NEAR" in limitation for limitation in analysis.limitations)


def test_scoped_function_call_key_allows_only_its_methods():
    analysis = parse_access_key(load_keys()["function_call_scoped"])
    assert analysis.receiver_id == "wrap.near"
    assert analysis.method_names == ("ft_transfer", "ft_transfer_call")
    assert analysis.allows_call(receiver_id="wrap.near", method_name="ft_transfer") is True
    assert analysis.allows_call(receiver_id="wrap.near", method_name="ft_transfer_call") is True
    assert analysis.allows_call(receiver_id="wrap.near", method_name="delete_key") is False
    assert analysis.allows_call(receiver_id="other.near", method_name="ft_transfer") is False


def test_scoped_key_with_an_allowance_is_low_risk():
    analysis = parse_access_key(load_keys()["function_call_scoped"])
    assert analysis.allowance_yocto is not None
    assert analysis.risk is AccessKeyRisk.LOW


def test_omitted_method_names_means_every_method_and_is_high_risk():
    """An empty method_names is 'all methods', not 'safe'."""
    analysis = parse_access_key(load_keys()["function_call_unrestricted_methods"])
    assert analysis.method_names == ()
    assert analysis.methods_unrestricted is True
    assert analysis.risk is AccessKeyRisk.HIGH
    assert analysis.allows_call(receiver_id="wrap.near", method_name="anything") is True
    assert any("every method" in w for w in analysis.warnings)


def test_omitted_allowance_is_unlimited_gas_and_warns():
    analysis = parse_access_key(load_keys()["function_call_unrestricted_methods"])
    assert analysis.allowance_yocto is None
    assert any("unlimited gas" in w for w in analysis.warnings)


def test_gas_key_is_recognised_and_keeps_its_nonce_lanes():
    analysis = parse_access_key(load_keys()["gas_key_scoped"])
    assert analysis.is_gas_key is True
    assert analysis.num_nonces == 1024
    assert any("nonce lanes" in capability for capability in analysis.capabilities)


def test_gas_key_function_call_cannot_set_an_allowance():
    analysis = parse_access_key(load_keys()["gas_key_scoped"])
    assert any("cannot set an allowance" in limitation for limitation in analysis.limitations)


def test_unknown_permission_is_treated_as_unrestricted():
    """Never treat an unrecognised permission as safe."""
    analysis = parse_access_key({"permission": {"SomethingNew": {}}})
    assert analysis.permission is AccessKeyPermission.UNKNOWN
    assert analysis.risk is AccessKeyRisk.CRITICAL
    assert analysis.can_transfer_near is False  # only FULL_ACCESS is explicit
    assert any("treated as unrestricted" in w for w in analysis.warnings)


def test_rpc_view_envelope_is_unwrapped():
    wrapped = {"access_key": {"permission": "FullAccess", "nonce": 1}}
    analysis = parse_access_key(wrapped)
    assert analysis.permission is AccessKeyPermission.FULL_ACCESS


def test_function_call_without_a_receiver_is_not_treated_as_unrestricted():
    analysis = parse_access_key({"permission": {"FunctionCall": {}}})
    assert analysis.permission is AccessKeyPermission.FUNCTION_CALL
    assert analysis.allows_call(receiver_id="wrap.near", method_name="ft_transfer") is False
    assert any("names no receiver_id" in w for w in analysis.warnings)


def test_analyze_access_keys_preserves_order():
    keys = load_keys()
    analyses = analyze_access_keys(list(keys.values()))
    assert len(analyses) == len(keys)


def test_worst_risk_uses_rank_not_the_string_value():
    keys = load_keys()
    analyses = analyze_access_keys(list(keys.values()))
    assert worst_risk(analyses) is AccessKeyRisk.CRITICAL


def test_worst_risk_of_nothing_is_critical():
    assert worst_risk(()) is AccessKeyRisk.CRITICAL


# --- key_supports_operation -------------------------------------------------


def test_full_access_key_supports_a_near_transfer():
    analysis = parse_access_key(load_keys()["full_access"])
    allowed, _ = key_supports_operation(analysis, operation="TRANSFER", transfers_near=True)
    assert allowed is True


def test_function_call_key_does_not_support_a_near_transfer():
    analysis = parse_access_key(load_keys()["function_call_scoped"])
    allowed, reason = key_supports_operation(analysis, operation="TRANSFER", transfers_near=True)
    assert allowed is False
    assert "cannot transfer NEAR" in reason


def test_function_call_key_supports_a_matching_contract_call():
    analysis = parse_access_key(load_keys()["function_call_scoped"])
    allowed, _ = key_supports_operation(
        analysis, operation="FUNCTION_CALL", receiver_id="wrap.near", method_name="ft_transfer"
    )
    assert allowed is True


def test_function_call_key_does_not_support_a_mismatched_contract_call():
    analysis = parse_access_key(load_keys()["function_call_scoped"])
    allowed, reason = key_supports_operation(
        analysis, operation="FUNCTION_CALL", receiver_id="wrap.near", method_name="delete_key"
    )
    assert allowed is False
    assert "not scoped" in reason


def test_function_call_key_does_not_support_add_key():
    analysis = parse_access_key(load_keys()["function_call_scoped"])
    allowed, reason = key_supports_operation(analysis, operation="ADD_KEY")
    assert allowed is False
    assert "only a full-access key" in reason


def test_a_float_allowance_is_rejected():
    with pytest.raises(ValueError):
        parse_access_key(
            {"permission": {"FunctionCall": {"receiver_id": "wrap.near", "allowance": 1.5}}}
        )


def test_analysis_dict_exposes_the_capabilities_and_limits():
    analysis = parse_access_key(load_keys()["function_call_scoped"])
    data = analysis.to_dict()
    assert data["can_transfer_near"] is False
    assert data["risk"] == "LOW"
    assert data["allowance_near"]
    assert "cannot add or remove access keys" in data["limitations"]
