"""Network identity and asset registry.

These are the two places where a wrong answer silently spends the wrong money:
signing for the wrong network, or converting an amount with the wrong decimals.
Both are tested directly.
"""

from __future__ import annotations

from decimal import Decimal

import pytest

from tracesettle.near.assets import (
    AssetError,
    from_base_units,
    is_supported,
    resolve_asset,
    supported_assets,
    to_base_units,
    verify_decimals,
)
from tracesettle.near.networks import (
    MAINNET_GENESIS,
    NETWORKS,
    TESTNET_GENESIS,
    NearNetwork,
    NetworkError,
    network_config,
    parse_network,
    verify_network_identity,
)


# -- networks -----------------------------------------------------------------


def test_parse_network_defaults_to_testnet():
    assert parse_network(None) is NearNetwork.TESTNET
    assert parse_network("") is NearNetwork.TESTNET


def test_parse_network_accepts_known_names_case_insensitively():
    assert parse_network("MAINNET") is NearNetwork.MAINNET
    assert parse_network(" testnet ") is NearNetwork.TESTNET


def test_parse_network_refuses_an_unknown_name_rather_than_defaulting():
    with pytest.raises(NetworkError):
        parse_network("mainnett")


def test_testnet_is_the_default_configuration():
    assert NETWORKS[NearNetwork.TESTNET].network is NearNetwork.TESTNET
    assert network_config(None).network is NearNetwork.TESTNET


def test_network_identities_are_distinct():
    assert NearNetwork.TESTNET.genesis_hash != NearNetwork.MAINNET.genesis_hash
    assert NearNetwork.TESTNET.chain_id == "testnet"
    assert NearNetwork.MAINNET.chain_id == "mainnet"


def test_verify_network_identity_accepts_a_matching_status():
    config = NETWORKS[NearNetwork.TESTNET]
    verify_network_identity(config, {"chain_id": "testnet", "genesis_hash": TESTNET_GENESIS})


def test_verify_network_identity_refuses_a_wrong_chain_id():
    config = NETWORKS[NearNetwork.TESTNET]
    with pytest.raises(NetworkError):
        verify_network_identity(config, {"chain_id": "mainnet", "genesis_hash": TESTNET_GENESIS})


def test_verify_network_identity_refuses_a_wrong_genesis_hash():
    """A testnet config pointed at a mainnet node must be refused."""
    config = NETWORKS[NearNetwork.TESTNET]
    with pytest.raises(NetworkError):
        verify_network_identity(config, {"chain_id": "testnet", "genesis_hash": MAINNET_GENESIS})


def test_mainnet_config_has_an_explorer_and_rpc():
    cfg = NETWORKS[NearNetwork.MAINNET]
    assert cfg.rpc_url.startswith("https://")
    assert cfg.explorer_url("abc") == "https://nearblocks.io/txns/abc"


# -- assets -------------------------------------------------------------------


def test_native_asset_identity_is_canonical():
    asset = resolve_asset(NearNetwork.TESTNET, "near:native")
    assert asset.is_native
    assert asset.identifier == "near:native"
    assert asset.decimals == 24


def test_asset_identifier_without_the_near_prefix_resolves():
    assert resolve_asset(NearNetwork.TESTNET, "native").identifier == "near:native"
    assert resolve_asset(NearNetwork.TESTNET, "wrap.testnet").symbol == "wNEAR"


def test_display_name_is_not_an_identifier():
    """A symbol must never resolve; only the canonical identifier does."""
    with pytest.raises(AssetError):
        resolve_asset(NearNetwork.TESTNET, "USDC")
    with pytest.raises(AssetError):
        resolve_asset(NearNetwork.TESTNET, "wNEAR")


def test_asset_is_network_scoped():
    """A mainnet token account is not valid on testnet."""
    assert is_supported(NearNetwork.MAINNET, "wrap.near")
    assert not is_supported(NearNetwork.TESTNET, "wrap.near")
    assert is_supported(NearNetwork.TESTNET, "wrap.testnet")
    assert not is_supported(NearNetwork.MAINNET, "wrap.testnet")


def test_verified_mainnet_decimals():
    assert resolve_asset(NearNetwork.MAINNET, "wrap.near").decimals == 24
    usdc = resolve_asset(
        NearNetwork.MAINNET, "17208628f84f5d6ad33f0da3bbbeb27ffcb398eac501a31bd6ad2011e36133a1"
    )
    assert usdc.decimals == 6 and usdc.symbol == "USDC"


def test_verified_testnet_decimals():
    assert resolve_asset(NearNetwork.TESTNET, "usdc.fakes.testnet").decimals == 6


def test_supported_assets_lists_native_first():
    assets = supported_assets(NearNetwork.TESTNET)
    assert assets[0].is_native


def test_to_base_units_is_exact_for_native_near():
    asset = resolve_asset(NearNetwork.TESTNET, "near:native")
    assert to_base_units(Decimal("1"), asset) == 10**24
    assert to_base_units("0.5", asset) == 5 * 10**23


def test_to_base_units_uses_the_asset_decimals():
    usdc = resolve_asset(NearNetwork.TESTNET, "usdc.fakes.testnet")
    assert to_base_units(Decimal("1"), usdc) == 10**6
    assert to_base_units("0.000001", usdc) == 1


def test_to_base_units_refuses_excess_precision():
    usdc = resolve_asset(NearNetwork.TESTNET, "usdc.fakes.testnet")
    with pytest.raises(AssetError):
        to_base_units("0.0000001", usdc)


def test_to_base_units_refuses_zero_and_negative():
    asset = resolve_asset(NearNetwork.TESTNET, "near:native")
    with pytest.raises(AssetError):
        to_base_units("0", asset)
    with pytest.raises(AssetError):
        to_base_units("-1", asset)


def test_to_base_units_refuses_non_numeric():
    asset = resolve_asset(NearNetwork.TESTNET, "near:native")
    with pytest.raises(AssetError):
        to_base_units("abc", asset)


def test_from_base_units_round_trips():
    asset = resolve_asset(NearNetwork.TESTNET, "usdc.fakes.testnet")
    assert from_base_units(1_500_000, asset) == Decimal("1.5")


def test_verify_decimals_accepts_a_match():
    asset = resolve_asset(NearNetwork.TESTNET, "usdc.fakes.testnet")
    verify_decimals({"decimals": 6}, asset)


def test_verify_decimals_refuses_a_mismatch():
    """A drifted or malicious contract must not silently change an amount."""
    asset = resolve_asset(NearNetwork.TESTNET, "usdc.fakes.testnet")
    with pytest.raises(AssetError):
        verify_decimals({"decimals": 18}, asset)


def test_verify_decimals_refuses_a_missing_value():
    asset = resolve_asset(NearNetwork.TESTNET, "usdc.fakes.testnet")
    with pytest.raises(AssetError):
        verify_decimals({}, asset)
