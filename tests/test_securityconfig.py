"""Fail-closed configuration tests.

The property under test: the application must refuse to start when it would
expose protected endpoints publicly with authentication disabled, while keeping
an explicitly restricted local development workflow working.
"""

from __future__ import annotations

import pytest

from tracesettle.securityconfig import (
    ConfigurationError,
    is_loopback_host,
    validate_startup,
)


def _validate(host, **overrides):
    base = dict(
        api_key="a-key",
        guard_auth_key_configured=True,
        service_auth_enabled=False,
        require_service_auth=False,
    )
    base.update(overrides)
    return validate_startup(host=host, **base)


# --- loopback detection ----------------------------------------------------


@pytest.mark.parametrize("host", ["127.0.0.1", "localhost", "::1", "127.0.0.5"])
def test_loopback_hosts_are_local(host):
    assert is_loopback_host(host) is True


@pytest.mark.parametrize(
    "host",
    ["0.0.0.0", "::", "192.168.1.10", "10.0.0.1", "example.com", "", None, "  "],
)
def test_non_loopback_hosts_are_public(host):
    assert is_loopback_host(host) is False


def test_unknown_host_is_treated_as_public():
    """An unparseable host must fail closed, not default to local."""
    assert is_loopback_host("not-an-address") is False


# --- loopback development workflow -----------------------------------------


def test_loopback_binding_needs_no_credentials():
    profile = _validate("127.0.0.1", api_key=None, guard_auth_key_configured=False)
    assert profile.public_binding is False
    assert "local development" in profile.describe()


def test_loopback_binding_needs_nothing_even_without_credentials():
    profile = _validate("localhost", api_key=None, guard_auth_key_configured=False)
    assert profile.public_binding is False


# --- public binding refusals -----------------------------------------------


def test_public_binding_without_api_key_is_refused():
    with pytest.raises(ConfigurationError) as exc:
        _validate("0.0.0.0", api_key=None)
    assert "TRACESETTLE_API_KEY" in str(exc.value)


def test_public_binding_without_guard_key_is_refused():
    with pytest.raises(ConfigurationError) as exc:
        _validate("0.0.0.0", guard_auth_key_configured=False)
    assert "TRACESETTLE_GUARD_AUTH_KEY" in str(exc.value)


def test_public_binding_without_both_keys_names_both():
    with pytest.raises(ConfigurationError) as exc:
        _validate("0.0.0.0", api_key=None, guard_auth_key_configured=False)
    message = str(exc.value)
    assert "TRACESETTLE_API_KEY" in message
    assert "TRACESETTLE_GUARD_AUTH_KEY" in message


def test_public_binding_with_all_credentials_starts():
    profile = _validate("0.0.0.0")
    assert profile.public_binding is True
    assert "api_key=set" in profile.describe()
    assert "guard_auth_key=set" in profile.describe()


def test_wildcard_and_specific_public_hosts_are_refused_alike():
    for host in ("0.0.0.0", "::", "203.0.113.7", "myapp.example.com"):
        with pytest.raises(ConfigurationError):
            _validate(host, api_key=None, guard_auth_key_configured=False)


# --- no override exists ----------------------------------------------------


def test_no_override_exists_for_a_public_bind():
    """A public bind without credentials must always raise, with no opt-out.

    Regression: an earlier revision accepted ``TRACESETTLE_ALLOW_INSECURE_PUBLIC=1``
    and then served protected endpoints (including the ability to mint a real
    authorization) with no authentication at all. That bypass is removed; the
    validator no longer takes any "allow insecure" parameter.
    """
    import inspect

    params = inspect.signature(validate_startup).parameters
    assert "allow_insecure_public" not in params
    with pytest.raises(ConfigurationError):
        _validate("0.0.0.0", api_key=None, guard_auth_key_configured=False)


def test_wildcard_host_is_refused_regardless_of_any_env(monkeypatch):
    """Even with the legacy override variable set, the refusal stands."""
    from tracesettle import config
    from tracesettle.securityconfig import validate_from_config

    monkeypatch.setenv("TRACESETTLE_ALLOW_INSECURE_PUBLIC", "1")
    monkeypatch.setattr(config, "API_KEY", None, raising=False)
    monkeypatch.setattr(config, "GUARD_AUTH_KEY_CONFIGURED", False, raising=False)
    with pytest.raises(ConfigurationError):
        validate_from_config("0.0.0.0")


# --- require-service-auth --------------------------------------------------


def test_require_service_auth_without_a_store_is_refused_on_any_binding():
    with pytest.raises(ConfigurationError) as exc:
        _validate("127.0.0.1", require_service_auth=True, service_auth_enabled=False)
    assert "TRACESETTLE_REQUIRE_SERVICE_AUTH" in str(exc.value)


def test_require_service_auth_with_a_store_is_allowed():
    profile = _validate("127.0.0.1", require_service_auth=True, service_auth_enabled=True)
    assert profile.require_service_auth is True


def test_public_binding_with_service_auth_and_keys_starts():
    profile = _validate("0.0.0.0", require_service_auth=True, service_auth_enabled=True)
    assert profile.public_binding is True
    assert profile.service_auth_enabled is True


# --- describe() never leaks a value ----------------------------------------


def test_profile_description_contains_no_secret_value():
    profile = _validate("0.0.0.0", api_key="super-secret-key")
    assert "super-secret-key" not in profile.describe()


# --- client policy selection is loopback-only ------------------------------


def test_public_binding_with_client_policy_selection_is_refused(monkeypatch):
    """Client-supplied policy selection must never be reachable publicly.

    It lets a caller choose the policy it is evaluated against, which is the
    enforcement decision itself. A public bind therefore refuses to start.
    """
    from tracesettle import config

    monkeypatch.setattr(config, "NEAR_ALLOW_CLIENT_POLICY_SELECTION", True)
    with pytest.raises(ConfigurationError) as excinfo:
        _validate("0.0.0.0")
    message = str(excinfo.value)
    assert "TRACESETTLE_NEAR_ALLOW_CLIENT_POLICY_SELECTION" in message
    # The message names the variable, never a value.
    assert "0.0.0.0" in message


def test_loopback_binding_with_client_policy_selection_starts(monkeypatch):
    from tracesettle import config

    monkeypatch.setattr(config, "NEAR_ALLOW_CLIENT_POLICY_SELECTION", True)
    profile = _validate("127.0.0.1")
    assert profile.public_binding is False


# --- the TEE gate fails closed ---------------------------------------------


def test_tee_gate_without_the_attestation_provider_is_refused(monkeypatch):
    """Requiring attestation without a way to obtain one must refuse to start.

    Otherwise the operator asks for enforced attestation and silently gets none.
    """
    from tracesettle import config

    monkeypatch.setattr(config, "NEAR_TEE_REQUIRED", True)
    monkeypatch.setattr(config, "TEE_ATTESTATION_ENABLED", False)
    monkeypatch.setattr(config, "NEAR_EXECUTION_ENABLED", True)
    with pytest.raises(ConfigurationError) as excinfo:
        _validate("127.0.0.1")
    assert "TRACESETTLE_TEE_ATTESTATION" in str(excinfo.value)


def test_tee_gate_without_the_execution_boundary_is_refused(monkeypatch):
    from tracesettle import config

    monkeypatch.setattr(config, "NEAR_TEE_REQUIRED", True)
    monkeypatch.setattr(config, "TEE_ATTESTATION_ENABLED", True)
    monkeypatch.setattr(config, "NEAR_EXECUTION_ENABLED", False)
    with pytest.raises(ConfigurationError) as excinfo:
        _validate("0.0.0.0")
    assert "TRACESETTLE_NEAR_EXECUTION" in str(excinfo.value)


def test_tee_gate_with_both_dependencies_starts(monkeypatch):
    from tracesettle import config

    monkeypatch.setattr(config, "NEAR_TEE_REQUIRED", True)
    monkeypatch.setattr(config, "TEE_ATTESTATION_ENABLED", True)
    monkeypatch.setattr(config, "NEAR_EXECUTION_ENABLED", True)
    profile = _validate("127.0.0.1")
    assert profile.public_binding is False


# --- enclave signing gate ---------------------------------------------------


def _with_config(monkeypatch, **attrs):
    from tracesettle import config

    for key, value in attrs.items():
        monkeypatch.setattr(config, key, value, raising=False)


def test_enclave_required_without_a_sign_url_is_refused(monkeypatch):
    _with_config(
        monkeypatch,
        ENCLAVE_REQUIRED=True,
        ENCLAVE_SIGN_URL=None,
        ENCLAVE_APPROVED_MEASUREMENT="mr_config_id=aa",
        NEAR_EXECUTION_ENABLED=True,
    )
    with pytest.raises(ConfigurationError) as exc:
        _validate("127.0.0.1")
    assert "TRACESETTLE_ENCLAVE_SIGN_URL" in str(exc.value)


def test_enclave_required_without_a_measurement_pin_is_refused(monkeypatch):
    _with_config(
        monkeypatch,
        ENCLAVE_REQUIRED=True,
        ENCLAVE_SIGN_URL="https://enclave.invalid/sign",
        ENCLAVE_APPROVED_MEASUREMENT=None,
        NEAR_EXECUTION_ENABLED=True,
    )
    with pytest.raises(ConfigurationError) as exc:
        _validate("127.0.0.1")
    assert "TRACESETTLE_ENCLAVE_APPROVED_MEASUREMENT" in str(exc.value)


def test_enclave_required_without_execution_is_refused(monkeypatch):
    _with_config(
        monkeypatch,
        ENCLAVE_REQUIRED=True,
        ENCLAVE_SIGN_URL="https://enclave.invalid/sign",
        ENCLAVE_APPROVED_MEASUREMENT="mr_config_id=aa",
        NEAR_EXECUTION_ENABLED=False,
    )
    with pytest.raises(ConfigurationError) as exc:
        _validate("127.0.0.1")
    assert "TRACESETTLE_NEAR_EXECUTION" in str(exc.value)


def test_enclave_required_with_full_configuration_starts(monkeypatch):
    _with_config(
        monkeypatch,
        ENCLAVE_REQUIRED=True,
        ENCLAVE_SIGN_URL="https://enclave.invalid/sign",
        ENCLAVE_APPROVED_MEASUREMENT="mr_config_id=aa",
        NEAR_EXECUTION_ENABLED=True,
    )
    profile = _validate("127.0.0.1")
    assert profile.public_binding is False


def test_approved_measurement_parses_field_value_pairs():
    from tracesettle.config import parse_approved_measurement

    assert parse_approved_measurement(None) == {}
    assert parse_approved_measurement("") == {}
    assert parse_approved_measurement("mr_config_id=AABB, rt_mr3=CC") == {
        "mr_config_id": "aabb",
        "rt_mr3": "cc",
    }


def test_approved_measurement_rejects_a_malformed_entry():
    from tracesettle.config import parse_approved_measurement

    with pytest.raises(ValueError):
        parse_approved_measurement("mr_config_id")
    with pytest.raises(ValueError):
        parse_approved_measurement("=aabb")


# --- OutLayer custody gate --------------------------------------------------


def test_outlayer_enabled_without_a_key_is_refused(monkeypatch):
    """Enabling the custody wallet without a provider key must refuse to start."""
    _with_config(
        monkeypatch,
        OUTLAYER_ENABLED=True,
        OUTLAYER_API_KEY=None,
        OUTLAYER_NETWORK="testnet",
        NEAR_EXECUTION_ENABLED=True,
    )
    with pytest.raises(ConfigurationError) as exc:
        _validate("127.0.0.1")
    assert "TRACESETTLE_OUTLAYER_API_KEY" in str(exc.value)


def test_outlayer_enabled_without_the_execution_boundary_is_refused(monkeypatch):
    _with_config(
        monkeypatch,
        OUTLAYER_ENABLED=True,
        OUTLAYER_API_KEY="wk_test_000000000000000000000000000000000000",
        OUTLAYER_NETWORK="testnet",
        NEAR_EXECUTION_ENABLED=False,
    )
    with pytest.raises(ConfigurationError) as exc:
        _validate("127.0.0.1")
    assert "TRACESETTLE_NEAR_EXECUTION" in str(exc.value)


def test_outlayer_enabled_with_an_unknown_network_is_refused(monkeypatch):
    _with_config(
        monkeypatch,
        OUTLAYER_ENABLED=True,
        OUTLAYER_API_KEY="wk_test_000000000000000000000000000000000000",
        OUTLAYER_NETWORK="devnet",
        NEAR_EXECUTION_ENABLED=True,
    )
    with pytest.raises(ConfigurationError) as exc:
        _validate("127.0.0.1")
    assert "TRACESETTLE_OUTLAYER_NETWORK" in str(exc.value)


def test_outlayer_enabled_with_full_configuration_starts(monkeypatch):
    _with_config(
        monkeypatch,
        OUTLAYER_ENABLED=True,
        OUTLAYER_API_KEY="wk_test_000000000000000000000000000000000000",
        OUTLAYER_NETWORK="testnet",
        NEAR_EXECUTION_ENABLED=True,
        OUTLAYER_REQUIRE_PROVIDER_POLICY=False,
    )
    profile = _validate("127.0.0.1")
    assert profile.public_binding is False


def test_outlayer_requiring_the_provider_policy_without_an_api_is_refused(monkeypatch):
    """A required provider policy with no Agent API would be dead on arrival."""
    _with_config(
        monkeypatch,
        OUTLAYER_ENABLED=True,
        OUTLAYER_API_KEY="wk_test_000000000000000000000000000000000000",
        OUTLAYER_NETWORK="testnet",
        NEAR_EXECUTION_ENABLED=True,
        OUTLAYER_REQUIRE_PROVIDER_POLICY=True,
        NEAR_AGENT_API_URL=None,
    )
    with pytest.raises(ConfigurationError) as exc:
        _validate("127.0.0.1")
    assert "TRACESETTLE_NEAR_AGENT_API_URL" in str(exc.value)


def test_outlayer_with_the_provider_policy_and_an_api_starts(monkeypatch):
    _with_config(
        monkeypatch,
        OUTLAYER_ENABLED=True,
        OUTLAYER_API_KEY="wk_test_000000000000000000000000000000000000",
        OUTLAYER_NETWORK="testnet",
        NEAR_EXECUTION_ENABLED=True,
        OUTLAYER_REQUIRE_PROVIDER_POLICY=True,
        NEAR_AGENT_API_URL="https://provider.invalid",
    )
    profile = _validate("127.0.0.1")
    assert profile.public_binding is False
