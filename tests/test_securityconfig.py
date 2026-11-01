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
