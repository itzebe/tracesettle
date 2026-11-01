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
        allow_insecure_public=False,
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


def test_loopback_binding_ignores_insecure_override_flag():
    profile = _validate("localhost", allow_insecure_public=True)
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


# --- explicit override -----------------------------------------------------


def test_insecure_public_override_allows_start_but_is_flagged():
    profile = _validate("0.0.0.0", api_key=None, guard_auth_key_configured=False, allow_insecure_public=True)
    assert profile.public_binding is True
    assert profile.insecure_public_override is True
    assert "INSECURE_PUBLIC_OVERRIDE" in profile.describe()


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
