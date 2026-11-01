"""Fail-closed startup validation for the network interface.

The tool must never expose its protected endpoints publicly with authentication
disabled. This module decides, from the bind host and the configured security
material, whether the process may start. It runs **before** any listener is
opened, so a misconfigured deployment fails to start rather than starting
insecure.

Rules:

* A loopback bind is the explicit local-development workflow and needs nothing.
* Any non-loopback bind is treated as public and is refused unless the required
  credentials are present. An unknown or empty host is treated as public
  (fail closed): only a value that provably parses as a loopback address is
  considered local.
* There is **no override**. A public bind without the required credentials is
  always refused; no environment variable can relax this, so the property holds
  under any deployment mistake. A deployment behind a terminating proxy must
  still set the credentials.

No secret value is ever read, logged, or returned here; only whether a value is
present.
"""

from __future__ import annotations

import ipaddress
from dataclasses import dataclass

#: Host names that always mean the local machine.
_LOOPBACK_NAMES = frozenset({"localhost"})


class ConfigurationError(RuntimeError):
    """An insecure or incomplete configuration. The message is safe to log."""


def is_loopback_host(host: str | None) -> bool:
    """Whether ``host`` provably binds only the loopback interface.

    Anything that is not a recognised loopback address or name — including an
    empty string, ``0.0.0.0``, ``::``, or an unresolved hostname — is treated as
    public, so the failure mode is "refuse", never "expose".
    """
    if not host or not isinstance(host, str):
        return False
    candidate = host.strip().strip("[]").lower()
    if not candidate:
        return False
    if candidate in _LOOPBACK_NAMES:
        return True
    try:
        return ipaddress.ip_address(candidate).is_loopback
    except ValueError:
        return False


@dataclass(frozen=True)
class DeploymentProfile:
    """The resolved, non-secret deployment posture, for logging and tests."""

    public_binding: bool
    api_key_configured: bool
    guard_auth_key_configured: bool
    service_auth_enabled: bool
    require_service_auth: bool

    def describe(self) -> str:
        """A one-line, secret-free description of the posture."""
        if not self.public_binding:
            return "loopback binding: local development profile"
        bits = [
            f"api_key={'set' if self.api_key_configured else 'unset'}",
            f"guard_auth_key={'set' if self.guard_auth_key_configured else 'unset'}",
            f"service_auth={'enabled' if self.service_auth_enabled else 'disabled'}",
        ]
        return "public binding: " + ", ".join(bits)


def validate_startup(
    *,
    host: str | None,
    api_key: str | None,
    guard_auth_key_configured: bool,
    service_auth_enabled: bool,
    require_service_auth: bool,
) -> DeploymentProfile:
    """Decide whether the process may start, and return the resolved profile.

    Raises :class:`ConfigurationError` when the configuration is insecure. The
    message names the environment variable to set and never contains a value.

    There is no override: a public bind without the required credentials always
    raises, so the fail-closed property cannot be relaxed by configuration.
    """
    public_binding = not is_loopback_host(host)
    profile = DeploymentProfile(
        public_binding=public_binding,
        api_key_configured=bool(api_key),
        guard_auth_key_configured=guard_auth_key_configured,
        service_auth_enabled=service_auth_enabled,
        require_service_auth=require_service_auth,
    )

    # An explicit requirement is honoured on any binding: asking for per-service
    # authentication and then not providing it is a misconfiguration, not a
    # fallback.
    if require_service_auth and not service_auth_enabled:
        raise ConfigurationError(
            "TRACESETTLE_REQUIRE_SERVICE_AUTH is set but no service credentials are "
            "configured; set TRACESETTLE_SERVICE_CREDENTIALS to a credential store "
            "with at least one credential, or unset TRACESETTLE_REQUIRE_SERVICE_AUTH"
        )

    if not public_binding:
        return profile

    missing: list[str] = []
    if not api_key:
        missing.append("TRACESETTLE_API_KEY")
    if not guard_auth_key_configured:
        missing.append("TRACESETTLE_GUARD_AUTH_KEY")
    if missing:
        raise ConfigurationError(
            "binding a public interface (host=%r) requires authentication, but these "
            "are unset: %s. Bind 127.0.0.1 for local development, or set the variables "
            "above. There is no override for this check." % (host, ", ".join(missing))
        )
    return profile


def validate_from_config(host: str | None) -> DeploymentProfile:
    """Validate using the live process configuration."""
    from . import config

    return validate_startup(
        host=host,
        api_key=config.API_KEY,
        guard_auth_key_configured=config.GUARD_AUTH_KEY_CONFIGURED,
        service_auth_enabled=config.service_auth_configured(),
        require_service_auth=config.REQUIRE_SERVICE_AUTH,
    )
