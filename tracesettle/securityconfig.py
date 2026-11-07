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

    # The TEE gate fails closed. Asking for enforced attestation without the
    # machinery to obtain one, or without the execution boundary that would obey
    # it, would silently drop the guarantee the operator asked for, so it is a
    # hard error on any binding.
    from . import config

    if config.NEAR_TEE_REQUIRED:
        if not config.TEE_ATTESTATION_ENABLED:
            raise ConfigurationError(
                "TRACESETTLE_NEAR_TEE_REQUIRED is set but TRACESETTLE_TEE_ATTESTATION is "
                "not; the gate would have no attestation to enforce. Enable the attestation "
                "provider, or unset TRACESETTLE_NEAR_TEE_REQUIRED"
            )
        if not config.NEAR_EXECUTION_ENABLED:
            raise ConfigurationError(
                "TRACESETTLE_NEAR_TEE_REQUIRED is set but TRACESETTLE_NEAR_EXECUTION is not; "
                "there is no execution boundary to enforce the gate on. Enable the execution "
                "boundary, or unset TRACESETTLE_NEAR_TEE_REQUIRED"
            )

    # The enclave signing boundary fails closed. Asking for enclave signing
    # without an endpoint to reach or an approved measurement to pin would
    # silently drop the guarantee the operator asked for, so it is a hard error
    # on any binding.
    if config.ENCLAVE_REQUIRED:
        if not config.ENCLAVE_SIGN_URL:
            raise ConfigurationError(
                "TRACESETTLE_ENCLAVE_REQUIRED is set but TRACESETTLE_ENCLAVE_SIGN_URL is not; "
                "there is no enclave signing endpoint to reach. Configure it, or unset "
                "TRACESETTLE_ENCLAVE_REQUIRED"
            )
        if not config.ENCLAVE_APPROVED_MEASUREMENT:
            raise ConfigurationError(
                "TRACESETTLE_ENCLAVE_REQUIRED is set but TRACESETTLE_ENCLAVE_APPROVED_MEASUREMENT "
                "is not; no enclave identity is approved, so provisioning would fail closed "
                "against every measurement. Pin the approved measurement, or unset "
                "TRACESETTLE_ENCLAVE_REQUIRED"
            )
        if not config.NEAR_EXECUTION_ENABLED:
            raise ConfigurationError(
                "TRACESETTLE_ENCLAVE_REQUIRED is set but TRACESETTLE_NEAR_EXECUTION is not; "
                "there is no execution boundary for the enclave to sign for. Enable the "
                "execution boundary, or unset TRACESETTLE_ENCLAVE_REQUIRED"
            )

    # The OutLayer custody boundary fails closed. Enabling a TEE-held signing
    # wallet without a key, with an unknown network, or without the execution
    # boundary that would authorize it would silently drop the guarantee the
    # operator asked for, so it is a hard error on any binding.
    if config.OUTLAYER_ENABLED:
        if not config.OUTLAYER_API_KEY:
            raise ConfigurationError(
                "TRACESETTLE_OUTLAYER_ENABLED is set but TRACESETTLE_OUTLAYER_API_KEY is not; "
                "there is no provider credential, so nothing could be signed. Set the key, "
                "or unset TRACESETTLE_OUTLAYER_ENABLED"
            )
        if config.OUTLAYER_NETWORK not in {"testnet", "mainnet"}:
            raise ConfigurationError(
                "TRACESETTLE_OUTLAYER_NETWORK must be 'testnet' or 'mainnet'; got an "
                "unsupported network name"
            )
        if not config.NEAR_EXECUTION_ENABLED:
            raise ConfigurationError(
                "TRACESETTLE_OUTLAYER_ENABLED is set but TRACESETTLE_NEAR_EXECUTION is not; "
                "there is no execution boundary to authorize an operation before it is "
                "signed. Enable the execution boundary, or unset TRACESETTLE_OUTLAYER_ENABLED"
            )
        # The independent NEAR provider policy is a second layer, separate from
        # OutLayer's own wallet policy. When the operator requires it but no Agent
        # API is configured, every custody operation would fail closed - the
        # feature would be silently dead. Refuse at start-up instead, naming the
        # variable, rather than run a boundary that can never authorize.
        if config.OUTLAYER_REQUIRE_PROVIDER_POLICY and not config.NEAR_AGENT_API_URL:
            raise ConfigurationError(
                "TRACESETTLE_OUTLAYER_ENABLED requires the independent NEAR provider policy, "
                "but TRACESETTLE_NEAR_AGENT_API_URL is not set, so the policy could never be "
                "read and every operation would fail closed. Set the Agent API base URL and "
                "key, or set TRACESETTLE_OUTLAYER_REQUIRE_PROVIDER_POLICY=0 to run without "
                "the provider-policy layer"
            )

    # The TEE signing boundary fails closed. Enabling a paid, remote signing
    # route without an owner/project/build, or asking for it as *required*
    # without the execution boundary that would obey it, would silently drop the
    # guarantee the operator asked for, so it is a hard error on any binding.
    if config.TEE_SIGNING_ENABLED:
        if not config.TEE_SIGNING_OWNER or not config.TEE_SIGNING_PROJECT:
            raise ConfigurationError(
                "TRACESETTLE_TEE_SIGNING is set but TRACESETTLE_TEE_SIGNING_OWNER or "
                "TRACESETTLE_TEE_SIGNING_PROJECT is not; the signing guest cannot be "
                "located. Set both, or unset TRACESETTLE_TEE_SIGNING"
            )
        if not config.TEE_SIGNING_APPROVED_BUILD:
            raise ConfigurationError(
                "TRACESETTLE_TEE_SIGNING is set but TRACESETTLE_TEE_SIGNING_APPROVED_BUILD "
                "is not; no build identity is pinned, so a swapped signing WASM could sign. "
                "Pin the approved build (sha256 of the signing WASM), or unset "
                "TRACESETTLE_TEE_SIGNING"
            )
        if config.TEE_SIGNING_NETWORK not in {"testnet", "mainnet"}:
            raise ConfigurationError(
                "TRACESETTLE_TEE_SIGNING_NETWORK must be 'testnet' or 'mainnet'; got an "
                "unsupported network name"
            )

    if config.TEE_SIGNING_REQUIRED:
        if not config.TEE_SIGNING_ENABLED:
            raise ConfigurationError(
                "TRACESETTLE_TEE_SIGNING_REQUIRED is set but TRACESETTLE_TEE_SIGNING is not; "
                "the gate would have no signing boundary to enforce. Enable the boundary, or "
                "unset TRACESETTLE_TEE_SIGNING_REQUIRED"
            )
        if not config.NEAR_EXECUTION_ENABLED:
            raise ConfigurationError(
                "TRACESETTLE_TEE_SIGNING_REQUIRED is set but TRACESETTLE_NEAR_EXECUTION is "
                "not; there is no execution boundary to enforce the gate on. Enable the "
                "execution boundary, or unset TRACESETTLE_TEE_SIGNING_REQUIRED"
            )

    if not public_binding:
        return profile

    # Client-supplied policy selection is a local-only affordance: it lets a
    # caller choose the policy it is judged against, which is exactly what the
    # enforcement boundary must not allow. Refuse rather than warn, so a
    # public deployment cannot be tricked into it by one environment variable.
    from . import config

    if config.NEAR_ALLOW_CLIENT_POLICY_SELECTION:
        raise ConfigurationError(
            "TRACESETTLE_NEAR_ALLOW_CLIENT_POLICY_SELECTION is set together with a public "
            "binding (host=%r). Client-supplied policy selection lets a caller choose the "
            "policy it is evaluated against, so it is loopback-only. Unset it, or bind "
            "127.0.0.1." % (host,)
        )

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
