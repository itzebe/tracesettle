"""Deterministic policy: what this deployment considers an authorized transfer.

A policy is plain data, loaded from a JSON file (``TRACESETTLE_GUARD_POLICY``) or
from the built-in default. Nothing here is learned or guessed; the same policy
plus the same request always yields the same decision.

Amounts in a policy file are decimal *strings*, never JSON numbers, so a policy
can express ``0.1`` exactly and cannot drift through binary floating point.
"""

from __future__ import annotations

import json
import os
import pathlib
from dataclasses import dataclass, field
from decimal import Decimal
from typing import Any

from .model import AmountError, canonical_amount, parse_amount


@dataclass(frozen=True)
class ServicePolicy:
    """What one transaction-requesting service identity is allowed to do."""

    service_id: str
    enabled: bool = True
    allowed_operations: frozenset[str] = field(default_factory=lambda: frozenset({"WITHDRAWAL"}))
    allowed_chains: frozenset[str] = frozenset()
    allowed_assets: frozenset[str] = frozenset()
    max_amount_per_transaction: Decimal | None = None
    max_amount_per_window: Decimal | None = None
    #: Above this amount the request needs a human approval before it can sign.
    approval_threshold: Decimal | None = None

    def to_dict(self) -> dict[str, Any]:
        return {
            "service_id": self.service_id,
            "enabled": self.enabled,
            "allowed_operations": sorted(self.allowed_operations),
            "allowed_chains": sorted(self.allowed_chains),
            "allowed_assets": sorted(self.allowed_assets),
            "max_amount_per_transaction": _amt(self.max_amount_per_transaction),
            "max_amount_per_window": _amt(self.max_amount_per_window),
            "approval_threshold": _amt(self.approval_threshold),
        }


@dataclass(frozen=True)
class PolicyConfig:
    """The complete authorization policy for one deployment."""

    policy_id: str = "default"
    name: str = "Default transaction security policy"
    version: str = "1"
    #: Destinations that may receive funds. Empty means "no destination is
    #: pre-approved", which is the safe default: every destination is then a
    #: review item rather than a silent allow.
    approved_destinations: frozenset[str] = frozenset()
    #: Known-bad destinations. A match is an immediate block.
    blocked_destinations: frozenset[str] = frozenset()
    services: dict[str, ServicePolicy] = field(default_factory=dict)
    per_transaction_limit: Decimal | None = None
    window_seconds: int = 3600
    max_requests_per_window: int = 60
    max_blocked_per_window: int = 5
    approval_threshold: Decimal | None = None
    min_approvals: int = 1
    #: Rejected authorization attempts (bad/expired/replayed) tolerated in a
    #: window before the service is treated as under attack.
    max_rejected_authorizations: int = 3
    authorization_ttl_seconds: int = 90
    #: When False, a destination that is not on the allowlist yields BLOCK
    #: rather than REQUIRE_APPROVAL. Default is the stricter "allowlist only".
    allow_unlisted_destinations: bool = False

    # -- helpers ------------------------------------------------------------

    def service(self, service_id: str) -> ServicePolicy | None:
        return self.services.get(service_id)

    def to_dict(self) -> dict[str, Any]:
        return {
            "policy_id": self.policy_id,
            "name": self.name,
            "version": self.version,
            "approved_destinations": sorted(self.approved_destinations),
            "blocked_destinations": sorted(self.blocked_destinations),
            "services": [s.to_dict() for s in self.services.values()],
            "per_transaction_limit": _amt(self.per_transaction_limit),
            "window_seconds": self.window_seconds,
            "max_requests_per_window": self.max_requests_per_window,
            "max_blocked_per_window": self.max_blocked_per_window,
            "approval_threshold": _amt(self.approval_threshold),
            "min_approvals": self.min_approvals,
            "max_rejected_authorizations": self.max_rejected_authorizations,
            "authorization_ttl_seconds": self.authorization_ttl_seconds,
            "allow_unlisted_destinations": self.allow_unlisted_destinations,
        }


def _amt(value: Decimal | None) -> str | None:
    return None if value is None else canonical_amount(value)


#: Destination case is normalised only where the chain's encoding is
#: case-insensitive. EVM hex is folded to lower case; everything else is exact.
def normalize_destination(value: str) -> str:
    value = (value or "").strip()
    if value[:2].lower() == "0x":
        return "0x" + value[2:].lower()
    return value


#: The built-in demonstration policy. It is a real, enforced policy: two
#: approved destinations, one service identity, and explicit limits. It exists
#: so the tool runs with no configuration file, not to make demos pass.
DEFAULT_POLICY = PolicyConfig(
    policy_id="default-v1",
    name="Default transaction security policy",
    version="1",
    approved_destinations=frozenset(
        {
            "0x4e6d3a556e485188e9c9a528bc72c88bd92bd735",
            "0xb741c00f6d63b6ded0ccada1a82bcbadc38a572b",
        }
    ),
    blocked_destinations=frozenset(
        {
            # A documented example of a denied destination. Real deployments
            # replace this from their own incident and screening feeds.
            "0x000000000000000000000000000000000000dEaD".lower(),
        }
    ),
    services={
        "treasury-agent": ServicePolicy(
            service_id="treasury-agent",
            allowed_operations=frozenset({"WITHDRAWAL", "SETTLEMENT"}),
            allowed_chains=frozenset({"eth", "base", "arb", "near"}),
            allowed_assets=frozenset({"USDC", "USDT", "ETH"}),
            max_amount_per_transaction=Decimal("10000"),
            max_amount_per_window=Decimal("25000"),
            approval_threshold=Decimal("5000"),
        )
    },
    per_transaction_limit=Decimal("10000"),
    window_seconds=3600,
    max_requests_per_window=30,
    max_blocked_per_window=5,
    approval_threshold=Decimal("5000"),
    min_approvals=1,
    max_rejected_authorizations=3,
    authorization_ttl_seconds=90,
    allow_unlisted_destinations=False,
)


def _parse_optional_amount(value: Any, field_name: str) -> Decimal | None:
    if value is None:
        return None
    try:
        return parse_amount(value)
    except AmountError as exc:
        raise ValueError(f"{field_name}: {exc}") from exc


def policy_from_dict(data: dict[str, Any]) -> PolicyConfig:
    """Build a policy from a parsed JSON object.

    Every field is optional and falls back to the default policy's value, so a
    partial file is a valid override. Unknown fields are ignored, not trusted.
    """
    base = DEFAULT_POLICY
    services: dict[str, ServicePolicy] = {}
    for raw in data.get("services", []) or []:
        if not isinstance(raw, dict) or not raw.get("service_id"):
            raise ValueError("each service entry needs a service_id")
        sid = str(raw["service_id"])
        services[sid] = ServicePolicy(
            service_id=sid,
            enabled=bool(raw.get("enabled", True)),
            allowed_operations=frozenset(
                str(x).upper() for x in raw.get("allowed_operations", ["WITHDRAWAL"])
            ),
            allowed_chains=frozenset(str(x).lower() for x in raw.get("allowed_chains", [])),
            allowed_assets=frozenset(str(x).upper() for x in raw.get("allowed_assets", [])),
            max_amount_per_transaction=_parse_optional_amount(
                raw.get("max_amount_per_transaction"), "max_amount_per_transaction"
            ),
            max_amount_per_window=_parse_optional_amount(
                raw.get("max_amount_per_window"), "max_amount_per_window"
            ),
            approval_threshold=_parse_optional_amount(
                raw.get("approval_threshold"), "approval_threshold"
            ),
        )
    if not services:
        services = dict(base.services)

    return PolicyConfig(
        policy_id=str(data.get("policy_id", base.policy_id)),
        name=str(data.get("name", base.name)),
        version=str(data.get("version", base.version)),
        approved_destinations=frozenset(
            normalize_destination(str(d)) for d in data.get("approved_destinations", [])
        )
        if "approved_destinations" in data
        else base.approved_destinations,
        blocked_destinations=frozenset(
            normalize_destination(str(d)) for d in data.get("blocked_destinations", [])
        )
        if "blocked_destinations" in data
        else base.blocked_destinations,
        services=services,
        per_transaction_limit=_parse_optional_amount(
            data.get("per_transaction_limit"), "per_transaction_limit"
        )
        if "per_transaction_limit" in data
        else base.per_transaction_limit,
        window_seconds=int(data.get("window_seconds", base.window_seconds)),
        max_requests_per_window=int(
            data.get("max_requests_per_window", base.max_requests_per_window)
        ),
        max_blocked_per_window=int(data.get("max_blocked_per_window", base.max_blocked_per_window)),
        approval_threshold=_parse_optional_amount(data.get("approval_threshold"), "approval_threshold")
        if "approval_threshold" in data
        else base.approval_threshold,
        min_approvals=int(data.get("min_approvals", base.min_approvals)),
        max_rejected_authorizations=int(
            data.get("max_rejected_authorizations", base.max_rejected_authorizations)
        ),
        authorization_ttl_seconds=int(
            data.get("authorization_ttl_seconds", base.authorization_ttl_seconds)
        ),
        allow_unlisted_destinations=bool(
            data.get("allow_unlisted_destinations", base.allow_unlisted_destinations)
        ),
    )


def load_policy(path: str | os.PathLike[str] | None = None) -> PolicyConfig:
    """Load the policy from ``path`` or ``TRACESETTLE_GUARD_POLICY``.

    A missing or unreadable policy file is an error, never a silent fallback to
    a more permissive policy: a security control that quietly degrades is worse
    than one that refuses to start.
    """
    resolved = path or os.environ.get("TRACESETTLE_GUARD_POLICY")
    if not resolved:
        return DEFAULT_POLICY
    text = pathlib.Path(resolved).read_text(encoding="utf-8")
    data = json.loads(text)
    if not isinstance(data, dict):
        raise ValueError("policy file must contain a JSON object")
    return policy_from_dict(data)
