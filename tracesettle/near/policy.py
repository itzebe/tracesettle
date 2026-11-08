"""NEAR Intents agent policy: read, validate, and scope-check.

Source of truth for the field names and the enforcement split is the official
page ``docs.agentsonintents.com/integration/agent-api/policies-and-limits``
(plus ``/concepts`` and ``/native-accounts``). The facts this module encodes:

* An agent has **one** policy. Each ``policy_update`` replaces the whole policy
  and names the ``expected_revision`` it edits.
* The policy is **in force only once** ``status`` is ``APPLIED`` **and**
  ``provider_policy_synced`` is ``true``. A requested or signed update is not
  enough; this module reports anything else as not-in-force.
* Two layers enforce the policy. The Agent API enforces ``destinations``,
  ``budget``, ``timelock_ms`` and ``schedule``. The agent's wallet enforces
  ``actions``, ``assets``, ``limits``, ``max_actions_per_hour``,
  ``owner_approval`` and ``frozen``.
* **Native requests are not protected by the Intents money rules.** For a
  native NEAR/EVM/Solana request, ``destinations``, ``budget``, ``timelock_ms``,
  ``schedule`` and ``owner_approval`` do not apply. The policy switch
  (``native.near.transfer`` and friends) is the whole fence. A NEAR transfer can
  go to any account whatever ``destinations`` says.

This module is read-only. It never signs, never writes a policy, and never
freezes or unfreezes an account. A policy that cannot be read is reported as
unavailable, never assumed permissive and never assumed restrictive.

The adapter can talk to the Agent API when a base URL and key are configured,
or read a local, clearly-labelled fixture for offline reproduction. It never
invents an endpoint: with no base URL configured it reports ``UNCONFIGURED`` and
the caller must supply a fixture.
"""

from __future__ import annotations

import enum
import json
import urllib.parse
from dataclasses import dataclass, field
from decimal import Decimal, InvalidOperation
from typing import Any

#: Cooldown the provider documents between policy changes (seconds).
POLICY_CHANGE_COOLDOWN_SECONDS = 600

#: Money actions an Intents policy can enable. Deposits need no action.
MONEY_ACTIONS = frozenset({"swap", "transfer", "withdraw"})

#: Limit windows the policy can express, per asset, in atomic units.
LIMIT_WINDOWS = ("per_transaction", "hourly", "daily", "monthly")

#: Native methods, exactly as the provider names them. When a chain is present
#: in ``native``, every method must be present; omitted means the method is off.
NATIVE_METHODS: dict[str, tuple[str, ...]] = {
    "near": ("sign_message", "transfer", "call"),
    "evm": ("sign_typed_data", "sign_message", "sign_transaction"),
    "solana": ("sign_message", "sign_transaction"),
}


class PolicyStatus(str, enum.Enum):
    """Provider lifecycle of a policy intent.

    Only ``APPLIED`` can be in force, and only together with
    ``provider_policy_synced``.
    """

    APPLIED = "APPLIED"
    PENDING = "PENDING"
    SIGNED = "SIGNED"
    REQUESTED = "REQUESTED"
    FAILED = "FAILED"
    UNKNOWN = "UNKNOWN"


class PolicyScope(str, enum.Enum):
    """Which transaction path a request takes.

    The distinction matters: an Intents-only policy protects the ``INTENTS``
    path and does **not** protect any native path.
    """

    INTENTS = "INTENTS"
    NATIVE_NEAR = "NATIVE_NEAR"
    NATIVE_EVM = "NATIVE_EVM"
    NATIVE_SOLANA = "NATIVE_SOLANA"

    @property
    def native(self) -> bool:
        return self is not PolicyScope.INTENTS

    @property
    def chain(self) -> str:
        return {
            PolicyScope.INTENTS: "near-intents",
            PolicyScope.NATIVE_NEAR: "near",
            PolicyScope.NATIVE_EVM: "evm",
            PolicyScope.NATIVE_SOLANA: "solana",
        }[self]


class PolicyAvailability(str, enum.Enum):
    """Whether the policy could be read at all (source health, not policy state)."""

    AVAILABLE = "AVAILABLE"
    #: No provider endpoint configured. A local fixture is required.
    UNCONFIGURED = "UNCONFIGURED"
    #: The provider answered, but refused (no key / wrong scope).
    UNAUTHENTICATED = "UNAUTHENTICATED"
    NOT_FOUND = "NOT_FOUND"
    #: The provider answered with a shape we cannot safely interpret.
    MALFORMED = "MALFORMED"
    UNAVAILABLE = "UNAVAILABLE"


class RequiredApproval(str, enum.Enum):
    """What the policy requires before an action may run."""

    NONE = "NONE"
    #: ``owner_approval`` is on: a human owner must approve the action.
    OWNER = "OWNER"


@dataclass(frozen=True)
class PolicyLimits:
    """Per-asset caps in atomic units, plus the hourly action count.

    Amounts are exact decimals. A limit expressed as a JSON number is read as a
    string first, so ``0.1`` cannot drift through binary floating point.
    """

    per_transaction: dict[str, Decimal] = field(default_factory=dict)
    hourly: dict[str, Decimal] = field(default_factory=dict)
    daily: dict[str, Decimal] = field(default_factory=dict)
    monthly: dict[str, Decimal] = field(default_factory=dict)
    max_actions_per_hour: int | None = None

    def limit_for(self, window: str, asset_id: str) -> Decimal | None:
        table = {
            "per_transaction": self.per_transaction,
            "hourly": self.hourly,
            "daily": self.daily,
            "monthly": self.monthly,
        }.get(window, {})
        return table.get(asset_id)

    def to_dict(self) -> dict[str, Any]:
        return {
            "per_transaction": {k: str(v) for k, v in self.per_transaction.items()},
            "hourly": {k: str(v) for k, v in self.hourly.items()},
            "daily": {k: str(v) for k, v in self.daily.items()},
            "monthly": {k: str(v) for k, v in self.monthly.items()},
            "max_actions_per_hour": self.max_actions_per_hour,
        }


@dataclass(frozen=True)
class DestinationRule:
    action: str
    chain: str
    address: str
    memo: str | None = None

    def matches(self, *, action: str, chain: str, address: str) -> bool:
        if self.action and self.action != action:
            return False
        if self.chain and self.chain != chain:
            return False
        return self.address == address

    def to_dict(self) -> dict[str, Any]:
        return {
            "action": self.action,
            "chain": self.chain,
            "address": self.address,
            "memo": self.memo,
        }


@dataclass(frozen=True)
class IntentsPolicy:
    """One agent's policy, as read from the provider (or a labelled fixture).

    Nothing here is trusted to be *in force*: read :attr:`in_force` before
    relying on any field.
    """

    agent_id: str
    revision: int
    status: PolicyStatus
    provider_policy_synced: bool
    frozen: bool = False
    actions: frozenset[str] = frozenset()
    assets: str = "any"
    asset_ids: frozenset[str] = frozenset()
    confidential: bool = False
    owner_approval: bool = False
    limits: PolicyLimits = field(default_factory=PolicyLimits)
    destinations_mode: str = "any"
    destinations: tuple[DestinationRule, ...] = ()
    budget_usd: Decimal | None = None
    #: Budget already spent (USD), read from the provider's usage view. ``None``
    #: when the provider supplies no usage. Never inferred from the budget.
    budget_spent_usd: Decimal | None = None
    timelock_ms: int | None = None
    schedule: dict[str, Any] | None = None
    native: dict[str, dict[str, bool]] = field(default_factory=dict)
    policy_hash: str | None = None
    #: When the provider read this policy revision (ISO-8601), if it supplies one.
    #: Used to enforce a freshness bound on a live policy read.
    as_of: str | None = None
    raw: dict[str, Any] = field(default_factory=dict)

    # -- state --------------------------------------------------------------

    @property
    def in_force(self) -> bool:
        """Whether the provider says this policy is actually applied and synced.

        Both conditions are required. A signed or requested update is not in
        force, so its rules must not be treated as active.
        """
        return self.status is PolicyStatus.APPLIED and self.provider_policy_synced

    @property
    def required_approval(self) -> RequiredApproval:
        return RequiredApproval.OWNER if self.owner_approval else RequiredApproval.NONE

    def asset_allowed(self, asset_id: str) -> bool:
        if self.assets == "any":
            return True
        return asset_id in self.asset_ids

    def native_method_enabled(self, chain: str, method: str) -> bool:
        methods = self.native.get(chain) or {}
        return bool(methods.get(method))

    def destination_allowed(self, *, action: str, chain: str, address: str) -> bool:
        if self.destinations_mode == "any":
            return True
        return any(
            rule.matches(action=action, chain=chain, address=address)
            for rule in self.destinations
        )

    def to_dict(self) -> dict[str, Any]:
        return {
            "agent_id": self.agent_id,
            "revision": self.revision,
            "status": self.status.value,
            "provider_policy_synced": self.provider_policy_synced,
            "in_force": self.in_force,
            "frozen": self.frozen,
            "actions": sorted(self.actions),
            "assets": self.assets,
            "asset_ids": sorted(self.asset_ids),
            "confidential": self.confidential,
            "owner_approval": self.owner_approval,
            "required_approval": self.required_approval.value,
            "limits": self.limits.to_dict(),
            "destinations_mode": self.destinations_mode,
            "destinations": [d.to_dict() for d in self.destinations],
            "budget_usd": None if self.budget_usd is None else str(self.budget_usd),
            "budget_spent_usd": (
                None if self.budget_spent_usd is None else str(self.budget_spent_usd)
            ),
            "timelock_ms": self.timelock_ms,
            "schedule": self.schedule,
            "native": self.native,
            "policy_hash": self.policy_hash,
            "as_of": self.as_of,
        }


# ---------------------------------------------------------------------------
# Scope analysis
# ---------------------------------------------------------------------------

#: Controls that apply only to the Intents money path.
INTENTS_ONLY_CONTROLS = (
    "destinations",
    "budget_usd",
    "timelock_ms",
    "schedule",
    "owner_approval",
)


def controls_applicable_to(scope: PolicyScope) -> tuple[str, ...]:
    """Which policy controls actually protect a request on this path.

    For a native path the Intents money controls do **not** apply; the only
    fence is the ``native`` method switch. Returning the real set here is what
    stops the wrapper from claiming a native transfer is covered by a
    destination list it is not.
    """
    if scope.native:
        return ("native_method_switch", "frozen")
    return (
        "actions",
        "assets",
        "limits",
        "max_actions_per_hour",
        "destinations",
        "budget_usd",
        "timelock_ms",
        "schedule",
        "owner_approval",
        "frozen",
    )


def controls_not_applicable_to(scope: PolicyScope) -> tuple[str, ...]:
    """Controls a caller might wrongly assume protect a native request."""
    if not scope.native:
        return ()
    return INTENTS_ONLY_CONTROLS


# ---------------------------------------------------------------------------
# Parsing
# ---------------------------------------------------------------------------


class PolicyParseError(ValueError):
    """A policy document we cannot interpret safely. Message is client-safe."""


def _dec(value: Any, field_name: str) -> Decimal | None:
    if value is None:
        return None
    if isinstance(value, bool) or isinstance(value, float):
        raise PolicyParseError(
            f"{field_name} must be a decimal string or integer, not a float"
        )
    text = str(value).strip()
    if not text:
        return None
    try:
        parsed = Decimal(text)
    except (InvalidOperation, ValueError) as exc:
        raise PolicyParseError(f"{field_name} is not a valid decimal number") from exc
    if not parsed.is_finite() or parsed < 0:
        raise PolicyParseError(f"{field_name} must be a finite non-negative number")
    return parsed


def _limits_from(raw: Any, max_actions_override: Any = None) -> PolicyLimits:
    if raw is None:
        raw = {}
    if not isinstance(raw, dict):
        raise PolicyParseError("policy.limits must be an object")
    out: dict[str, dict[str, Decimal]] = {w: {} for w in LIMIT_WINDOWS}
    for window in LIMIT_WINDOWS:
        table = raw.get(window) or {}
        if not isinstance(table, dict):
            raise PolicyParseError(f"policy.limits.{window} must be an object")
        for asset_id, amount in table.items():
            parsed = _dec(amount, f"policy.limits.{window}.{asset_id}")
            if parsed is not None:
                out[window][str(asset_id)] = parsed
    # The documented Policy carries ``max_actions_per_hour`` beside ``limits``;
    # a flat fixture may instead nest it under ``limits``. Either is accepted,
    # the explicit sibling value taking precedence.
    max_actions = max_actions_override if max_actions_override is not None else raw.get("max_actions_per_hour")
    if max_actions is not None:
        if isinstance(max_actions, bool) or not isinstance(max_actions, int) or max_actions < 0:
            raise PolicyParseError(
                "policy.limits.max_actions_per_hour must be a non-negative integer"
            )
    return PolicyLimits(
        per_transaction=out["per_transaction"],
        hourly=out["hourly"],
        daily=out["daily"],
        monthly=out["monthly"],
        max_actions_per_hour=max_actions,
    )


def _destinations_from(raw: Any) -> tuple[str, tuple[DestinationRule, ...]]:
    if raw is None:
        return "any", ()
    if not isinstance(raw, dict):
        raise PolicyParseError("policy.destinations must be an object")
    mode = str(raw.get("mode", "any"))
    rules: list[DestinationRule] = []
    entries = raw.get("list") or []
    if not isinstance(entries, list):
        raise PolicyParseError("policy.destinations.list must be an array")
    for entry in entries:
        if not isinstance(entry, dict):
            raise PolicyParseError("each destination must be an object")
        address = str(entry.get("address", "")).strip()
        if not address:
            raise PolicyParseError("each destination needs an address")
        rules.append(
            DestinationRule(
                action=str(entry.get("action", "")).strip().lower(),
                chain=str(entry.get("chain", "")).strip().lower(),
                address=address,
                memo=(str(entry["memo"]) if entry.get("memo") is not None else None),
            )
        )
    return mode, tuple(rules)


def _native_from(raw: Any) -> dict[str, dict[str, bool]]:
    if raw is None:
        return {}
    if not isinstance(raw, dict):
        raise PolicyParseError("policy.native must be an object")
    out: dict[str, dict[str, bool]] = {}
    for chain, methods in raw.items():
        chain_name = str(chain).strip().lower()
        if chain_name not in NATIVE_METHODS:
            raise PolicyParseError(
                f"policy.native.{chain_name} is not a supported native chain"
            )
        if not isinstance(methods, dict):
            raise PolicyParseError(f"policy.native.{chain_name} must be an object")
        # The provider requires every method to be present when a chain is
        # switched on. A missing method is off, never assumed on.
        for method in NATIVE_METHODS[chain_name]:
            out.setdefault(chain_name, {})[method] = False
        for method, enabled in methods.items():
            method_name = str(method).strip().lower()
            out.setdefault(chain_name, {})[method_name] = _native_method_on(enabled)
    return out


def _native_method_on(enabled: Any) -> bool:
    """Whether a native method switch is on.

    ``transfer`` is a boolean. ``sign_message`` / ``call`` /
    ``sign_transaction`` are arrays of permitted message prefixes, contract
    ids, or selectors: an **empty** array is off, a non-empty array is on. A
    plain boolean is also accepted. Anything else is off, never assumed on.
    """
    if isinstance(enabled, bool):
        return enabled
    if isinstance(enabled, (list, tuple)):
        return len(enabled) > 0
    return False


def _budget_from(body: dict[str, Any], usage: Any) -> tuple[Decimal | None, Decimal | None]:
    """The policy's budget and, separately, its already-spent amount (USD).

    The documented ``Policy.budget`` is an object of window amounts
    (``daily_usd`` / ``weekly_usd`` / ``monthly_usd``); the tightest set window
    is the effective budget. A flat fixture may instead carry a scalar
    ``budget_usd``. The provider's *usage* is read only from ``usage.budget``
    (the ``BudgetView``), never from the policy's own budget object.
    """
    budget = _dec(body.get("budget_usd"), "policy.budget_usd")
    if budget is None:
        raw_budget = body.get("budget")
        if isinstance(raw_budget, dict):
            for window in ("daily_usd", "weekly_usd", "monthly_usd"):
                parsed = _dec(raw_budget.get(window), f"policy.budget.{window}")
                if parsed is not None:
                    budget = parsed if budget is None else min(budget, parsed)
        elif raw_budget is not None:
            budget = _dec(raw_budget, "policy.budget")
    spent: Decimal | None = None
    if isinstance(usage, dict):
        usage_budget = usage.get("budget")
        if isinstance(usage_budget, dict):
            for window in ("daily", "weekly", "monthly"):
                entry = usage_budget.get(window)
                if isinstance(entry, dict):
                    parsed = _dec(entry.get("spent_usd"), "usage.budget.spent_usd")
                    if parsed is not None:
                        spent = parsed if spent is None else max(spent, parsed)
    return budget, spent


def parse_policy(raw: Any) -> IntentsPolicy:
    """Parse a provider policy document into an :class:`IntentsPolicy`.

    Two documented shapes are accepted. The live endpoint
    ``GET /v1/agents/{agent_id}/policy`` returns a **PolicyView** whose
    lifecycle fields (``status``, ``provider_policy_synced``, ``revision``,
    ``policy_hash``, ``applied_at``) sit at the top level and whose rules are
    nested under ``policy`` (a **Policy**). A flat document (used by local
    fixtures and the offline demonstration) carries both in one object. When
    both are present the nested ``Policy`` provides the rules and the envelope
    provides the lifecycle.

    Strict: an unexpected shape raises :class:`PolicyParseError` rather than
    being coerced into a permissive default.
    """
    if not isinstance(raw, dict):
        raise PolicyParseError("policy must be a JSON object")

    # A PolicyView nests the rules under 'policy'; a flat document does not.
    nested = raw.get("policy")
    body = nested if isinstance(nested, dict) else raw
    view = raw

    def field(name: str, default: Any = None) -> Any:
        # Rules come from the nested Policy when present; lifecycle falls back
        # to the flat document so both shapes parse.
        if name in body:
            return body[name]
        return view.get(name, default)

    agent_id = str(body.get("agent_id", view.get("agent_id", "")) or "").strip()
    revision_raw = field("revision", 0)
    try:
        revision = int(revision_raw)
    except (TypeError, ValueError) as exc:
        raise PolicyParseError("policy.revision must be an integer") from exc

    status_raw = str(field("status", "UNKNOWN")).strip().upper()
    try:
        status = PolicyStatus(status_raw)
    except ValueError:
        status = PolicyStatus.UNKNOWN

    synced = field("provider_policy_synced")
    provider_synced = bool(synced) if synced is not None else False

    actions_raw = body.get("actions") or []
    if not isinstance(actions_raw, (list, tuple)):
        raise PolicyParseError("policy.actions must be an array")
    actions = frozenset(str(a).strip().lower() for a in actions_raw)

    assets_raw = body.get("assets", "any")
    asset_ids: frozenset[str] = frozenset()
    if isinstance(assets_raw, (list, tuple)):
        asset_ids = frozenset(str(a) for a in assets_raw)
        assets = "list"
    else:
        assets = str(assets_raw)

    destinations_mode, destinations = _destinations_from(body.get("destinations"))
    native = _native_from(body.get("native"))
    timelock = body.get("timelock_ms")
    if timelock is not None:
        if isinstance(timelock, bool) or not isinstance(timelock, int) or timelock < 0:
            raise PolicyParseError("policy.timelock_ms must be a non-negative integer")

    schedule = body.get("schedule")
    if schedule is not None and not isinstance(schedule, dict):
        raise PolicyParseError("policy.schedule must be an object")

    budget_usd, budget_spent_usd = _budget_from(body, view.get("usage"))

    return IntentsPolicy(
        agent_id=agent_id,
        revision=revision,
        status=status,
        provider_policy_synced=provider_synced,
        frozen=bool(body.get("frozen", False)),
        actions=actions,
        assets=assets,
        asset_ids=asset_ids,
        confidential=bool(body.get("confidential", False)),
        owner_approval=bool(body.get("owner_approval", False)),
        limits=_limits_from(body.get("limits"), body.get("max_actions_per_hour")),
        destinations_mode=destinations_mode,
        destinations=destinations,
        budget_usd=budget_usd,
        budget_spent_usd=budget_spent_usd,
        timelock_ms=timelock,
        schedule=schedule,
        native=native,
        policy_hash=(str(field("policy_hash")) if field("policy_hash") else None),
        # Freshness: the documented PolicyView exposes ``applied_at``; a fixture
        # may carry ``as_of``. Either names when the revision became current.
        as_of=(str(field("as_of") or field("applied_at")) if (field("as_of") or field("applied_at")) else None),
        raw=body,
    )


# ---------------------------------------------------------------------------
# Adapter
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class PolicyRead:
    """The result of reading a policy: availability + the policy, if any."""

    availability: PolicyAvailability
    policy: IntentsPolicy | None = None
    detail: str = ""
    endpoint: str | None = None
    #: True when the policy came from a local fixture, not the provider.
    local_fixture: bool = False

    @property
    def ok(self) -> bool:
        return self.availability is PolicyAvailability.AVAILABLE and self.policy is not None

    def to_dict(self) -> dict[str, Any]:
        return {
            "availability": self.availability.value,
            "detail": self.detail,
            "endpoint": self.endpoint,
            "local_fixture": self.local_fixture,
            "policy": self.policy.to_dict() if self.policy else None,
        }


@dataclass(frozen=True)
class ProviderAuth:
    """The result of authenticating against the Agent API (``GET /v1/whoami``).

    Carries only the provider's own non-secret identifiers. The API key itself
    is never stored, logged, or returned.
    """

    authenticated: bool
    api_key_id: str | None = None
    tenant_id: str | None = None
    detail: str = ""
    endpoint: str | None = None
    http_status: int | None = None

    def to_dict(self) -> dict[str, Any]:
        return {
            "authenticated": self.authenticated,
            "api_key_id": self.api_key_id,
            "tenant_id": self.tenant_id,
            "detail": self.detail,
            "endpoint": self.endpoint,
            "http_status": self.http_status,
        }


class PolicyAdapter:
    """Reads an agent policy from the Agent API, or from a labelled fixture.

    The Agent API base URL and key are **never invented**. With no base URL
    configured the adapter reports ``UNCONFIGURED`` and the caller supplies a
    local fixture for offline reproduction. This keeps the zero-budget rule and
    the "no fabricated endpoints" rule intact.
    """

    def __init__(
        self,
        *,
        base_url: str | None = None,
        api_key: str | None = None,
        http_client: Any = None,
        expected_host: str | None = None,
        expected_agent_id: str | None = None,
        max_age_seconds: int = 0,
        now: Any = None,
    ) -> None:
        self.base_url = (base_url or "").rstrip("/") or None
        self._api_key = api_key or None
        self._http = http_client
        # Provider identity: the host the policy read is allowed to come from.
        # ``None`` means "any host", which is only safe when the base URL was
        # configured by the operator; a caller-supplied host is never trusted.
        self.expected_host = (expected_host or "").strip().lower() or None
        # Agent association: the read must be for the operator's agent.
        self.expected_agent_id = (expected_agent_id or "").strip() or None
        # Freshness: 0 disables the age check; otherwise the policy's ``as_of``
        # (when the provider supplies one) must be no older than this.
        self.max_age_seconds = int(max_age_seconds or 0)
        self._now = now

    def read_policy(self, agent_id: str) -> PolicyRead:
        """Read one agent's policy from the configured provider, and verify it.

        The provider is the Agent API. It is called only when a base URL and an
        HTTP client are configured; otherwise the read is reported as
        unconfigured. Nothing about the endpoint is guessed: it is the
        documented ``GET /v1/agents/{agent_id}/policy`` path. The API key is
        sent as the ``X-API-Key`` header and is never logged.

        Four things are verified before the read is reported ``AVAILABLE``:
        the provider host (identity), the agent association, the policy
        revision's ``as_of`` freshness (when a bound is set), and that the body
        actually parsed. Any failure is reported as a non-available read, so a
        caller fails closed rather than trusting an unverified policy.
        """
        if not self.base_url or self._http is None:
            return PolicyRead(
                availability=PolicyAvailability.UNCONFIGURED,
                detail=(
                    "No Agent API base URL is configured. Set TRACESETTLE_NEAR_AGENT_API_URL "
                    "and TRACESETTLE_NEAR_AGENT_API_KEY to read live policy, or load a local "
                    "fixture with PolicyAdapter.from_fixture."
                ),
            )
        if not self._api_key:
            return PolicyRead(
                availability=PolicyAvailability.UNAUTHENTICATED,
                detail=(
                    "No Agent API key is configured. The provider requires X-API-Key; refusing "
                    "to make an unauthenticated read that would be reported as a policy."
                ),
            )
        host = urllib.parse.urlsplit(self.base_url).hostname or ""
        if self.expected_host and host.lower() != self.expected_host:
            return PolicyRead(
                availability=PolicyAvailability.MALFORMED,
                detail=(
                    "the configured Agent API host does not match the pinned provider host; "
                    "refusing to trust a policy read from an unexpected provider"
                ),
            )
        if self.expected_agent_id and str(agent_id) != self.expected_agent_id:
            return PolicyRead(
                availability=PolicyAvailability.MALFORMED,
                detail=(
                    "the requested agent id does not match the configured agent; refusing to "
                    "trust a policy read for a different agent"
                ),
            )
        endpoint = f"{self.base_url}/v1/agents/{agent_id}/policy"
        try:
            result = self._http.get_json(endpoint, headers={"X-API-Key": self._api_key})
        except Exception as exc:  # noqa: BLE001 - any transport failure is "unavailable"
            return PolicyRead(
                availability=PolicyAvailability.UNAVAILABLE,
                detail=f"policy read failed: {type(exc).__name__}",
                endpoint=endpoint,
            )
        status = getattr(result, "http_status", None)
        source_status = getattr(result, "status", None)
        body = getattr(result, "data", None)
        if status in (401, 403) or str(source_status) == "SourceStatus.UNAUTHORIZED":
            return PolicyRead(
                availability=PolicyAvailability.UNAUTHENTICATED,
                detail="the provider refused the request (missing or wrong credentials)",
                endpoint=endpoint,
            )
        if status == 404:
            return PolicyRead(
                availability=PolicyAvailability.NOT_FOUND,
                detail="no policy exists for this agent yet",
                endpoint=endpoint,
            )
        if not getattr(result, "ok", False) or body is None:
            return PolicyRead(
                availability=PolicyAvailability.UNAVAILABLE,
                detail=f"the provider returned an unusable response (status {status})",
                endpoint=endpoint,
            )
        try:
            policy = parse_policy(body)
        except PolicyParseError as exc:
            return PolicyRead(
                availability=PolicyAvailability.MALFORMED,
                detail=f"the provider policy could not be interpreted: {exc}",
                endpoint=endpoint,
            )
        # Agent association, verified against the *body*, not just the request.
        if self.expected_agent_id and policy.agent_id and policy.agent_id != self.expected_agent_id:
            return PolicyRead(
                availability=PolicyAvailability.MALFORMED,
                detail=(
                    "the provider returned a policy for a different agent; refusing to trust it"
                ),
                endpoint=endpoint,
            )
        freshness = self._freshness(policy)
        if freshness is not None:
            return PolicyRead(
                availability=PolicyAvailability.UNAVAILABLE,
                detail=freshness,
                endpoint=endpoint,
            )
        return PolicyRead(
            availability=PolicyAvailability.AVAILABLE,
            policy=policy,
            detail="policy read from the provider and verified (host, agent, freshness)",
            endpoint=endpoint,
        )

    def authenticate(self) -> ProviderAuth:
        """Authenticate the configured key against the Agent API (``GET /v1/whoami``).

        Read-only and free. Distinguishes a valid key (200 with identifiers),
        invalid/retired credentials (401/403), an unavailable provider
        (5xx/timeout), and an unconfigured adapter. The key is sent only as the
        ``X-API-Key`` header and is never logged or returned; only the
        provider's own ``api_key_id``/``tenant_id`` are surfaced.
        """
        if not self.base_url or self._http is None:
            return ProviderAuth(
                authenticated=False,
                detail=(
                    "No Agent API base URL is configured. Set TRACESETTLE_NEAR_AGENT_API_URL "
                    "and TRACESETTLE_NEAR_AGENT_API_KEY to authenticate."
                ),
            )
        if not self._api_key:
            return ProviderAuth(
                authenticated=False,
                detail=(
                    "No Agent API key is configured. The provider requires X-API-Key; refusing "
                    "to make an unauthenticated whoami call."
                ),
            )
        endpoint = f"{self.base_url}/v1/whoami"
        try:
            result = self._http.get_json(endpoint, headers={"X-API-Key": self._api_key})
        except Exception as exc:  # noqa: BLE001 - any transport failure is "unavailable"
            return ProviderAuth(
                authenticated=False,
                detail=f"whoami request failed: {type(exc).__name__}",
                endpoint=endpoint,
            )
        status = getattr(result, "http_status", None)
        source_status = getattr(result, "status", None)
        body = getattr(result, "data", None)
        if status in (401, 403) or str(source_status) == "SourceStatus.UNAUTHORIZED":
            return ProviderAuth(
                authenticated=False,
                detail="the provider rejected the key (invalid or retired credentials)",
                endpoint=endpoint,
                http_status=status,
            )
        if not getattr(result, "ok", False) or not isinstance(body, dict):
            return ProviderAuth(
                authenticated=False,
                detail=f"the provider did not return an identity document (status {status})",
                endpoint=endpoint,
                http_status=status,
            )
        api_key_id = str(body.get("api_key_id") or "").strip() or None
        tenant_id = str(body.get("tenant_id") or "").strip() or None
        if not api_key_id and not tenant_id:
            return ProviderAuth(
                authenticated=False,
                detail="the provider response carried no identity fields",
                endpoint=endpoint,
                http_status=status,
            )
        return ProviderAuth(
            authenticated=True,
            api_key_id=api_key_id,
            tenant_id=tenant_id,
            detail="authenticated against the Agent API",
            endpoint=endpoint,
            http_status=status,
        )

    def _freshness(self, policy: "IntentsPolicy") -> str | None:
        """Return a refusal reason when the policy is too old, else ``None``."""
        if self.max_age_seconds <= 0:
            return None
        as_of = getattr(policy, "as_of", None)
        if not as_of:
            return (
                "the provider policy carries no 'as_of' timestamp, so its freshness cannot be "
                "established; refusing to treat it as current"
            )
        try:
            from datetime import datetime, timezone

            observed = datetime.fromisoformat(str(as_of).replace("Z", "+00:00"))
            if observed.tzinfo is None:
                observed = observed.replace(tzinfo=timezone.utc)
        except ValueError:
            return f"the provider policy 'as_of' ({as_of!r}) is not a parseable timestamp"
        now = self._now() if callable(self._now) else (self._now or datetime.now(timezone.utc))
        if now.tzinfo is None:
            now = now.replace(tzinfo=timezone.utc)
        age = (now - observed).total_seconds()
        if age > self.max_age_seconds:
            return (
                f"the provider policy is {int(age)}s old, beyond the {self.max_age_seconds}s "
                "freshness bound; refusing to treat it as current"
            )
        if age < -self.max_age_seconds:
            return "the provider policy 'as_of' is in the future; refusing to trust it"
        return None

    @staticmethod
    def from_fixture(
        raw: Any, *, agent_id: str = "fixture-agent", detail: str = ""
    ) -> PolicyRead:
        """Load a policy from a local, clearly-labelled fixture.

        The returned read is marked ``local_fixture=True`` so no caller can
        mistake it for live provider state.
        """
        try:
            policy = parse_policy(raw)
        except PolicyParseError as exc:
            return PolicyRead(
                availability=PolicyAvailability.MALFORMED,
                detail=f"fixture policy could not be interpreted: {exc}",
                local_fixture=True,
            )
        if not policy.agent_id:
            policy = IntentsPolicy(**{**policy.__dict__, "agent_id": agent_id})
        return PolicyRead(
            availability=PolicyAvailability.AVAILABLE,
            policy=policy,
            detail=detail or "policy loaded from a local fixture (not live provider state)",
            local_fixture=True,
        )


def load_fixture(path: str) -> PolicyRead:
    """Load a policy fixture from a JSON file on disk."""
    with open(path, "r", encoding="utf-8") as handle:
        raw = json.load(handle)
    return PolicyAdapter.from_fixture(raw, detail=f"policy fixture loaded from {path}")


class FixturePolicyAdapter:
    """An adapter that always returns one fixed, labelled fixture read.

    Used when the operator pins a local fixture instead of a live Agent API URL
    (offline reproduction). It has the same ``read_policy`` shape as
    :class:`PolicyAdapter` so a caller - including the provider-policy gate -
    cannot tell the two apart, but the read it returns is marked
    ``local_fixture=True`` and it never contacts a provider.
    """

    def __init__(self, read: PolicyRead) -> None:
        self._read = read
        #: Present so a caller can report the source honestly; a fixture has none.
        self.base_url: str | None = None

    def read_policy(self, agent_id: str) -> PolicyRead:  # noqa: ARG002 - fixed fixture
        return self._read


def adapter_from_config(config: Any, http_client: Any = None) -> Any:
    """Build a policy adapter from server configuration, or ``None``.

    Precedence matches the guard's own resolution: the operator's pinned fixture
    first (offline reproduction), then a live Agent API URL. When neither is
    configured the result is ``None``, so the provider-policy layer is reported
    as *not applied* rather than invented. The API key is read only here and is
    never logged or returned.
    """
    fixture = getattr(config, "NEAR_POLICY_FIXTURE", None)
    if fixture:
        return FixturePolicyAdapter(load_fixture(fixture))
    base_url = getattr(config, "NEAR_AGENT_API_URL", None)
    if base_url:
        return PolicyAdapter(
            base_url=base_url,
            api_key=getattr(config, "NEAR_AGENT_API_KEY", None),
            http_client=http_client,
            expected_host=getattr(config, "NEAR_AGENT_API_EXPECTED_HOST", None),
            expected_agent_id=getattr(config, "NEAR_AGENT_ID", None),
            max_age_seconds=getattr(config, "NEAR_AGENT_POLICY_MAX_AGE_SECONDS", 0),
        )
    return None
