"""The independent NEAR provider-policy gate.

TraceSettle enforces **two** independent policy layers before an agent's payment
may reach a signer:

* its own operator policy (the seven deterministic guard controls in
  :mod:`tracesettle.guard.rules`), and
* the **provider** policy the NEAR Intents Agent API holds for the agent
  (:mod:`tracesettle.near.policy`).

This module is the second layer. It is deliberately *not* OutLayer's wallet
policy: OutLayer governs what its own custody wallet will sign, while the Agent
API policy is what the agent's operator has authorized the agent to do. One is
not a substitute for the other, and neither is trusted to be in force without
being read and checked.

The gate never weakens a decision. It runs after the guard has decided and can
only make the outcome *stricter* (``ALLOW`` -> ``HOLD``/``BLOCK``), never looser.
Every failure to establish that the provider policy is in force resolves to
``HOLD`` - the guard's "insufficient evidence" outcome - so a policy that cannot
be read, is stale, is not applied, or is malformed never yields an authorization.

The guard's decision vocabulary has no ``UNKNOWN`` value; ``HOLD`` *is* its
"cannot establish" state, and it never authorizes signing. The gate therefore
reports the reason precisely (``UNAVAILABLE``, ``MALFORMED``, ``NOT_IN_FORCE``,
...) while mapping every non-establishing reason onto ``HOLD``.

An explicit denial (``FROZEN``, a disabled native method) maps to ``BLOCK``: the
provider says *no*, rather than *we cannot tell*.
"""

from __future__ import annotations

import enum
from dataclasses import dataclass, field, replace
from typing import Any

from ..guard.model import (
    Decision,
    FindingSeverity,
    GuardDecision,
    RiskFinding,
)

#: The policy layer name recorded in findings, so an explanation never implies
#: the operator policy alone decided the outcome.
PROVIDER_POLICY_LAYER = "near provider policy (NEAR Intents Agent API)"

#: The native action a NEAR transfer corresponds to in the provider policy's
#: ``native.near`` switch.
NATIVE_TRANSFER_ACTION = "transfer"


class ProviderPolicyOutcome(str, enum.Enum):
    """Why the provider policy did or did not permit this operation.

    The vocabulary distinguishes *cannot establish* (mapped to ``HOLD``) from
    *explicitly denied* (mapped to ``BLOCK``), because the two demand different
    operator responses.
    """

    #: The provider policy is applied, synced, not frozen, and enables the action.
    IN_FORCE = "IN_FORCE"
    #: The policy exists but is not applied/synced; its rules are not active.
    NOT_IN_FORCE = "NOT_IN_FORCE"
    #: The agent's wallet is frozen by the provider.
    FROZEN = "FROZEN"
    #: The policy does not enable the native NEAR transfer method.
    NATIVE_TRANSFER_DISABLED = "NATIVE_TRANSFER_DISABLED"
    #: No provider endpoint is configured and live policy is required.
    UNCONFIGURED = "UNCONFIGURED"
    #: The provider refused the read (missing or wrong credentials).
    UNAUTHENTICATED = "UNAUTHENTICATED"
    #: The provider has no policy for this agent yet.
    NOT_FOUND = "NOT_FOUND"
    #: The provider answered with a shape that cannot be safely interpreted.
    MALFORMED = "MALFORMED"
    #: The provider could not be reached, or answered unusably.
    UNAVAILABLE = "UNAVAILABLE"
    #: The policy's freshness could not be established within the bound.
    STALE = "STALE"
    #: The read returned a policy for a different agent.
    AGENT_MISMATCH = "AGENT_MISMATCH"


#: Outcomes that are an explicit denial by the provider, not an absence of
#: evidence. These map to ``BLOCK``.
_DENIAL_OUTCOMES = frozenset(
    {ProviderPolicyOutcome.FROZEN, ProviderPolicyOutcome.NATIVE_TRANSFER_DISABLED}
)

#: Severity of the finding each outcome raises.
_SEVERITY: dict[ProviderPolicyOutcome, FindingSeverity] = {
    ProviderPolicyOutcome.IN_FORCE: FindingSeverity.INFO,
    ProviderPolicyOutcome.FROZEN: FindingSeverity.CRITICAL,
    ProviderPolicyOutcome.NATIVE_TRANSFER_DISABLED: FindingSeverity.HIGH,
    ProviderPolicyOutcome.NOT_IN_FORCE: FindingSeverity.HIGH,
    ProviderPolicyOutcome.UNAVAILABLE: FindingSeverity.HIGH,
    ProviderPolicyOutcome.MALFORMED: FindingSeverity.HIGH,
    ProviderPolicyOutcome.UNAUTHENTICATED: FindingSeverity.HIGH,
    ProviderPolicyOutcome.NOT_FOUND: FindingSeverity.HIGH,
    ProviderPolicyOutcome.STALE: FindingSeverity.HIGH,
    ProviderPolicyOutcome.AGENT_MISMATCH: FindingSeverity.CRITICAL,
    ProviderPolicyOutcome.UNCONFIGURED: FindingSeverity.HIGH,
}


@dataclass(frozen=True)
class ProviderPolicyDecision:
    """The gate's verdict, with the provenance of the policy it read."""

    outcome: ProviderPolicyOutcome
    detail: str
    #: The guard decision this implies. ``ALLOW`` only for ``IN_FORCE``.
    decision: Decision
    #: Where the policy came from: ``live``, ``fixture`` or ``none``.
    source: str
    endpoint: str | None = None
    agent_id: str | None = None
    revision: int | None = None
    status: str | None = None
    provider_policy_synced: bool | None = None
    as_of: str | None = None
    policy_hash: str | None = None
    #: True when the policy was read from a local fixture, never the provider.
    local_fixture: bool = False
    #: The provider's own usage counters, when the read supplied them. Kept as
    #: *evidence*: they are gateway-supplied and best-effort under concurrency, so
    #: they are never the enforcement for a strict limit (TraceSettle's own
    #: durable counters are). Recorded so an investigator can see them.
    usage_counters: dict[str, Any] = field(default_factory=dict)

    @property
    def permitted(self) -> bool:
        return self.decision is Decision.ALLOW

    @property
    def blocks_execution(self) -> bool:
        return not self.permitted

    def to_dict(self) -> dict[str, Any]:
        return {
            "outcome": self.outcome.value,
            "decision": self.decision.value,
            "detail": self.detail,
            "source": self.source,
            "endpoint": self.endpoint,
            "agent_id": self.agent_id,
            "revision": self.revision,
            "status": self.status,
            "provider_policy_synced": self.provider_policy_synced,
            "as_of": self.as_of,
            "policy_hash": self.policy_hash,
            "local_fixture": self.local_fixture,
            "usage_counters": dict(self.usage_counters),
            "permitted": self.permitted,
        }


def _decision_for(outcome: ProviderPolicyOutcome) -> Decision:
    if outcome is ProviderPolicyOutcome.IN_FORCE:
        return Decision.ALLOW
    if outcome in _DENIAL_OUTCOMES:
        return Decision.BLOCK
    return Decision.HOLD


class ProviderPolicyGate:
    """Reads the provider policy and requires it to be in force.

    ``require`` is the operator's explicit decision to depend on the provider
    policy. When ``True`` (the default for the real-execution path) *every*
    failure to establish the policy resolves to a non-``ALLOW`` decision. When
    ``False`` an unconfigured or unreachable provider is reported but does not
    block, which is only appropriate where the provider policy is known not to
    apply.
    """

    def __init__(
        self,
        adapter: Any,
        *,
        agent_id: str,
        require: bool = True,
        native_chain: str = "near",
        action: str = NATIVE_TRANSFER_ACTION,
    ) -> None:
        if not agent_id:
            raise ValueError("a provider-policy gate requires the agent id it is reading for")
        self.adapter = adapter
        self.agent_id = agent_id
        self.require = bool(require)
        self.native_chain = native_chain
        self.action = action

    def evaluate(self) -> ProviderPolicyDecision:
        """Read the provider policy and decide whether it permits the operation."""
        read = self.adapter.read_policy(self.agent_id)
        availability = getattr(read.availability, "value", str(read.availability))
        source = "fixture" if getattr(read, "local_fixture", False) else "live"

        if not read.ok or read.policy is None:
            outcome = self._unavailable_outcome(availability)
            decision = _decision_for(outcome)
            if not self.require and outcome in {
                ProviderPolicyOutcome.UNCONFIGURED,
                ProviderPolicyOutcome.UNAVAILABLE,
                ProviderPolicyOutcome.NOT_FOUND,
                ProviderPolicyOutcome.UNAUTHENTICATED,
                ProviderPolicyOutcome.STALE,
            }:
                # The operator has declared the provider policy non-authoritative
                # for this deployment; report the read honestly but do not block.
                return ProviderPolicyDecision(
                    outcome=outcome,
                    detail=(
                        f"provider policy could not be read ({outcome.value}: {read.detail}); "
                        "not required by configuration, so it does not block"
                    ),
                    decision=Decision.ALLOW,
                    source=source,
                    endpoint=getattr(read, "endpoint", None),
                    agent_id=self.agent_id,
                    local_fixture=getattr(read, "local_fixture", False),
                )
            return ProviderPolicyDecision(
                outcome=outcome,
                detail=f"provider policy could not be established ({outcome.value}): {read.detail}",
                decision=decision,
                source=source,
                endpoint=getattr(read, "endpoint", None),
                agent_id=self.agent_id,
                local_fixture=getattr(read, "local_fixture", False),
            )

        policy = read.policy
        common = dict(
            source=source,
            endpoint=getattr(read, "endpoint", None),
            agent_id=policy.agent_id or self.agent_id,
            revision=policy.revision,
            status=getattr(policy.status, "value", str(policy.status)),
            provider_policy_synced=policy.provider_policy_synced,
            as_of=policy.as_of,
            policy_hash=policy.policy_hash,
            local_fixture=getattr(read, "local_fixture", False),
        )

        # Agent association, re-checked against the parsed body even though the
        # adapter already verified it: a policy for another agent must never be
        # read as this agent's.
        if policy.agent_id and policy.agent_id != self.agent_id:
            return ProviderPolicyDecision(
                outcome=ProviderPolicyOutcome.AGENT_MISMATCH,
                detail=(
                    f"the provider returned a policy for agent '{policy.agent_id}', not "
                    f"'{self.agent_id}'; refusing to treat it as this agent's policy"
                ),
                decision=Decision.BLOCK,
                **common,
            )

        if not policy.in_force:
            return ProviderPolicyDecision(
                outcome=ProviderPolicyOutcome.NOT_IN_FORCE,
                detail=(
                    f"the provider policy is not in force (status={common['status']}, "
                    f"provider_policy_synced={policy.provider_policy_synced}); a requested or "
                    "signed update is not active, so no operation is authorized under it"
                ),
                decision=Decision.HOLD,
                **common,
            )

        if policy.frozen:
            return ProviderPolicyDecision(
                outcome=ProviderPolicyOutcome.FROZEN,
                detail="the provider has frozen this agent's wallet; no operation is permitted",
                decision=Decision.BLOCK,
                **common,
            )

        # The native method switch is the whole fence for a native NEAR transfer:
        # the Intents money rules (destinations/budget/timelock) do not apply.
        if not policy.native_method_enabled(self.native_chain, self.action):
            return ProviderPolicyDecision(
                outcome=ProviderPolicyOutcome.NATIVE_TRANSFER_DISABLED,
                detail=(
                    f"the provider policy does not enable native.{self.native_chain}."
                    f"{self.action}; a native NEAR transfer is refused by this policy"
                ),
                decision=Decision.BLOCK,
                **common,
            )

        return ProviderPolicyDecision(
            outcome=ProviderPolicyOutcome.IN_FORCE,
            detail=(
                f"the provider policy (revision {policy.revision}) is applied and synced, not "
                f"frozen, and enables native.{self.native_chain}.{self.action}"
            ),
            decision=Decision.ALLOW,
            usage_counters=_usage_counters(policy),
            **common,
        )

    @staticmethod
    def _unavailable_outcome(availability: str) -> ProviderPolicyOutcome:
        try:
            return ProviderPolicyOutcome(availability)
        except ValueError:
            # NOT_IN_FORCE/STALE are not source-health words; anything else the
            # adapter reports is treated as an unreadable policy.
            if availability == "STALE":
                return ProviderPolicyOutcome.STALE
            return ProviderPolicyOutcome.UNAVAILABLE


def _finding_for(decision: ProviderPolicyDecision) -> RiskFinding:
    """The finding the gate contributes, so the decision explains itself."""
    return RiskFinding(
        code=f"PROVIDER_POLICY_{decision.outcome.value}",
        severity=_SEVERITY.get(decision.outcome, FindingSeverity.HIGH),
        title="NEAR provider policy",
        detail=decision.detail,
        policy=PROVIDER_POLICY_LAYER,
        observed={
            "provider_policy_outcome": decision.outcome.value,
            "provider_policy_source": decision.source,
            "provider_policy_revision": str(decision.revision)
            if decision.revision is not None
            else "unknown",
        },
    )


def _usage_counters(policy: Any) -> dict[str, Any]:
    """Extract the provider's usage counters from a parsed policy, if present.

    These are gateway-supplied and best-effort under concurrency (the provider
    documents them as such), so they are recorded as evidence only. TraceSettle's
    own durable counters are what enforce a strict limit.
    """
    raw = getattr(policy, "raw", None) or {}
    counters = raw.get("usage") or raw.get("counters")
    return dict(counters) if isinstance(counters, dict) else {}


def combine_provider_policy(
    decision: GuardDecision,
    gate_decision: ProviderPolicyDecision,
) -> GuardDecision:
    """Fold the provider-policy verdict into a guard decision, never loosening it.

    The combined decision is the stricter of the two. When the gate blocks, any
    authorization the guard issued is discarded - a token that could reach a
    signer must not survive a provider-policy refusal.
    """
    combined = decision.decision
    if gate_decision.decision.severity > combined.severity:
        combined = gate_decision.decision

    findings = decision.findings
    # Only add a finding when the gate says something beyond "in force": an
    # IN_FORCE pass adds noise, not information.
    if gate_decision.outcome is not ProviderPolicyOutcome.IN_FORCE:
        findings = findings + (_finding_for(gate_decision),)

    authorization = decision.authorization
    if combined is not Decision.ALLOW:
        authorization = None

    applicable = decision.applicable_policies
    if PROVIDER_POLICY_LAYER not in applicable:
        applicable = tuple(sorted(set(applicable) | {PROVIDER_POLICY_LAYER}))

    explanation = decision.explanation
    if gate_decision.outcome is not ProviderPolicyOutcome.IN_FORCE:
        explanation = f"{explanation} Provider policy: {gate_decision.detail}"

    risk_level = decision.risk_level
    if gate_decision.outcome is not ProviderPolicyOutcome.IN_FORCE:
        risk_level = max(
            [risk_level, _SEVERITY.get(gate_decision.outcome, FindingSeverity.HIGH)],
            key=lambda s: s.rank,
        )

    return replace(
        decision,
        decision=combined,
        authorization=authorization,
        findings=findings,
        applicable_policies=applicable,
        explanation=explanation,
        risk_level=risk_level,
    )
