"""NEAR integration for TRACESETTLE.

Two capabilities, both standard-library only:

* **Pre-execution protection** (:mod:`tracesettle.near.agent_wrapper`): an
  agent-side authorization wrapper that asks the guard for a decision on the
  *actual* transaction parameters before an agent is allowed to sign or submit.
  It also reads the agent's NEAR Intents policy
  (:mod:`tracesettle.near.policy`) and the scope of the access key the agent
  would sign with (:mod:`tracesettle.near.access_keys`), so a request that is
  outside the protection of either is not silently treated as authorized.

* **Post-settlement assurance** (:mod:`tracesettle.near.settlement`): a thin,
  documented mapping from the existing 1Click/NEAR evidence into the NEAR
  settlement stages, so a provider's "success" is never taken as proof.

Honest scope, repeated everywhere because it matters:

* Nothing here signs, broadcasts, or moves funds. The reference executor is
  simulated and says so.
* The policy adapter *reads* policy state. It never requests an owner signature,
  never writes a policy, and never freezes or unfreezes an account.
* A policy is reported in force only when the provider says it is ``APPLIED``
  and ``provider_policy_synced``; a requested or signed update is not enough.
* Native NEAR/EVM/Solana requests are **not** protected by an Intents policy's
  destinations, budget, timelock, schedule or owner approval. That gap is
  surfaced explicitly, never papered over.
"""

from __future__ import annotations

from .attacks import (
    SCENARIOS,
    ScenarioResult,
    near_demo_policy,
    run_all,
    run_scenario,
    scenario_catalog,
)
from .access_keys import (
    AccessKeyAnalysis,
    AccessKeyPermission,
    AccessKeyRisk,
    analyze_access_keys,
    parse_access_key,
)
from .agent_wrapper import (
    AGENT_DECISION_OUTCOMES,
    AgentAuthorizationWrapper,
    AgentTransaction,
    WrapperDecision,
    WrapperOutcome,
)
from .policy import (
    IntentsPolicy,
    PolicyAdapter,
    PolicyAvailability,
    PolicyLimits,
    PolicyScope,
    PolicyStatus,
    RequiredApproval,
    parse_policy,
)
from .settlement import (
    NearSettlementAssurance,
    settlement_assurance_from_result,
)
from .tee import TeeAssessment, assess_verifiable_execution

__all__ = [
    "AGENT_DECISION_OUTCOMES",
    "SCENARIOS",
    "ScenarioResult",
    "AccessKeyAnalysis",
    "AccessKeyPermission",
    "AccessKeyRisk",
    "AgentAuthorizationWrapper",
    "AgentTransaction",
    "IntentsPolicy",
    "NearSettlementAssurance",
    "PolicyAdapter",
    "PolicyAvailability",
    "PolicyLimits",
    "PolicyScope",
    "PolicyStatus",
    "RequiredApproval",
    "TeeAssessment",
    "WrapperDecision",
    "WrapperOutcome",
    "analyze_access_keys",
    "near_demo_policy",
    "run_all",
    "run_scenario",
    "scenario_catalog",
    "assess_verifiable_execution",
    "parse_access_key",
    "parse_policy",
    "settlement_assurance_from_result",
]
