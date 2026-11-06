"""Agent-side authorization wrapper.

The wrapper is the piece an AI agent (or a payment service acting for one) must
call **before** it is allowed to sign or submit a transaction. It inspects the
*actual* transaction parameters — never the agent's explanation of them — and
returns one of five outcomes:

``ALLOW``
    Proceed. Only when an exact, transaction-bound authorization is valid.
``REQUIRE_APPROVAL`` (the "WARN" outcome)
    An authenticated human must approve before signing.
``BLOCK``
    Refuse to sign or submit.
``HOLD``
    Do not execute while the required security condition is unresolved.
``UNKNOWN``
    Fail safely: the evidence needed to authorize could not be obtained.

Three independent checks feed the outcome, and the strictest wins:

1. **The guard decision** on the transaction parameters. This is the existing
   deterministic control set (identity, destination, amount, velocity, rejected
   authorizations, client assertions, integrity).
2. **The NEAR Intents policy scope**. An Intents-only policy does not protect a
   native NEAR/EVM/Solana request; that gap is surfaced, not hidden.
3. **The access-key scope**. A function-call key cannot transfer NEAR, so an
   agent that intends a NEAR transfer with such a key is refused before signing.

Nothing here signs a real transaction. The reference signer's executor is
simulated and every receipt says so.
"""

from __future__ import annotations

import enum
from dataclasses import dataclass, field
from datetime import datetime, timezone
from decimal import Decimal
from typing import Any

from ..guard.model import (
    AmountError,
    Decision,
    GuardDecision,
    SignOutcome,
    SignResult,
    TransactionRequest,
    parse_amount,
)
from ..guard.service import GuardService
from ..guard.signer import SignRequest
from .access_keys import AccessKeyAnalysis, AccessKeyPermission, key_supports_operation
from .approval import ApprovalRequest
from .counterparty import CounterpartyOutcome, CounterpartyRead
from .policy import (
    IntentsPolicy,
    PolicyAvailability,
    PolicyRead,
    PolicyScope,
    controls_applicable_to,
    controls_not_applicable_to,
)


class WrapperOutcome(str, enum.Enum):
    """The five outcomes an agent-facing wrapper may return."""

    ALLOW = "ALLOW"
    #: The mission's "WARN": an authenticated human approval is required.
    REQUIRE_APPROVAL = "REQUIRE_APPROVAL"
    BLOCK = "BLOCK"
    HOLD = "HOLD"
    UNKNOWN = "UNKNOWN"

    @property
    def severity(self) -> int:
        return _OUTCOME_SEVERITY[self]

    @property
    def permits_signing(self) -> bool:
        return self is WrapperOutcome.ALLOW


#: Ordered so a strictest-wins combination is a simple ``max``. UNKNOWN is the
#: strictest because "we could not prove it is safe" must never be weaker than a
#: plain refusal: an unknown result is a fail-safe stop, not a soft warning.
_OUTCOME_SEVERITY: dict[WrapperOutcome, int] = {
    WrapperOutcome.ALLOW: 0,
    WrapperOutcome.REQUIRE_APPROVAL: 1,
    WrapperOutcome.HOLD: 2,
    WrapperOutcome.BLOCK: 3,
    WrapperOutcome.UNKNOWN: 4,
}

#: The outcomes the mission requires, as a machine-readable list.
AGENT_DECISION_OUTCOMES = tuple(o.value for o in WrapperOutcome)


class WrapperSeverity(str, enum.Enum):
    INFO = "INFO"
    LOW = "LOW"
    MEDIUM = "MEDIUM"
    HIGH = "HIGH"
    CRITICAL = "CRITICAL"

    @property
    def rank(self) -> int:
        return _WRAPPER_RANK[self]


_WRAPPER_RANK = {
    WrapperSeverity.INFO: 0,
    WrapperSeverity.LOW: 1,
    WrapperSeverity.MEDIUM: 2,
    WrapperSeverity.HIGH: 3,
    WrapperSeverity.CRITICAL: 4,
}


@dataclass(frozen=True)
class WrapperFinding:
    code: str
    severity: WrapperSeverity
    title: str
    detail: str
    observed: dict[str, str] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        return {
            "code": self.code,
            "severity": self.severity.value,
            "title": self.title,
            "detail": self.detail,
            "observed": dict(self.observed),
        }


@dataclass(frozen=True)
class AgentTransaction:
    """A transaction an agent wants to sign, described by its real parameters.

    The wrapper reads these fields, not any prose the agent supplies. ``scope``
    selects whether the request is an Intents action or a native NEAR/EVM/Solana
    action, because the two are governed by different policy controls.
    """

    service_id: str
    operation: str
    chain: str
    asset: str
    amount: str
    destination: str
    scope: PolicyScope = PolicyScope.INTENTS
    #: The Intents policy action this request maps to (``swap``, ``transfer``,
    #: ``withdraw``). Declared explicitly because the guard and the Intents API
    #: use different vocabularies (the guard says ``WITHDRAWAL``, the policy says
    #: ``withdraw``). When omitted it is derived from ``operation``.
    policy_action: str | None = None
    request_id: str | None = None
    idempotency_key: str | None = None
    client_reference: str | None = None
    #: For a native contract call: the receiver and method the agent will call.
    receiver_id: str | None = None
    method_name: str | None = None
    #: True when the operation moves NEAR (a transfer, or a call attaching NEAR).
    transfers_near: bool = False
    simulated: bool = True
    #: Fields the agent sent hoping to assert its own approval. Never honoured.
    asserted_approval_fields: tuple[str, ...] = ()
    metadata: dict[str, Any] = field(default_factory=dict)

    def to_request(self) -> TransactionRequest:
        """Build the guard request from the *actual* parameters.

        Raises :class:`AmountError` for an amount that cannot be used safely.
        """
        amount: Decimal = parse_amount(self.amount)
        return TransactionRequest(
            request_id=self.request_id or f"agent-{self.service_id}",
            service_id=self.service_id,
            operation=self.operation,
            chain=self.chain,
            asset=self.asset,
            amount=amount,
            destination=self.destination,
            amount_raw=str(self.amount),
            idempotency_key=self.idempotency_key,
            client_reference=self.client_reference,
            simulated=self.simulated,
            asserted_approval_fields=self.asserted_approval_fields,
            metadata=dict(self.metadata),
        )

    def to_dict(self) -> dict[str, Any]:
        return {
            "service_id": self.service_id,
            "operation": self.operation,
            "chain": self.chain,
            "asset": self.asset,
            "amount": self.amount,
            "destination": self.destination,
            "scope": self.scope.value,
            "policy_action": self.policy_action,
            "request_id": self.request_id,
            "idempotency_key": self.idempotency_key,
            "receiver_id": self.receiver_id,
            "method_name": self.method_name,
            "transfers_near": self.transfers_near,
            "simulated": self.simulated,
        }


@dataclass(frozen=True)
class WrapperDecision:
    """The explainable result of asking the wrapper whether an agent may sign."""

    outcome: WrapperOutcome
    summary: str
    transaction: AgentTransaction
    scope: PolicyScope
    findings: tuple[WrapperFinding, ...] = ()
    guard_decision: GuardDecision | None = None
    policy: PolicyRead | None = None
    access_key: AccessKeyAnalysis | None = None
    counterparty: CounterpartyRead | None = None
    #: Controls that actually protect this request on this path.
    applicable_controls: tuple[str, ...] = ()
    #: Controls a caller might wrongly assume protect this request.
    non_applicable_controls: tuple[str, ...] = ()
    limitations: tuple[str, ...] = ()
    simulated: bool = True

    @property
    def permits_signing(self) -> bool:
        return self.outcome.permits_signing and self.authorization is not None

    @property
    def authorization(self) -> Any:
        if self.guard_decision is None:
            return None
        return self.guard_decision.authorization

    def to_dict(self, *, include_authorization: bool = False) -> dict[str, Any]:
        out: dict[str, Any] = {
            "outcome": self.outcome.value,
            "permits_signing": self.permits_signing,
            "summary": self.summary,
            "scope": self.scope.value,
            "transaction": self.transaction.to_dict(),
            "applicable_controls": list(self.applicable_controls),
            "non_applicable_controls": list(self.non_applicable_controls),
            "findings": [f.to_dict() for f in self.findings],
            "limitations": list(self.limitations),
            "simulated": self.simulated,
            "policy": self.policy.to_dict() if self.policy else None,
            "access_key": self.access_key.to_dict() if self.access_key else None,
            "counterparty": self.counterparty.to_dict() if self.counterparty else None,
            "guard_decision": (
                self.guard_decision.to_dict(include_authorization=include_authorization)
                if self.guard_decision
                else None
            ),
        }
        return out


@dataclass(frozen=True)
class WrapperSubmission:
    """The result of asking the wrapper to actually sign/submit a transaction."""

    outcome: WrapperOutcome
    decision: WrapperDecision
    sign_result: SignResult | None = None
    detail: str = ""

    @property
    def executed(self) -> bool:
        return self.sign_result is not None and self.sign_result.outcome is SignOutcome.EXECUTED

    def to_dict(self) -> dict[str, Any]:
        return {
            "outcome": self.outcome.value,
            "detail": self.detail,
            "executed": self.executed,
            "decision": self.decision.to_dict(),
            "sign_result": self.sign_result.to_dict() if self.sign_result else None,
        }


def _finding(
    code: str,
    severity: WrapperSeverity,
    title: str,
    detail: str,
    observed: dict[str, str] | None = None,
) -> WrapperFinding:
    return WrapperFinding(
        code=code, severity=severity, title=title, detail=detail, observed=observed or {}
    )


def _utc_now_iso() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


class AgentAuthorizationWrapper:
    """Refuses to let an agent sign until TraceSettle says it may.

    The wrapper is deterministic: identical parameters, policy and key produce
    an identical outcome. It consults no model and no score.
    """

    def __init__(
        self,
        service: GuardService,
        *,
        policy_read: PolicyRead | None = None,
        access_key: AccessKeyAnalysis | None = None,
        counterparty: CounterpartyRead | None = None,
    ) -> None:
        self._service = service
        self._policy_read = policy_read
        self._access_key = access_key
        self._counterparty = counterparty

    # -- evaluation ---------------------------------------------------------

    def evaluate(
        self,
        transaction: AgentTransaction,
        *,
        approval: Any = None,
        counterparty: CounterpartyRead | None = None,
    ) -> WrapperDecision:
        """Decide whether the agent may sign this transaction.

        Every check runs; the strictest outcome wins. Nothing short-circuits, so
        the returned decision carries the whole picture.

        ``approval`` is a human approval (see
        :mod:`tracesettle.near.approval`). It is honoured only for a
        ``REQUIRE_APPROVAL`` outcome and only when bound to this exact payload;
        it can never override a ``BLOCK``. ``counterparty`` overrides the
        configured counterparty read for this call (used by tests and the demo);
        otherwise the wrapper's own read, if any, is used.
        """
        findings: list[WrapperFinding] = []
        limitations: list[str] = []
        proposed: list[WrapperOutcome] = []

        scope = transaction.scope
        cp_read = counterparty if counterparty is not None else self._counterparty

        # 1. The guard decision on the real parameters.
        guard_decision: GuardDecision | None = None
        try:
            request = transaction.to_request()
        except AmountError as exc:
            findings.append(
                _finding(
                    "INVALID_AMOUNT",
                    WrapperSeverity.HIGH,
                    "Amount cannot be used safely",
                    f"The transaction amount could not be parsed: {exc}",
                    {"amount": str(transaction.amount)},
                )
            )
            proposed.append(WrapperOutcome.UNKNOWN)
            request = None

        if request is not None:
            guard_decision = self._service.evaluate(request, approval=approval)
            proposed.append(_outcome_from_guard(guard_decision.decision))
            findings.append(
                _finding(
                    "GUARD_DECISION",
                    WrapperSeverity.INFO,
                    f"TraceSettle guard decision: {guard_decision.decision.value}",
                    guard_decision.summary,
                    {"decision": guard_decision.decision.value},
                )
            )
            for risk in guard_decision.findings:
                findings.append(
                    _finding(
                        f"GUARD_{risk.code}",
                        WrapperSeverity(risk.severity.value),
                        risk.title,
                        risk.detail,
                        risk.observed,
                    )
                )

        # 2. The NEAR Intents policy scope.
        policy_outcome, policy_findings, policy_limitations = self._evaluate_policy(
            transaction, self._policy_read
        )
        proposed.append(policy_outcome)
        findings.extend(policy_findings)
        limitations.extend(policy_limitations)

        # 3. The access-key scope.
        key_outcome, key_findings = self._evaluate_access_key(transaction, self._access_key)
        proposed.append(key_outcome)
        findings.extend(key_findings)

        # 4. Counterparty risk intelligence.
        cp_outcome, cp_findings, cp_limitations = _evaluate_counterparty(cp_read)
        proposed.append(cp_outcome)
        findings.extend(cp_findings)
        limitations.extend(cp_limitations)

        outcome = max(proposed, key=lambda o: o.severity) if proposed else WrapperOutcome.UNKNOWN
        applicable = controls_applicable_to(scope)
        non_applicable = controls_not_applicable_to(scope)
        if non_applicable:
            limitations.append(
                "This is a native request: the Intents policy controls "
                f"{list(non_applicable)} do not apply. Only the policy's native method switch "
                "and an independent TraceSettle decision protect it."
            )

        summary = _summarize(outcome, transaction, findings)
        return WrapperDecision(
            outcome=outcome,
            summary=summary,
            transaction=transaction,
            scope=scope,
            findings=tuple(findings),
            guard_decision=guard_decision,
            policy=self._policy_read,
            access_key=self._access_key,
            counterparty=cp_read,
            applicable_controls=applicable,
            non_applicable_controls=non_applicable,
            limitations=tuple(limitations),
            simulated=transaction.simulated,
        )

    # -- submission ---------------------------------------------------------

    def approval_request(
        self, transaction: AgentTransaction, *, summary: str | None = None
    ) -> ApprovalRequest:
        """Build the approval a human must give before this exact payload may sign.

        The returned :class:`~tracesettle.near.approval.ApprovalRequest` carries
        the payload fingerprint the eventual approval must be bound to, so the
        human is approving *these* parameters. It does not approve anything: only
        a :class:`~tracesettle.near.approval.HumanApprovalChannel` can mint an
        approval, and the agent holds no reference to one.
        """
        request = transaction.to_request()
        fingerprint = self._service.approval_payload_fingerprint(request)
        return ApprovalRequest(
            request_id=transaction.request_id or f"apr-{transaction.service_id}",
            service_id=transaction.service_id,
            operation=transaction.operation,
            chain=transaction.chain,
            asset=transaction.asset,
            amount=str(transaction.amount),
            destination=transaction.destination,
            payload_fingerprint=fingerprint,
            summary=summary
            or (
                f"{transaction.operation} {transaction.amount} {transaction.asset} to "
                f"{transaction.destination}"
            ),
            created_at=_utc_now_iso(),
        )

    def submit(
        self,
        transaction: AgentTransaction,
        authorization: Any,
        *,
        approval: Any = None,
        decision: WrapperDecision | None = None,
    ) -> WrapperSubmission:
        """Sign/submit only if the wrapper allows it, then hand to the signer.

        The authorization is validated by the signer against the *actual*
        transaction, so a token minted for a different destination, amount or
        asset is refused even though it is genuine. This is the "changed the
        destination after approval" case. A ``REQUIRE_APPROVAL`` outcome is
        re-evaluated with ``approval`` so a human approval bound to this exact
        payload is the only way it can reach the signer.

        ``decision`` may be supplied to reuse a decision already produced by
        :meth:`evaluate` - which is what a caller does after a human approval,
        because a human approval is single-use and a second evaluation would
        consume it. The signer still independently re-derives the binding from
        the transaction it is asked to sign, so a reused decision cannot smuggle
        an unauthorized transaction past the boundary.
        """
        if decision is None:
            decision = self.evaluate(transaction, approval=approval)
        if not decision.permits_signing:
            return WrapperSubmission(
                outcome=decision.outcome,
                decision=decision,
                sign_result=None,
                detail=(
                    "the wrapper did not permit signing, so the transaction never reached the "
                    "signer"
                ),
            )

        request = transaction.to_request()
        sign_result = self._service.sign(
            SignRequest(transaction=request, authorization=authorization)
        )
        if sign_result.outcome is SignOutcome.EXECUTED:
            return WrapperSubmission(
                outcome=WrapperOutcome.ALLOW,
                decision=decision,
                sign_result=sign_result,
                detail="authorization validated against the actual transaction; executed",
            )
        # A refusal at the signing boundary is a hard stop, never a soft warning.
        return WrapperSubmission(
            outcome=WrapperOutcome.BLOCK,
            decision=decision,
            sign_result=sign_result,
            detail=f"the signer refused: {sign_result.state.value} ({sign_result.detail})",
        )

    # -- internals ----------------------------------------------------------

    def _evaluate_policy(
        self, transaction: AgentTransaction, policy_read: PolicyRead | None
    ) -> tuple[WrapperOutcome, list[WrapperFinding], list[str]]:
        findings: list[WrapperFinding] = []
        limitations: list[str] = []
        scope = transaction.scope

        if policy_read is None:
            return WrapperOutcome.ALLOW, findings, limitations

        if policy_read.availability is not PolicyAvailability.AVAILABLE or policy_read.policy is None:
            # We could not read the policy. For a native request the policy
            # switch is the only fence, so an unreadable policy is a HOLD: we
            # cannot prove the method is enabled. For an Intents request the
            # guard's own policy still governs, so we warn rather than block.
            severity = WrapperSeverity.HIGH if scope.native else WrapperSeverity.MEDIUM
            findings.append(
                _finding(
                    "POLICY_UNAVAILABLE",
                    severity,
                    "Agent policy could not be read",
                    f"Policy availability is {policy_read.availability.value}: {policy_read.detail}",
                )
            )
            if scope.native:
                limitations.append(
                    "A native request is fenced only by the policy's native method switch; with "
                    "the policy unreadable, that switch cannot be confirmed."
                )
                return WrapperOutcome.HOLD, findings, limitations
            return WrapperOutcome.REQUIRE_APPROVAL, findings, limitations

        policy: IntentsPolicy = policy_read.policy
        if policy_read.local_fixture:
            limitations.append(
                "The policy was read from a local fixture, not from live provider state. It is a "
                "reproduction of the documented shape, not a statement about a real agent."
            )

        # A policy that is not APPLIED+synced is not in force, whatever it says.
        if not policy.in_force:
            findings.append(
                _finding(
                    "POLICY_NOT_IN_FORCE",
                    WrapperSeverity.HIGH,
                    "Policy is not in force",
                    f"The policy status is {policy.status.value} and provider_policy_synced is "
                    f"{policy.provider_policy_synced}. A requested or signed update is not applied; "
                    "its rules must not be treated as active.",
                    {
                        "status": policy.status.value,
                        "provider_policy_synced": str(policy.provider_policy_synced),
                    },
                )
            )
            if scope.native:
                return WrapperOutcome.HOLD, findings, limitations
            return WrapperOutcome.REQUIRE_APPROVAL, findings, limitations

        # From here the policy is in force.
        if policy.frozen:
            findings.append(
                _finding(
                    "AGENT_FROZEN",
                    WrapperSeverity.CRITICAL,
                    "Agent is frozen",
                    "The in-force policy freezes this agent; no money action may run.",
                )
            )
            return WrapperOutcome.BLOCK, findings, limitations

        if scope.native:
            return self._evaluate_native(transaction, policy, findings, limitations)

        # Intents path: check the money-action controls the API/wallet enforce.
        action = _policy_action_for(transaction)
        if action and action not in policy.actions:
            findings.append(
                _finding(
                    "POLICY_ACTION_DENIED",
                    WrapperSeverity.HIGH,
                    "Action not enabled by the policy",
                    f"The policy enables {sorted(policy.actions)}; '{action}' is not among them.",
                    {"action": action},
                )
            )
            return WrapperOutcome.BLOCK, findings, limitations

        asset_id = str(transaction.metadata.get("asset_id") or transaction.asset)
        if not policy.asset_allowed(asset_id):
            findings.append(
                _finding(
                    "POLICY_ASSET_DENIED",
                    WrapperSeverity.HIGH,
                    "Asset not permitted by the policy",
                    f"The policy permits {sorted(policy.asset_ids)}; '{asset_id}' is not among them.",
                    {"asset_id": asset_id},
                )
            )
            return WrapperOutcome.BLOCK, findings, limitations

        per_tx = policy.limits.limit_for("per_transaction", asset_id)
        if per_tx is not None:
            try:
                amount = parse_amount(transaction.amount)
            except AmountError:
                amount = None
            if amount is not None and amount > per_tx:
                findings.append(
                    _finding(
                        "POLICY_PER_TRANSACTION_EXCEEDED",
                        WrapperSeverity.HIGH,
                        "Amount exceeds the policy per-transaction limit",
                        f"Requested {transaction.amount} {asset_id}; the policy per-transaction "
                        f"limit is {per_tx}.",
                        {"amount": str(transaction.amount), "limit": str(per_tx)},
                    )
                )
                return WrapperOutcome.BLOCK, findings, limitations

        if not policy.destination_allowed(
            action=action, chain=transaction.chain.strip().lower(), address=transaction.destination
        ):
            findings.append(
                _finding(
                    "POLICY_DESTINATION_DENIED",
                    WrapperSeverity.HIGH,
                    "Destination not permitted by the policy",
                    f"The policy destination list (mode '{policy.destinations_mode}') does not "
                    f"include {transaction.destination} for action '{action}'.",
                    {"destination": transaction.destination},
                )
            )
            return WrapperOutcome.BLOCK, findings, limitations

        if policy.required_approval is not None and policy.owner_approval:
            findings.append(
                _finding(
                    "POLICY_OWNER_APPROVAL_REQUIRED",
                    WrapperSeverity.MEDIUM,
                    "Owner approval required",
                    "The in-force policy requires an owner approval before this action runs.",
                )
            )
            return WrapperOutcome.REQUIRE_APPROVAL, findings, limitations

        return WrapperOutcome.ALLOW, findings, limitations

    def _evaluate_native(
        self,
        transaction: AgentTransaction,
        policy: IntentsPolicy,
        findings: list[WrapperFinding],
        limitations: list[str],
    ) -> tuple[WrapperOutcome, list[WrapperFinding], list[str]]:
        """A native NEAR/EVM/Solana request: only the method switch applies."""
        chain_key = {
            PolicyScope.NATIVE_NEAR: "near",
            PolicyScope.NATIVE_EVM: "evm",
            PolicyScope.NATIVE_SOLANA: "solana",
        }.get(transaction.scope, "near")
        method = str(transaction.metadata.get("native_method") or "").strip().lower()
        if not method:
            method = {
                "near": "transfer" if transaction.transfers_near else "call",
                "evm": "sign_transaction",
                "solana": "sign_transaction",
            }.get(chain_key, "call")

        if not policy.native_method_enabled(chain_key, method):
            findings.append(
                _finding(
                    "POLICY_SCOPE_REJECTED",
                    WrapperSeverity.HIGH,
                    "Native method not enabled by the policy",
                    f"The in-force policy does not enable native.{chain_key}.{method}. An Intents "
                    "policy's destinations, budget, timelock, schedule and owner approval do not "
                    "protect a native request; the method switch is the whole fence, and it is off.",
                    {"chain": chain_key, "method": method},
                )
            )
            return WrapperOutcome.BLOCK, findings, limitations

        # The switch is on. The Intents money rules still do not apply, so an
        # independent TraceSettle decision is what governs. Record the gap.
        findings.append(
            _finding(
                "NATIVE_NOT_COVERED_BY_INTENTS_POLICY",
                WrapperSeverity.MEDIUM,
                "Native request is outside the Intents money controls",
                f"native.{chain_key}.{method} is enabled, but destinations, budget, timelock_ms, "
                "schedule and owner_approval do not apply to native requests. An independent "
                "TraceSettle authorization is required.",
                {"chain": chain_key, "method": method},
            )
        )
        limitations.append(
            f"native.{chain_key}.{method} is enabled, but the Intents money controls do not apply "
            "to it; only the independent TraceSettle decision governs."
        )
        return WrapperOutcome.ALLOW, findings, limitations

    def _evaluate_access_key(
        self, transaction: AgentTransaction, analysis: AccessKeyAnalysis | None
    ) -> tuple[WrapperOutcome, list[WrapperFinding]]:
        """Check the access key against the request.

        The key's scope only fences an operation the agent signs **directly**,
        which is a native NEAR/EVM/Solana request. On the Intents path the
        agent's wallet provider signs the on-chain transaction, so the key scope
        is not the fence there; the policy and the guard decision are. Applying
        the key check to Intents would be wrong in both directions: it would
        reject a legitimate withdrawal and it would imply the key protects an
        action it never signs.

        What is always worth reporting, on either path, is a full-access key:
        an agent that holds one can transfer NEAR and add keys, so it forces a
        review regardless of the request.
        """
        findings: list[WrapperFinding] = []
        if analysis is None:
            return WrapperOutcome.ALLOW, findings

        if analysis.permission is AccessKeyPermission.UNKNOWN:
            # An unrecognised permission shape cannot be shown to fence anything.
            # Treating it as unrestricted and allowing the action would be the
            # "unrecognised structure treated as safe" defect, so it fails closed
            # to a review even on the Intents path, where a full-access key only
            # warns. It is at least as dangerous as full access.
            findings.append(
                _finding(
                    "ACCESS_KEY_PERMISSION_UNKNOWN",
                    WrapperSeverity.CRITICAL,
                    "Agent's access-key permission is not recognised",
                    "The key's permission shape is not FullAccess or FunctionCall, so its scope "
                    "cannot be established. It is treated as unrestricted, which is at least as "
                    "dangerous as a full-access key, and the action requires review.",
                )
            )
            return WrapperOutcome.REQUIRE_APPROVAL, findings

        if analysis.permission is AccessKeyPermission.FULL_ACCESS:
            findings.append(
                _finding(
                    "ACCESS_KEY_FULL_ACCESS",
                    WrapperSeverity.HIGH,
                    "Agent holds a full-access key",
                    "A full-access key can transfer NEAR, add keys and deploy contracts. An agent "
                    "must sign with a function-call key scoped to one contract.",
                )
            )
            # Full access does not by itself block; the guard still governs. But
            # it is a serious finding and it forces review.
            return WrapperOutcome.REQUIRE_APPROVAL, findings

        if not transaction.scope.native:
            # Intents path: the key is not what signs this action.
            return WrapperOutcome.ALLOW, findings

        allowed, reason = key_supports_operation(
            analysis,
            operation=transaction.operation,
            receiver_id=transaction.receiver_id or transaction.destination,
            method_name=transaction.method_name,
            transfers_near=transaction.transfers_near,
        )
        if allowed:
            return WrapperOutcome.ALLOW, findings

        findings.append(
            _finding(
                "ACCESS_KEY_SCOPE_REJECTED",
                WrapperSeverity.HIGH,
                "Operation is outside the access key's scope",
                reason,
                {
                    "operation": transaction.operation,
                    "receiver_id": analysis.receiver_id or "",
                },
            )
        )
        return WrapperOutcome.BLOCK, findings


#: Guard operation vocabulary mapped to the Intents policy action vocabulary.
#: The two systems name the same money movement differently; the mapping is
#: explicit so a new operation cannot silently fall through as "unlisted".
_OPERATION_TO_POLICY_ACTION = {
    "WITHDRAWAL": "withdraw",
    "WITHDRAW": "withdraw",
    "SETTLEMENT": "transfer",
    "TRANSFER": "transfer",
    "SWAP": "swap",
    "EXCHANGE": "swap",
}


def _policy_action_for(transaction: AgentTransaction) -> str:
    """The Intents policy action for a request, declared or derived."""
    if transaction.policy_action:
        return transaction.policy_action.strip().lower()
    return _OPERATION_TO_POLICY_ACTION.get(
        transaction.operation.strip().upper(), transaction.operation.strip().lower()
    )


def _outcome_from_guard(decision: Decision) -> WrapperOutcome:
    return {
        Decision.ALLOW: WrapperOutcome.ALLOW,
        Decision.REQUIRE_APPROVAL: WrapperOutcome.REQUIRE_APPROVAL,
        Decision.HOLD: WrapperOutcome.HOLD,
        Decision.BLOCK: WrapperOutcome.BLOCK,
    }[decision]


#: Counterparty outcome mapped to the wrapper outcome it requires. CLEAR adds
#: nothing; REVIEW asks for a human; BLOCK refuses; UNKNOWN fails safe.
_COUNTERPARTY_TO_WRAPPER = {
    CounterpartyOutcome.CLEAR: WrapperOutcome.ALLOW,
    CounterpartyOutcome.REVIEW: WrapperOutcome.REQUIRE_APPROVAL,
    CounterpartyOutcome.BLOCK: WrapperOutcome.BLOCK,
    CounterpartyOutcome.UNKNOWN: WrapperOutcome.UNKNOWN,
}

#: Counterparty signal severity mapped onto the wrapper's severity scale.
_CP_SEVERITY = {
    "INFO": WrapperSeverity.INFO,
    "LOW": WrapperSeverity.LOW,
    "MEDIUM": WrapperSeverity.MEDIUM,
    "HIGH": WrapperSeverity.HIGH,
    "CRITICAL": WrapperSeverity.CRITICAL,
}


def _evaluate_counterparty(
    read: CounterpartyRead | None,
) -> tuple[WrapperOutcome, list[WrapperFinding], list[str]]:
    """Fold counterparty risk intelligence into the wrapper outcome.

    Counterparty intelligence only ever *adds* restriction: a CLEAR read adds
    nothing, a REVIEW asks for a human, a BLOCK refuses, and an UNKNOWN (a signal
    that could not be read) fails safe. It never overrides a mandatory control
    downward, and with no read configured it is inert.
    """
    if read is None:
        return WrapperOutcome.ALLOW, [], []
    findings = [
        _finding(
            f"COUNTERPARTY_{f.code}",
            _CP_SEVERITY.get(f.severity.value, WrapperSeverity.MEDIUM),
            f.title,
            f.detail,
            dict(f.observed, source=f.source, method=f.method),
        )
        for f in read.findings
    ]
    limitations = list(read.limitations)
    if read.outcome is not CounterpartyOutcome.CLEAR:
        limitations.append(
            f"Counterparty intelligence for {read.account_id} resolved to "
            f"{read.outcome.value}."
        )
    return _COUNTERPARTY_TO_WRAPPER[read.outcome], findings, limitations


def _summarize(
    outcome: WrapperOutcome,
    transaction: AgentTransaction,
    findings: tuple[WrapperFinding, ...] | list[WrapperFinding],
) -> str:
    drivers = [f for f in findings if f.severity.rank >= WrapperSeverity.MEDIUM.rank]
    if not drivers:
        return (
            f"{outcome.value}: every applicable check passed for "
            f"{transaction.operation} {transaction.amount} {transaction.asset} to "
            f"{transaction.destination}."
        )
    worst = max(drivers, key=lambda f: f.severity.rank)
    return f"{outcome.value}: {worst.title} — {worst.detail}"
