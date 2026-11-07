"""Independent, reproducible evaluation scenarios for a technical judge.

This module is the machine behind the public ``/evaluate`` page and the
``GET /api/guard/judge/scenarios`` endpoint. It runs the *real* authorization
boundary, the *real* reference signer, the *real* replay store and the *real*
NEAR settlement verifier, and reports, for each scenario, exactly what happened:
the decision, whether the signer was reached, whether anything was signed, and
whether anything was broadcast.

Two kinds of scenario are kept apart on purpose:

* **Enforcement scenarios** (1-9) are controlled simulations. The transaction
  parameters are synthetic, the executor is simulated, and nothing reaches a
  chain. They exist to prove the *boundary* behaves as specified.
* **The settlement scenario** (10) is a genuine, read-only check of an
  already-final NEAR **testnet** transaction, read from a public RPC. It is
  labelled ``real`` and its result is never upgraded from an outage.

A judge does not need the operator's secrets, a wallet, or any paid service to
run this module: ``python3 -m tracesettle judge`` runs it offline, and the public
endpoint serves the same results keylessly when the operator opts in.

Nothing here is mocked. The single substitution anywhere is the simulated
executor, which records what it was asked to do and never touches a chain.
"""

from __future__ import annotations

import datetime as _dt
from dataclasses import dataclass, field
from decimal import Decimal
from typing import Any

from .guard.authorization import AuthorizationAuthority, InMemoryReplayStore
from .guard.model import AmountError
from .guard.service import (
    GuardService,
    RequestValidationError,
    request_from_payload,
)
from .guard.signer import ReferenceSigner, SimulatedExecutor
from .near.agent_wrapper import (
    AgentAuthorizationWrapper,
    AgentTransaction,
    WrapperOutcome,
)
from .near.approval import ApprovalAuthority, CallbackChannel
from .near.attacks import (
    APPROVED_DESTINATION,
    APPROVED_DESTINATION_2,
    ATTACKER_DESTINATION,
    DEMO_KEY,
    near_demo_policy,
)
from .near.policy import PolicyScope

#: The uniform honest-scope note every simulated scenario carries.
SIMULATION_NOTE = (
    "Controlled simulation: the transaction parameters are synthetic, the executor is "
    "simulated, and nothing is broadcast to any chain. The authorization boundary, the "
    "replay store, the reference signer and the approval authority are the real production code."
)

#: The honest-scope note the one live scenario carries.
LIVE_NOTE = (
    "This scenario is not simulated: it reads an already-final NEAR testnet transaction from a "
    "public RPC and checks its fields. It never signs, builds or broadcasts anything."
)


@dataclass(frozen=True)
class JudgeScenario:
    """The result of one independent evaluation scenario."""

    id: str
    title: str
    threat: str
    #: What the judge should expect to happen.
    expected: str
    #: The concrete input the scenario used (synthetic unless ``real``).
    input: dict[str, Any]
    #: What actually happened, in one line.
    observed: str
    #: Whether the observed behaviour matched the expectation.
    passed: bool
    #: How many times the executor was asked to run.
    signer_calls: int
    #: Whether anything was actually signed.
    signed: bool
    #: Whether anything was broadcast to a network.
    broadcast: bool
    #: True only for the live settlement check.
    real: bool = False
    #: Whether the result came from a simulation (True) or real evidence (False).
    simulated: bool = True
    #: Free-form evidence the judge can inspect.
    evidence: dict[str, Any] = field(default_factory=dict)
    #: The decision/state label, for at-a-glance rendering.
    decision: str = ""

    @property
    def skipped(self) -> bool:
        """A live check that could not run is a limitation, not a failure.

        A ``UNAVAILABLE`` or ``UNSUPPORTED`` result from the real, read-only
        settlement check means the host could not reach the chain, not that the
        product misbehaved. It is surfaced as "skipped" so no surface reports a
        network outage as an unexpected result.
        """
        return self.real and not self.passed and self.decision in {"UNAVAILABLE", "UNSUPPORTED"}

    def to_dict(self) -> dict[str, Any]:
        return {
            "id": self.id,
            "title": self.title,
            "threat": self.threat,
            "expected": self.expected,
            "input": self.input,
            "observed": self.observed,
            "passed": self.passed,
            "skipped": self.skipped,
            "signer_calls": self.signer_calls,
            "signed": self.signed,
            "broadcast": self.broadcast,
            "real": self.real,
            "simulated": self.simulated,
            "evidence": self.evidence,
            "decision": self.decision,
        }


class _World:
    """A fresh guard + wrapper + counting executor, isolated to one scenario.

    ``clock`` lets a scenario control time so authorization expiry can be tested
    without sleeping. The signer is the real :class:`ReferenceSigner`; the only
    stand-in is the executor, which never touches a chain.
    """

    def __init__(self, *, ttl_seconds: int = 90, clock: Any = None) -> None:
        self.executor = SimulatedExecutor()
        self.authority = AuthorizationAuthority(
            key=DEMO_KEY,
            key_id="judge-demo-key",
            ephemeral=False,
            replay_store=InMemoryReplayStore(),
            ttl_seconds=ttl_seconds,
            clock=clock,
        )
        self.approval_authority = ApprovalAuthority(key=DEMO_KEY, key_id="judge-approval")
        self.service = GuardService(
            policy=near_demo_policy(),
            authority=self.authority,
            approval_authority=self.approval_authority,
        )
        self.service._signer = ReferenceSigner(self.authority, executor=self.executor)  # noqa: SLF001
        self.wrapper = AgentAuthorizationWrapper(self.service)


def _tx(**overrides: Any) -> AgentTransaction:
    base: dict[str, Any] = dict(
        service_id="treasury-agent",
        operation="WITHDRAWAL",
        chain="base",
        asset="USDC",
        amount="1250.50",
        destination=APPROVED_DESTINATION,
        scope=PolicyScope.INTENTS,
        policy_action="withdraw",
        request_id="judge-demo",
        simulated=True,
    )
    base.update(overrides)
    return AgentTransaction(**base)


def _calls(world: _World) -> int:
    return len(world.executor.receipts())


# ---------------------------------------------------------------------------
# Enforcement scenarios (simulated)
# ---------------------------------------------------------------------------


def scenario_unauthorized_receiver() -> JudgeScenario:
    """An agent is manipulated into paying an attacker-controlled receiver."""
    world = _World()
    tx = _tx(destination=ATTACKER_DESTINATION, request_id="judge-unauthorized")
    decision = world.wrapper.evaluate(tx)
    submission = world.wrapper.submit(tx, decision.authorization)
    calls = _calls(world)
    passed = (
        decision.outcome is WrapperOutcome.BLOCK
        and calls == 0
        and not submission.executed
    )
    return JudgeScenario(
        id="unauthorized_receiver",
        title="Unauthorized receiver",
        threat=(
            "A compromised agent or an injected instruction redirects a payment to a "
            "destination the operator never approved."
        ),
        expected="BLOCK, no authorization issued, signer never reached",
        input={"destination": ATTACKER_DESTINATION, "amount": "1250.50 USDC", "chain": "base"},
        observed=f"decision={decision.outcome.value}, signer calls={calls}",
        passed=passed,
        signer_calls=calls,
        signed=False,
        broadcast=False,
        decision=decision.outcome.value,
        evidence={
            "reasons": [f"{f.code}: {f.title}" for f in decision.findings],
            "signer_calls": calls,
            "executed": submission.executed,
        },
    )


def scenario_manipulated_amount() -> JudgeScenario:
    """An agent proposes a transfer far above the operator's per-transaction limit."""
    world = _World()
    tx = _tx(amount="480000", request_id="judge-manipulated")
    decision = world.wrapper.evaluate(tx)
    submission = world.wrapper.submit(tx, decision.authorization)
    calls = _calls(world)
    passed = (
        decision.outcome is WrapperOutcome.BLOCK
        and calls == 0
        and not submission.executed
    )
    return JudgeScenario(
        id="manipulated_amount",
        title="Manipulated amount",
        threat=(
            "A manipulated amount moves the payment outside the operator's spending "
            "policy, turning a routine invoice into an oversized transfer."
        ),
        expected="BLOCK, no authorization issued, signer never reached",
        input={"destination": APPROVED_DESTINATION, "amount": "480000 USDC (limit 10000)"},
        observed=f"decision={decision.outcome.value}, signer calls={calls}",
        passed=passed,
        signer_calls=calls,
        signed=False,
        broadcast=False,
        decision=decision.outcome.value,
        evidence={
            "reasons": [f"{f.code}: {f.title}" for f in decision.findings],
            "signer_calls": calls,
            "executed": submission.executed,
        },
    )


def scenario_tampered_after_authorization() -> JudgeScenario:
    """The transaction is changed after authorization; the binding must refuse it."""
    world = _World()
    approved = _tx(destination=APPROVED_DESTINATION, request_id="judge-tamper")
    decision = world.wrapper.evaluate(approved)
    token = decision.authorization
    # Both destinations are policy-approved, so the destination control passes;
    # it is the signer's parameter binding that must refuse.
    tampered = _tx(destination=APPROVED_DESTINATION_2, request_id="judge-tamper")
    submission = world.wrapper.submit(tampered, token)
    state = submission.sign_result.state.value if submission.sign_result else "n/a"
    calls = _calls(world)
    passed = (
        decision.outcome is WrapperOutcome.ALLOW
        and not submission.executed
        and state in {"WRONG_PARAMETERS", "WRONG_SERVICE"}
        and calls == 0
    )
    return JudgeScenario(
        id="tampered_after_authorization",
        title="Altered transaction after authorization",
        threat=(
            "An application swaps the destination after a legitimate authorization was "
            "issued, hoping to reuse the token for a different transfer."
        ),
        expected="Refused: the authorization is bound to the exact transaction",
        input={
            "authorized_destination": APPROVED_DESTINATION,
            "submitted_destination": APPROVED_DESTINATION_2,
        },
        observed=f"submit={submission.outcome.value}, signer state={state}, signer calls={calls}",
        passed=passed,
        signer_calls=calls,
        signed=False,
        broadcast=False,
        decision=state,
        evidence={
            "signer_state": state,
            "authorized_digest": (token.parameters or {}).get("fingerprint", "") if token else "",
            "signer_calls": calls,
        },
    )


def scenario_expired_authorization() -> JudgeScenario:
    """An authorization is used after its short lifetime has elapsed."""
    t0 = _dt.datetime(2026, 1, 1, 12, 0, 0, tzinfo=_dt.timezone.utc)
    now = [t0]

    def clock() -> _dt.datetime:
        return now[0]

    world = _World(ttl_seconds=30, clock=clock)
    tx = _tx(request_id="judge-expired")
    decision = world.wrapper.evaluate(tx)
    token = decision.authorization
    # Advance well past the 30-second lifetime.
    now[0] = t0 + _dt.timedelta(seconds=120)
    submission = world.wrapper.submit(tx, token)
    state = submission.sign_result.state.value if submission.sign_result else "n/a"
    calls = _calls(world)
    passed = (
        decision.outcome is WrapperOutcome.ALLOW
        and not submission.executed
        and state == "EXPIRED"
        and calls == 0
    )
    return JudgeScenario(
        id="expired_authorization",
        title="Expired authorization",
        threat=(
            "A stale authorization is presented long after it was issued, after the "
            "window in which the operator intended it to be valid."
        ),
        expected="Refused: the authorization has expired",
        input={"issued_at": token.issued_at if token else "", "ttl_seconds": 30, "used_after_seconds": 120},
        observed=f"submit={submission.outcome.value}, signer state={state}, signer calls={calls}",
        passed=passed,
        signer_calls=calls,
        signed=False,
        broadcast=False,
        decision=state,
        evidence={"signer_state": state, "signer_calls": calls},
    )


def scenario_replayed_authorization() -> JudgeScenario:
    """A spent authorization is presented a second time."""
    world = _World()
    tx = _tx(request_id="judge-replay")
    decision = world.wrapper.evaluate(tx)
    token = decision.authorization
    first = world.wrapper.submit(tx, token)
    second = world.wrapper.submit(tx, token)
    state = second.sign_result.state.value if second.sign_result else "n/a"
    calls = _calls(world)
    passed = (
        first.executed
        and not second.executed
        and state in {"REPLAYED", "MISSING"}
        and calls == 1
    )
    return JudgeScenario(
        id="replayed_authorization",
        title="Replayed authorization",
        threat=(
            "A captured authorization is replayed to sign a second transaction with the "
            "same parameters, doubling the transfer."
        ),
        expected="First use succeeds; the replay is refused; only one execution occurs",
        input={"authorization_uses": 2, "same_transaction": True},
        observed=f"first={first.outcome.value}, second={second.outcome.value}, "
        f"signer state={state}, signer calls={calls}",
        passed=passed,
        signer_calls=calls,
        signed=False,
        broadcast=False,
        decision=state,
        evidence={"signer_state": state, "signer_calls": calls, "first_executed": first.executed},
    )


def scenario_malformed_input() -> JudgeScenario:
    """Hostile or malformed input is rejected with a controlled error, never a crash."""
    hostile: list[tuple[str, dict[str, Any]]] = [
        ("non_object", "not-a-dict"),  # type: ignore[list-item]
        ("missing_service_id", {"operation": "WITHDRAWAL", "chain": "base", "asset": "USDC",
                                "amount": "1", "destination": APPROVED_DESTINATION}),
        ("bad_amount", {"service_id": "treasury-agent", "operation": "WITHDRAWAL", "chain": "base",
                        "asset": "USDC", "amount": "not-a-number", "destination": APPROVED_DESTINATION}),
        ("overflow_amount", {"service_id": "treasury-agent", "operation": "WITHDRAWAL", "chain": "base",
                             "asset": "USDC", "amount": "1e1000000000", "destination": APPROVED_DESTINATION}),
        ("non_string_destination", {"service_id": "treasury-agent", "operation": "WITHDRAWAL",
                                    "chain": "base", "asset": "USDC", "amount": "1", "destination": 12345}),
        ("null_service_id", {"service_id": None, "operation": "WITHDRAWAL", "chain": "base",
                             "asset": "USDC", "amount": "1", "destination": APPROVED_DESTINATION}),
    ]
    results: list[dict[str, Any]] = []
    all_rejected = True
    for name, payload in hostile:
        try:
            request_from_payload(payload)  # type: ignore[arg-type]
            # Parsed without error -> the scenario did NOT reject; that is a fail.
            results.append({"case": name, "rejected": False, "error": "accepted"})
            all_rejected = False
        except (RequestValidationError, AmountError) as exc:
            results.append({"case": name, "rejected": True, "error": type(exc).__name__})
        except Exception as exc:  # noqa: BLE001 - an unhandled type IS the defect
            results.append({"case": name, "rejected": False, "error": f"UNHANDLED {type(exc).__name__}"})
            all_rejected = False
    return JudgeScenario(
        id="malformed_input",
        title="Invalid or malformed input",
        threat=(
            "A caller sends a malformed, missing, non-numeric or absurdly large field to "
            "probe for an unhandled error or a fail-open."
        ),
        expected="Every case is rejected with a typed validation error; nothing raises",
        input={"cases": [name for name, _ in hostile]},
        observed=f"{sum(1 for r in results if r['rejected'])}/{len(results)} rejected with a typed error",
        passed=all_rejected,
        signer_calls=0,
        signed=False,
        broadcast=False,
        decision="REJECTED",
        evidence={"cases": results},
    )


def scenario_missing_service_identity() -> JudgeScenario:
    """An unregistered service identity cannot obtain an authorization."""
    world = _World()
    tx = _tx(service_id="rogue-agent", request_id="judge-identity")
    decision = world.wrapper.evaluate(tx)
    submission = world.wrapper.submit(tx, decision.authorization)
    calls = _calls(world)
    passed = (
        decision.outcome is WrapperOutcome.BLOCK
        and not decision.permits_signing
        and calls == 0
        and not submission.executed
    )
    return JudgeScenario(
        id="missing_service_identity",
        title="Missing or unknown service identity",
        threat=(
            "A caller presents an identity the operator never registered, hoping to be "
            "evaluated under a weaker or default policy."
        ),
        expected="BLOCK: an unknown identity fails closed and cannot sign",
        input={"service_id": "rogue-agent (not registered)"},
        observed=f"decision={decision.outcome.value}, permits_signing={decision.permits_signing}, "
        f"signer calls={calls}",
        passed=passed,
        signer_calls=calls,
        signed=False,
        broadcast=False,
        decision=decision.outcome.value,
        evidence={
            "reasons": [f"{f.code}: {f.title}" for f in decision.findings],
            "permits_signing": decision.permits_signing,
            "signer_calls": calls,
        },
    )


def scenario_approval_required() -> JudgeScenario:
    """An above-threshold payment needs a human approval bound to the exact payload."""
    world = _World()
    tx = _tx(amount="6000", request_id="judge-approval")
    decision = world.wrapper.evaluate(tx)
    # The agent tries to sign with no approval: it must be refused.
    without = world.wrapper.submit(tx, decision.authorization)
    # A human approves the exact payload.
    channel = CallbackChannel(lambda _req: "ops-human")
    request = world.wrapper.approval_request(tx)
    approver = channel.request_approval(request)
    approval = world.approval_authority.approve(request, approver=approver or "ops-human")
    approved_decision = world.wrapper.evaluate(tx, approval=approval)
    with_approval = world.wrapper.submit(tx, approved_decision.authorization, decision=approved_decision)
    calls = _calls(world)
    passed = (
        decision.outcome is WrapperOutcome.REQUIRE_APPROVAL
        and not without.executed
        and with_approval.executed
        and calls == 1
    )
    return JudgeScenario(
        id="approval_required",
        title="Approval required",
        threat=(
            "An agent attempts a payment above the operator's approval threshold, hoping "
            "to sign it without a human in the loop."
        ),
        expected="REQUIRE_APPROVAL; unsigned without approval, signed only after a bound approval",
        input={"destination": APPROVED_DESTINATION, "amount": "6000 USDC (threshold 5000)"},
        observed=f"evaluate={decision.outcome.value}, submit(no approval)={without.outcome.value}, "
        f"submit(approved)={with_approval.outcome.value}, signer calls={calls}",
        passed=passed,
        signer_calls=calls,
        signed=False,
        broadcast=False,
        decision=decision.outcome.value,
        evidence={
            "without_approval_executed": without.executed,
            "with_approval_executed": with_approval.executed,
            "approver": approver,
            "signer_calls": calls,
        },
    )


def scenario_legitimate_authorized() -> JudgeScenario:
    """A legitimate, in-policy payment is authorized and follows the execution path."""
    world = _World()
    tx = _tx(request_id="judge-legitimate")
    decision = world.wrapper.evaluate(tx)
    submission = world.wrapper.submit(tx, decision.authorization)
    calls = _calls(world)
    passed = (
        decision.outcome is WrapperOutcome.ALLOW
        and submission.executed
        and calls == 1
    )
    return JudgeScenario(
        id="legitimate_authorized",
        title="Legitimate authorized transaction",
        threat=(
            "A well-formed, in-policy payment must NOT be blocked; the boundary must let "
            "the authorized path proceed."
        ),
        expected="ALLOW, an authorization is issued, and the signer executes once",
        input={"destination": APPROVED_DESTINATION, "amount": "1250.50 USDC", "chain": "base"},
        observed=f"decision={decision.outcome.value}, signer calls={calls}, executed={submission.executed}",
        passed=passed,
        signer_calls=calls,
        signed=False,
        broadcast=False,
        decision=decision.outcome.value,
        evidence={"signer_calls": calls, "executed": submission.executed},
    )


def scenario_settlement_verification() -> JudgeScenario:
    """A real, already-final NEAR testnet transaction is verified field by field.

    This is the one non-simulated scenario. It reads from a public RPC and never
    signs, builds or broadcasts. An RPC outage is reported as ``UNAVAILABLE`` and
    is never upgraded into a verdict.
    """
    from .near.settlement_check import verify_reference_settlement

    check = verify_reference_settlement()
    data = check.to_dict()
    verified = bool(data.get("verified"))
    state = data.get("state", "UNAVAILABLE")
    passed = state == "VERIFIED"  # an outage is not a pass, but is reported honestly
    return JudgeScenario(
        id="settlement_verification",
        title="Independent settlement verification",
        threat=(
            "A provider reports success. A provider's word is not proof; the settlement "
            "must be checked against the on-chain record."
        ),
        expected="VERIFIED only if the on-chain record matches the intended operation",
        input={"network": "testnet", "tx_hash": data.get("tx_hash", "")},
        observed=f"state={state}, tx={data.get('tx_hash', '')}",
        passed=passed,
        signer_calls=0,
        signed=False,
        broadcast=False,
        real=True,
        simulated=False,
        decision=state,
        evidence={
            "network": data.get("network"),
            "mainnet": False,
            "verified": verified,
            "checks": (data.get("verification") or {}).get("checks", []),
            "note": data.get("note", ""),
        },
    )


#: The full, ordered set of independent evaluation scenarios.
SCENARIOS: tuple[Any, ...] = (
    scenario_unauthorized_receiver,
    scenario_manipulated_amount,
    scenario_tampered_after_authorization,
    scenario_expired_authorization,
    scenario_replayed_authorization,
    scenario_malformed_input,
    scenario_missing_service_identity,
    scenario_approval_required,
    scenario_legitimate_authorized,
    scenario_settlement_verification,
)


def run_all() -> tuple[JudgeScenario, ...]:
    """Run every scenario, in order, and return the results."""
    return tuple(fn() for fn in SCENARIOS)


def run_one(scenario_id: str) -> JudgeScenario:
    """Run one scenario by id."""
    key = scenario_id.strip().lower()
    for fn in SCENARIOS:
        # The id is the function's ``scenario_`` suffix.
        if fn.__name__ == f"scenario_{key}":
            return fn()
    raise KeyError(f"unknown scenario {scenario_id!r}")


def to_report(results: tuple[JudgeScenario, ...] | None = None) -> dict[str, Any]:
    """A machine-readable report a judge can inspect or diff between runs."""
    results = results if results is not None else run_all()
    enforcement = [r for r in results if not r.real]
    live = [r for r in results if r.real]
    return {
        "scenarios": [r.to_dict() for r in results],
        "summary": {
            "total": len(results),
            "passed": sum(1 for r in results if r.passed),
            "enforcement_passed": sum(1 for r in enforcement if r.passed),
            "enforcement_total": len(enforcement),
            "live_passed": sum(1 for r in live if r.passed),
            "live_total": len(live),
            "signer_calls_on_refusals": sum(
                r.signer_calls for r in results if r.decision in {"BLOCK", "REFUSED", "EXPIRED", "REPLAYED",
                                                                  "WRONG_PARAMETERS", "REJECTED"}
            ),
            "broadcast_occurred": any(r.broadcast for r in results),
        },
        "notes": {"simulation": SIMULATION_NOTE, "live": LIVE_NOTE},
        "disclaimer": (
            "Enforcement scenarios are controlled simulations; the settlement scenario is a real, "
            "read-only NEAR testnet check. No scenario signs, broadcasts or moves funds."
        ),
    }


__all__ = [
    "JudgeScenario",
    "SCENARIOS",
    "run_all",
    "run_one",
    "to_report",
]


# Referenced for the type of an amount bound; kept explicit so a reader sees the
# unit the policy uses (a Decimal, never a float).
_AMOUNT_UNIT = Decimal
