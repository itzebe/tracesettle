"""A deterministic local agent harness: an instruction in, a decision out.

This is a **local test agent**, not a live AI integration. It turns a payment
instruction into a concrete NEAR transaction *proposal* using a deterministic
rule - no model, no network - and then drives that proposal through the
**production** authorization boundary
(:class:`~tracesettle.near.execution.NearExecutionBoundary`), which is the same
code path the console and the wallet flow use. It exists so the whole lifecycle

    agent instruction -> proposal -> TraceSettle evaluation -> decision ->
    signer enforcement -> broadcast -> independent settlement verification

can be reproduced from one command, and so the same path can be pointed at NEAR
testnet (``--live``) or run offline with a deterministic RPC.

Two scenarios are provided:

* **malicious** - the instruction is a legitimate invoice, but injected context
  redirects the payment to an attacker receiver. The planner (compromised)
  proposes the attacker's receiver; the real guard ``BLOCK``s it, the signer is
  never invoked, and nothing is broadcast.
* **legitimate** - the instruction pays the operator-approved receiver; the real
  guard ``ALLOW``s it, the signer signs exactly the authorized bytes, the
  transaction is broadcast, and settlement is independently verified.

The harness never invents a decision. It reports whatever the boundary returns,
and counts the signer's calls, so "the signer was never reached" is provable as
"the signer was called zero times" rather than as prose. An agent's own claim of
approval is never read: the guard evaluates the *proposal's parameters*.
"""

from __future__ import annotations

import dataclasses
from dataclasses import dataclass
from typing import Any, Protocol

from ..model import SourceStatus
from .execution import ExecutionError, NearExecutionBoundary, PreparedOperation
from .ledger import SubmissionLedger
from .networks import NETWORKS, NearNetwork
from .pipeline import NearExecutionPipeline, SigningError, TransactionSigner
from .rpc import RpcResult

#: The default agent identity. It must be a registered service in the operator
#: policy, or the guard refuses it (which is itself a demonstrated outcome).
DEFAULT_SERVICE_ID = "treasury-agent"


class Planner(Protocol):
    """Turns an instruction (and any injected context) into a proposal."""

    def __call__(
        self, instruction: "PaymentInstruction", injected: "InjectedContext | None"
    ) -> "Proposal": ...


@dataclass(frozen=True)
class PaymentInstruction:
    """What the agent was told to do. The ``text`` is untrusted; it is never
    evaluated. Only the resulting :class:`Proposal` reaches the boundary."""

    text: str
    receiver_id: str
    amount: str
    asset: str = "near:native"


@dataclass(frozen=True)
class InjectedContext:
    """A malicious instruction injected into the agent's context.

    It does not change what the boundary evaluates; it changes what the
    *compromised planner* proposes. The gap between the two is the whole point.
    """

    text: str
    receiver_id: str


@dataclass(frozen=True)
class Proposal:
    """The concrete transaction the agent's planner produced."""

    receiver_id: str
    amount: str
    asset: str
    redirected: bool = False


def default_planner(
    instruction: PaymentInstruction, injected: InjectedContext | None
) -> Proposal:
    """The deterministic planner used by the demonstration.

    With no injected context it proposes exactly what the instruction asked for.
    With injected context that names a different receiver it follows the
    injection - modelling a manipulated agent - so the proposal no longer matches
    the instruction. The boundary then judges the *proposal*, not the text.
    """
    if injected is not None and injected.receiver_id != instruction.receiver_id:
        return Proposal(
            receiver_id=injected.receiver_id,
            amount=instruction.amount,
            asset=instruction.asset,
            redirected=True,
        )
    return Proposal(
        receiver_id=instruction.receiver_id,
        amount=instruction.amount,
        asset=instruction.asset,
    )


class CountingSigner:
    """Wraps a signer and counts every ``sign`` call.

    This is how the harness proves "the signer was never reached": the count is
    zero. It delegates to the real signer unchanged, so a signature that is
    produced is a real signature.
    """

    def __init__(self, inner: TransactionSigner) -> None:
        self._inner = inner
        self.calls = 0

    @property
    def public_key(self) -> str:
        return self._inner.public_key

    def sign(self, message: bytes) -> bytes:
        self.calls += 1
        return self._inner.sign(message)


@dataclass
class HarnessResult:
    """The complete, reviewable outcome of one harness run."""

    scenario: str
    instruction: str
    injected_context: str
    proposed_receiver: str
    proposed_amount: str
    redirected: bool
    decision: str
    authorized: bool
    reasons: tuple[str, ...]
    signer_calls: int
    signed: bool
    broadcast_occurred: bool
    tx_hash: str
    submission_state: str
    settlement_state: str
    verification: dict[str, Any] | None
    notes: tuple[str, ...] = ()

    def to_dict(self) -> dict[str, Any]:
        return dataclasses.asdict(self)


def _proposal_reasons(prepared: PreparedOperation) -> tuple[str, ...]:
    """The human-readable reasons behind a decision, from the real findings."""
    findings = prepared.decision.findings or ()
    return tuple(f"{f.code}: {f.detail}" for f in findings)


class LocalAgentHarness:
    """Drive an agent's proposal through the production NEAR boundary.

    ``boundary`` is a real :class:`NearExecutionBoundary`; ``signer`` is the key
    holder (in the offline demonstration, a testnet
    :class:`~tracesettle.near.pipeline.LocalKeySigner`; in the live run, the same,
    pointed at a funded testnet account). The harness holds no key itself.
    """

    def __init__(
        self,
        boundary: NearExecutionBoundary,
        *,
        signer: TransactionSigner,
        service_id: str = DEFAULT_SERVICE_ID,
        account_id: str,
        pipeline: NearExecutionPipeline | None = None,
        planner: Planner = default_planner,
    ) -> None:
        self.boundary = boundary
        self.signer = CountingSigner(signer)
        self.service_id = service_id
        self.account_id = account_id
        self.pipeline = pipeline or NearExecutionPipeline(boundary, ledger=SubmissionLedger())
        self._planner = planner
        #: The most recent prepared operation, kept so an offline transport can
        #: rebuild the matching on-chain record for verification. Never a secret.
        self.last_prepared: PreparedOperation | None = None

    def run(
        self,
        instruction: PaymentInstruction,
        *,
        injected: InjectedContext | None = None,
        scenario: str = "legitimate",
        idempotency_key: str = "",
        attempts: int | None = None,
        delay: float | None = None,
    ) -> HarnessResult:
        """Run one instruction end to end and return the evidence."""
        before = self.signer.calls
        proposal = self._planner(instruction, injected)

        # The production boundary builds the *real* transaction and evaluates it.
        # A refusal here means nothing downstream may sign.
        try:
            prepared = self.boundary.prepare(
                service_id=self.service_id,
                account_id=self.account_id,
                public_key=self.signer.public_key,
                receiver_id=proposal.receiver_id,
                asset_identifier=proposal.asset,
                amount_human=proposal.amount,
            )
        except ExecutionError as exc:
            return HarnessResult(
                scenario=scenario,
                instruction=instruction.text,
                injected_context=injected.text if injected else "",
                proposed_receiver=proposal.receiver_id,
                proposed_amount=proposal.amount,
                redirected=proposal.redirected,
                decision="REFUSED_BEFORE_EVALUATION",
                authorized=False,
                reasons=(str(exc),),
                signer_calls=self.signer.calls - before,
                signed=False,
                broadcast_occurred=False,
                tx_hash="",
                submission_state="",
                settlement_state="",
                verification=None,
                notes=("the boundary refused before a transaction could be built",),
            )

        decision = prepared.decision.decision.value
        self.last_prepared = prepared
        if not prepared.authorized:
            # No authorization means nothing to sign. The pipeline is never
            # entered, so the signer count is provably unchanged.
            return HarnessResult(
                scenario=scenario,
                instruction=instruction.text,
                injected_context=injected.text if injected else "",
                proposed_receiver=proposal.receiver_id,
                proposed_amount=proposal.amount,
                redirected=proposal.redirected,
                decision=decision,
                authorized=False,
                reasons=_proposal_reasons(prepared),
                signer_calls=self.signer.calls - before,
                signed=False,
                broadcast_occurred=False,
                tx_hash=prepared.transaction.tx_hash,
                submission_state="",
                settlement_state="",
                verification=None,
                notes=("no authorization was issued, so the signer was never invoked",),
            )

        # Only an ALLOW with a bound authorization reaches here.
        try:
            result = self.pipeline.execute(
                prepared,
                self.signer,
                idempotency_key=idempotency_key,
                attempts=attempts,
                delay=delay,
            )
        except SigningError as exc:
            return HarnessResult(
                scenario=scenario,
                instruction=instruction.text,
                injected_context=injected.text if injected else "",
                proposed_receiver=proposal.receiver_id,
                proposed_amount=proposal.amount,
                redirected=proposal.redirected,
                decision=decision,
                authorized=True,
                reasons=_proposal_reasons(prepared),
                signer_calls=self.signer.calls - before,
                signed=False,
                broadcast_occurred=False,
                tx_hash=prepared.transaction.tx_hash,
                submission_state="",
                settlement_state="",
                verification=None,
                notes=(f"the signer refused: {exc}",),
            )

        return HarnessResult(
            scenario=scenario,
            instruction=instruction.text,
            injected_context=injected.text if injected else "",
            proposed_receiver=proposal.receiver_id,
            proposed_amount=proposal.amount,
            redirected=proposal.redirected,
            decision=decision,
            authorized=True,
            reasons=_proposal_reasons(prepared),
            signer_calls=self.signer.calls - before,
            signed=True,
            broadcast_occurred=bool(result.signed_b64),
            tx_hash=result.tx_hash,
            submission_state=result.state,
            settlement_state=result.settlement_state,
            verification=result.verification.to_dict() if result.verification else None,
            notes=(),
        )


# ---------------------------------------------------------------------------
# A deterministic offline RPC, so the harness runs with no network at all.
# ---------------------------------------------------------------------------


class OfflineNearRpc:
    """An in-memory NEAR RPC for the offline demonstration and tests.

    It mirrors :class:`~tracesettle.near.rpc.NearRpc` so the boundary calls it
    unchanged, and it records every submission in ``broadcasts`` so "nothing was
    broadcast" is asserted from the transport, never from prose. It is a
    *network* boundary: every line of ``execution.py`` and ``pipeline.py`` runs.

    ``record_provider`` returns the transaction the pipeline is currently
    processing (the caller's most recent prepared operation). ``broadcast_tx_commit``
    and ``tx`` then return the on-chain record for *that* transaction, exactly as
    the real node does, so the verifier reconciles real values rather than an
    empty object. The provider is optional; without it the transport returns an
    empty record and the verdict is honestly "insufficient evidence".
    """

    #: A fixed, valid testnet block hash so the built bytes are deterministic.
    BLOCK_HASH = "9Gq9bHtf6SKUuWLbzgPMVedA3BtYbYVwb5NVUrQyzoE9"

    def __init__(
        self,
        network: NearNetwork = NearNetwork.TESTNET,
        *,
        nonce: int = 42,
    ) -> None:
        self.config = NETWORKS[network]
        self.nonce = nonce
        self.broadcasts: list[str] = []
        self.access_key_permission: Any = "FullAccess"
        #: Returns the prepared operation currently being processed, or None.
        #: Set after construction so the harness can be wired in lazily.
        self.record_provider: Any = None

    def _record(self) -> dict[str, Any]:
        if self.record_provider is None:
            return {}
        prepared = self.record_provider()
        if prepared is None:
            return {}
        return offline_rpc_result_for(prepared.transaction)

    def status(self) -> RpcResult:
        return RpcResult(
            SourceStatus.OK,
            {"chain_id": self.config.chain_id, "genesis_hash": self.config.genesis_hash},
        )

    def block_hash(self, *, finality: str = "final") -> RpcResult:
        return RpcResult(SourceStatus.OK, {"hash": self.BLOCK_HASH, "height": 1})

    def view_access_key(self, account_id: str, public_key: str) -> RpcResult:
        return RpcResult(
            SourceStatus.OK,
            {"nonce": self.nonce, "permission": self.access_key_permission},
        )

    def call_function(
        self, account_id: str, method_name: str, args: Any = None, *, finality: str = "final"
    ) -> RpcResult:
        decimals = {"usdc.fakes.testnet": 6, "wrap.testnet": 24}.get(account_id, 24)
        return RpcResult(SourceStatus.OK, {"decimals": decimals})

    def send_tx(self, signed_transaction_b64: str, *, wait_until: str = "INCLUDED_FINAL") -> RpcResult:
        self.broadcasts.append(signed_transaction_b64)
        return RpcResult(SourceStatus.OK, self._record())

    def tx_status(self, tx_hash: str, sender_account_id: str) -> RpcResult:
        record = self._record()
        if record and str(record.get("transaction", {}).get("hash", "")) != tx_hash:
            # A hash we do not know: report it as absent rather than fabricate.
            return RpcResult(SourceStatus.NOT_FOUND, None, error="unknown transaction")
        return RpcResult(SourceStatus.OK, record)


def offline_rpc_result_for(tx: Any) -> dict[str, Any]:
    """Build an RPC ``tx`` result that matches a built transaction.

    Used to drive the offline verification path to a real verdict; the shape is
    the documented NEAR ``tx`` result, not an invention.
    """
    return {
        "final_execution_status": "FINAL",
        "status": {"SuccessValue": ""},
        "transaction": {
            "hash": tx.tx_hash,
            "signer_id": tx.signer_id,
            "receiver_id": tx.receiver_id,
            "nonce": tx.nonce,
            "actions": [{"Transfer": {"deposit": str(tx.amount_base)}}]
            if tx.operation == "TRANSFER"
            else [],
        },
        "transaction_outcome": {"block_hash": OfflineNearRpc.BLOCK_HASH, "outcome": {"logs": []}},
        "receipts_outcome": [],
    }


__all__ = [
    "CountingSigner",
    "DEFAULT_SERVICE_ID",
    "HarnessResult",
    "InjectedContext",
    "LocalAgentHarness",
    "OfflineNearRpc",
    "PaymentInstruction",
    "Proposal",
    "default_planner",
    "offline_rpc_result_for",
]
