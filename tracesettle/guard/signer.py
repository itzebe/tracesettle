"""The reference signer: the enforcement point that fails closed.

A signer that consults TraceSettle must do exactly one thing before it signs:
ask this module to validate the authorization against the *actual* transaction
it has been asked to sign. If validation is not exactly ``VALID``, the signer
refuses and no execution happens.

There is no "trusted caller" path, no client-supplied approval, and no
configuration that turns a refusal into an execution. The only way to reach the
executor is a token that was signed by the guard key, names the same service,
matches the transaction parameters exactly, is inside its validity window, and
has never been used before.

Scope honesty
-------------
TraceSettle cannot block an arbitrary blockchain transaction. This signer is a
*reference* integration: a working demonstration that a transaction cannot reach
the signing step without a valid authorization. It does not hold keys and does
not broadcast to any chain. :class:`SimulatedExecutor` records the transaction
it was asked to execute and is always labelled as simulated.
"""

from __future__ import annotations

import threading
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any, Protocol

from .authorization import AuthorizationAuthority, AuthVerification
from .model import (
    AuthState,
    RequestFingerprint,
    SignOutcome,
    SignResult,
    TransactionRequest,
    canonical_fields,
    fingerprint_of,
)


def _utc_now() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


@dataclass(frozen=True)
class ExecutionReceipt:
    """A record of what the executor was asked to do, and whether it did it."""

    execution_id: str
    executed_at: str
    service_id: str
    operation: str
    chain: str
    asset: str
    amount: str
    destination: str
    authorization_id: str | None
    simulated: bool = True
    note: str = ""

    def to_dict(self) -> dict[str, Any]:
        return {
            "execution_id": self.execution_id,
            "executed_at": self.executed_at,
            "service_id": self.service_id,
            "operation": self.operation,
            "chain": self.chain,
            "asset": self.asset,
            "amount": self.amount,
            "destination": self.destination,
            "authorization_id": self.authorization_id,
            "simulated": self.simulated,
            "note": self.note,
        }


class Executor(Protocol):
    """The thing that would actually submit a transaction.

    A production deployment replaces :class:`SimulatedExecutor` with a real
    signer/relayer. The reference signer's refusal logic does not change: a real
    executor is only ever reached through the same validated path.
    """

    def execute(self, request: TransactionRequest, authorization_id: str | None) -> ExecutionReceipt: ...


class SimulatedExecutor:
    """Records the transaction it is asked to execute. Never touches a chain.

    This is the only executor shipped. It exists so the enforcement path can be
    demonstrated end to end without holding funds or keys. Every receipt it
    returns is marked ``simulated=True`` and is never presented as a real
    blockchain transaction.
    """

    def __init__(self) -> None:
        self._lock = threading.Lock()
        self._counter = 0
        self._receipts: list[ExecutionReceipt] = []

    def execute(self, request: TransactionRequest, authorization_id: str | None) -> ExecutionReceipt:
        with self._lock:
            self._counter += 1
            receipt = ExecutionReceipt(
                execution_id=f"exec_{self._counter:06d}",
                executed_at=_utc_now(),
                service_id=request.service_id,
                operation=request.operation.strip().upper(),
                chain=request.chain.strip().lower(),
                asset=request.asset.strip().upper(),
                amount=request.amount_raw,
                destination=request.destination,
                authorization_id=authorization_id,
                simulated=True,
                note=(
                    "Simulated execution: TraceSettle holds no keys and broadcasts to no chain. "
                    "This receipt records that the authorization boundary was passed, nothing more."
                ),
            )
            self._receipts.append(receipt)
            return receipt

    def receipts(self) -> tuple[ExecutionReceipt, ...]:
        with self._lock:
            return tuple(self._receipts)


@dataclass(frozen=True)
class SignRequest:
    """What a calling application asks the signer to sign.

    ``authorization`` is the token the guard issued. The remaining fields are the
    transaction the caller wants signed, *independently of* the token: the signer
    compares the two, so a caller cannot reuse a token for a different transfer.
    """

    transaction: TransactionRequest
    authorization: Any = None
    expected_service_id: str | None = None
    metadata: dict[str, Any] = field(default_factory=dict)


class ReferenceSigner:
    """Validates the authorization, then either executes or refuses. Never both."""

    def __init__(
        self,
        authority: AuthorizationAuthority,
        executor: Executor | None = None,
        *,
        on_outcome: "callable[[SignResult], None] | None" = None,
    ) -> None:
        self._authority = authority
        self._executor = executor or SimulatedExecutor()
        self._on_outcome = on_outcome

    @property
    def executor(self) -> Executor:
        return self._executor

    def sign(self, request: SignRequest) -> SignResult:
        """Validate the authorization for this transaction and act on the result.

        The refusal path returns before the executor is consulted, so a refused
        transaction provably cannot reach execution.
        """
        expected = canonical_fields(
            service_id=request.transaction.service_id,
            operation=request.transaction.operation,
            chain=request.transaction.chain,
            asset=request.transaction.asset,
            amount=request.transaction.amount,
            destination=request.transaction.destination,
        )
        verification = self._authority.validate(
            request.authorization,
            expected=expected,
            consume=True,
            expected_service_id=request.expected_service_id,
        )

        if not verification.valid:
            result = SignResult(
                outcome=SignOutcome.REFUSED,
                state=verification.state,
                detail=verification.detail,
                authorization_id=verification.authorization_id,
                service_id=verification.service_id or request.transaction.service_id,
                request_id=request.transaction.request_id,
                simulated=False,
            )
            self._notify(result)
            return result

        receipt = self._executor.execute(request.transaction, verification.authorization_id)
        result = SignResult(
            outcome=SignOutcome.EXECUTED,
            state=AuthState.VALID,
            detail="authorization validated; the simulated executor recorded the transaction",
            authorization_id=verification.authorization_id,
            service_id=verification.service_id or request.transaction.service_id,
            request_id=request.transaction.request_id,
            simulated=receipt.simulated,
            receipt=receipt.to_dict(),
        )
        self._notify(result)
        return result

    def _notify(self, result: SignResult) -> None:
        if self._on_outcome is not None:
            self._on_outcome(result)

    def verify_only(self, request: SignRequest) -> AuthVerification:
        """Validate without consuming the nonce or executing.

        Used by a caller that wants to check a token up front. It is deliberately
        non-consuming: only :meth:`sign` spends the token, so a pre-check cannot
        be used to burn a token an attacker cannot otherwise use.
        """
        expected = fingerprint_of(
            canonical_fields(
                service_id=request.transaction.service_id,
                operation=request.transaction.operation,
                chain=request.transaction.chain,
                asset=request.transaction.asset,
                amount=request.transaction.amount,
                destination=request.transaction.destination,
            )
        )
        return self._authority.validate(
            request.authorization,
            expected=expected,
            consume=False,
            expected_service_id=request.expected_service_id,
        )


def fingerprint_of_request(request: TransactionRequest) -> RequestFingerprint:
    return fingerprint_of(
        canonical_fields(
            service_id=request.service_id,
            operation=request.operation,
            chain=request.chain,
            asset=request.asset,
            amount=request.amount,
            destination=request.destination,
        )
    )