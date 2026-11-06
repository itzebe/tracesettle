"""The OutLayer custody execution boundary.

This is the only supported path from an intended operation to a transaction
signed by a TEE-held wallet key. It is a *superset* of
:mod:`tracesettle.near.execution` for the custody case: the guard still decides,
but the signature is produced by OutLayer's enclave rather than by a caller's
wallet, so the boundary must additionally bind the authorization to the exact
operation it sends and independently verify the result.

The order is fixed and any failure refuses:

1. resolve the provider and the wallet identity **server-side**;
2. build the transaction request (validated recipient and amount);
3. evaluate it with the guard, using the *operator's* policy;
4. if, and only if, the outcome is ALLOW, issue a transaction-bound
   authorization whose digest commits to the exact operation;
5. send that exact operation to OutLayer, with an idempotency key derived from
   the same digest;
6. poll the provider request to a terminal state (never resubmitting an
   operation whose outcome is unknown);
7. independently verify settlement against the authorized transaction through
   the NEAR RPC - a provider ``status == "success"`` is a *claim*, not proof.

An operation that is BLOCK, HOLD, REQUIRE_APPROVAL or otherwise not authorized
never reaches :meth:`CustodyExecution.execute`; the executor is simply not
called. That is what the regression tests assert.

The boundary holds no key. It never stores, logs or transmits a private key or
seed phrase; the provider's API key lives only in the server-side config and is
never placed in a response.
"""

from __future__ import annotations

import hashlib
import json
import time
from dataclasses import dataclass, field
from decimal import Decimal
from typing import Any

from ..guard.model import (
    Decision,
    GuardDecision,
    TransactionRequest,
    canonical_fields,
    fingerprint_of,
    parse_amount,
)
from ..guard.service import GuardService
from ..model import SourceStatus
from .networks import NearNetwork
from .outlayer import (
    ProviderOutcome,
    OutLayerCustodyProvider,
    OutLayerError,
    YOCTO_PER_NEAR,
    idempotency_key_for,
    is_in_flight,
    is_terminal,
)
from .rpc import NearRpc
from .verify import Check, SettlementState, SettlementVerification

#: The guard operation and chain this boundary uses. ``WITHDRAWAL`` is the native
#: value-transfer operation the existing policy engine already understands (the
#: same value :func:`tracesettle.near.txbuild.build_transfer` defaults to), and
#: ``NEAR:NATIVE`` is the native asset identifier the policy already authorises.
CUSTODY_OPERATION = "WITHDRAWAL"
CUSTODY_ASSET = "NEAR:NATIVE"

#: The provider account is a NEAR implicit account: a 64-hex string. The account
#: id and the wallet's public key must agree, which is what binds the TEE-held
#: key to the on-chain signer.
_IMPLICIT_RE = r"^[0-9a-f]{64}$"


class CustodyError(ValueError):
    """A refusal on the custody execution path."""


def _implicit_account(public_key: str) -> str:
    """The NEAR implicit account id for an ``ed25519:<base58>`` public key."""
    if not public_key.startswith("ed25519:"):
        raise CustodyError("the wallet public key is not an ed25519 key")
    b58 = public_key.split(":", 1)[1]
    # base58-decode without a dependency
    alphabet = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz"
    n = 0
    for ch in b58:
        n = n * 58 + alphabet.index(ch)
    raw = n.to_bytes(32, "big")
    return raw.hex()


def _to_yocto(amount: Decimal) -> int:
    """Convert whole NEAR to yoctoNEAR exactly, refusing sub-yocto precision.

    Extracted and unit-tested directly because ``parse_amount`` already bounds an
    amount to 18 decimal places (a multiple of 1e6 yocto), so this refusal is a
    defensive invariant of the conversion rather than a reachable input path.
    """
    scaled = amount * Decimal(YOCTO_PER_NEAR)
    if scaled != scaled.to_integral_value():
        raise CustodyError("the amount has more precision than one yoctoNEAR")
    return int(scaled)


@dataclass
class PreparedCustodyTransfer:
    """A constructed, evaluated custody transfer, ready to send.

    ``authorization`` is present only on ALLOW. ``transaction_digest`` is the
    canonical digest the authorization is bound to *and* the value the provider
    operation is re-derived from before it is sent, so a substituted recipient,
    amount, asset, network or service cannot ride on a valid authorization.
    """

    network: NearNetwork
    wallet_account: str
    wallet_public_key: str
    destination: str
    amount_yocto: int
    amount_human: Decimal
    service_id: str
    decision: GuardDecision
    authorization: Any = None
    authorization_id: str | None = None
    binding: dict[str, str] = field(default_factory=dict)
    transaction_digest: str = ""
    idempotency_key: str = ""

    @property
    def authorized(self) -> bool:
        return self.decision.decision is Decision.ALLOW and self.authorization is not None

    def to_dict(self) -> dict[str, Any]:
        return {
            "network": self.network.value,
            "mode": "outlayer-custody",
            "wallet_account": self.wallet_account,
            "wallet_public_key": self.wallet_public_key,
            "destination": self.destination,
            "amount_yocto": str(self.amount_yocto),
            "amount_near": str(self.amount_human),
            "service_id": self.service_id,
            "decision": self.decision.to_dict(include_authorization=False),
            "authorized": self.authorized,
            "authorization_id": self.authorization_id,
            "binding": dict(self.binding),
            "transaction_digest": self.transaction_digest,
            "idempotency_key": self.idempotency_key,
        }


@dataclass
class CustodyExecution:
    """The outcome of a custody execution, with the independent verification."""

    provider: ProviderOutcome
    tx_hash: str | None
    verification: SettlementVerification
    authorization_id: str | None = None
    transaction_digest: str = ""
    settlement_verified: bool = False
    provider_claimed_success: bool = False

    def to_dict(self) -> dict[str, Any]:
        return {
            "provider": self.provider.to_dict(),
            "tx_hash": self.tx_hash,
            "authorization_id": self.authorization_id,
            "transaction_digest": self.transaction_digest,
            "provider_claimed_success": self.provider_claimed_success,
            "settlement_verified": self.settlement_verified,
            "verification": self.verification.to_dict(),
        }


def custody_digest(
    *,
    network: str,
    wallet_account: str,
    destination: str,
    amount_yocto: int,
    service_id: str,
    operation: str = CUSTODY_OPERATION,
    asset: str = CUSTODY_ASSET,
) -> str:
    """The canonical digest of a custody transfer.

    It commits to the network, the wallet identity, the recipient, the exact
    amount in base units, the operation, the asset and the service, so a change
    to any of them changes the digest and therefore the authorization binding.
    """
    payload = json.dumps(
        {
            "network": network,
            "wallet_account": wallet_account,
            "operation": operation.upper(),
            "asset": asset.upper(),
            "destination": destination,
            "amount_yocto": str(int(amount_yocto)),
            "service_id": service_id,
        },
        sort_keys=True,
        separators=(",", ":"),
    ).encode("utf-8")
    return hashlib.sha256(b"TRACESETTLE-OUTLAYER-CUSTODY-V1\x00" + payload).hexdigest()


def verify_custody_transaction(
    *,
    transaction_digest: str,
    tx_hash: str,
    wallet_account: str,
    expected_receiver: str,
    expected_deposit_yocto: int,
    result: Any,
    source_status: SourceStatus,
) -> SettlementVerification:
    """Independently verify a custody transaction against the NEAR chain record.

    Every check is a refusal on failure. In particular the transaction is
    ``VERIFIED`` only when the chain reports it final, successful, signed by the
    configured wallet, addressed to the authorized recipient, carrying the
    authorized deposit, and signed with a key whose implicit account *is* the
    wallet account - the cryptographic tie between the TEE-held key and the
    on-chain signer. A provider claim is never consulted here.
    """
    if source_status is not SourceStatus.OK or not isinstance(result, dict):
        return SettlementVerification(
            state=SettlementState.INSUFFICIENT_EVIDENCE,
            source_status=source_status.value,
            note="the chain record could not be obtained; no conclusion is drawn",
            checks=[Check("record_available", False, source_status.value)],
        )
    checks: list[Check] = []
    onchain = result.get("transaction", {}) or {}
    finality = str(result.get("final_execution_status", ""))
    status_kind = _status_kind(result.get("status"))

    reported_hash = str(onchain.get("hash", ""))
    checks.append(
        Check("tx_hash_matches", reported_hash == tx_hash, f"expected {tx_hash}, got {reported_hash or 'none'}")
    )
    checks.append(
        Check(
            "signer_is_wallet",
            str(onchain.get("signer_id", "")) == wallet_account,
            f"expected {wallet_account}, got {onchain.get('signer_id')}",
        )
    )
    checks.append(
        Check(
            "receiver_is_authorized_destination",
            str(onchain.get("receiver_id", "")) == expected_receiver,
            f"expected {expected_receiver}, got {onchain.get('receiver_id')}",
        )
    )
    deposit = _transfer_deposit(onchain)
    checks.append(
        Check(
            "amount_matches",
            deposit == expected_deposit_yocto,
            f"expected {expected_deposit_yocto}, got {deposit}",
        )
    )
    # The signing key's implicit account must be the wallet account: this is the
    # on-chain proof that the key that signed is the TEE-held wallet key.
    public_key = str(onchain.get("public_key", ""))
    try:
        key_account = _implicit_account(public_key) if public_key else ""
    except (CustodyError, ValueError):
        key_account = ""
    checks.append(
        Check(
            "signing_key_is_the_wallet_key",
            key_account == wallet_account,
            f"key {public_key or 'none'} resolves to {key_account or 'none'}",
        )
    )
    checks.append(Check("final", finality == "FINAL", f"final_execution_status={finality or 'unknown'}"))
    checks.append(Check("execution_success", status_kind == "success", f"status={status_kind}"))

    ok = all(c.ok for c in checks)
    state = SettlementState.VERIFIED if ok else SettlementState.DISPUTED
    return SettlementVerification(
        state=state,
        checks=checks,
        evidence={
            "transaction_digest": transaction_digest,
            "tx_hash": tx_hash,
            "final_execution_status": finality,
            "signer_id": onchain.get("signer_id"),
            "receiver_id": onchain.get("receiver_id"),
            "deposit_yocto": deposit,
        },
        source_status=source_status.value,
        note=(
            "independently verified against the NEAR chain record"
            if ok
            else "the chain record contradicts the authorized transaction"
        ),
    )


def _status_kind(status: Any) -> str:
    if not isinstance(status, dict):
        return "unknown"
    if "SuccessValue" in status or "SuccessReceiptId" in status:
        return "success"
    if "Failure" in status:
        return "failure"
    return "unknown"


def _transfer_deposit(onchain: dict) -> int | None:
    for action in onchain.get("actions", []) or []:
        if isinstance(action, dict) and "Transfer" in action:
            try:
                return int(action["Transfer"]["deposit"])
            except (KeyError, TypeError, ValueError):
                return None
    return None


class OutLayerCustodyBoundary:
    """Runs the authorization firewall in front of the OutLayer custody provider."""

    def __init__(
        self,
        guard_service: GuardService,
        provider: OutLayerCustodyProvider,
        *,
        network: NearNetwork = NearNetwork.TESTNET,
        rpc: NearRpc | None = None,
        poll_attempts: int = 10,
        poll_delay: float = 1.5,
        sleep: Any | None = None,
        identity: Any | None = None,
    ) -> None:
        self.guard = guard_service
        self.provider = provider
        self.network = network
        self.rpc = rpc
        self.poll_attempts = poll_attempts
        self.poll_delay = poll_delay
        self._sleep = sleep if sleep is not None else time.sleep
        self._identity = identity

    # -- identity -----------------------------------------------------------

    def wallet_identity(self) -> Any:
        """The resolved wallet identity, cached after the first read."""
        if self._identity is None:
            self._identity = self.provider.address("near")
        return self._identity

    def info(self) -> dict[str, Any]:
        """Describe the boundary without ever contacting the provider.

        A configured provider is reported as configured; whether it is *reachable*
        is a separate, explicit probe, so a status page never implies a live
        connection it has not made.
        """
        return {
            "enabled": True,
            "provider": "outlayer",
            "network": self.provider.config.network,
            "is_testnet": self.provider.config.is_testnet,
            "wallet_id": self.provider.config.wallet_id or None,
            "mode": "outlayer-custody",
            "signing": "TEE (OutLayer Agent Custody)",
            "note": (
                "Operations are authorized by TraceSettle and then signed by an "
                "OutLayer TEE-held wallet key. Settlement is verified independently "
                "through the NEAR RPC."
            ),
        }

    def provider_status(self) -> dict[str, Any]:
        """Probe the provider: reachability, wallet identity, balance, policy.

        A failure here is reported, never hidden. The provider's own ``policy``
        and the register-contract's approved measurements are included as
        evidence; neither is treated as TraceSettle's authorization.
        """
        status: dict[str, Any] = {"provider": "outlayer", "network": self.provider.config.network}
        try:
            identity = self.wallet_identity()
            status["reachable"] = True
            status["wallet"] = identity.to_dict()
        except OutLayerError as exc:
            status["reachable"] = False
            status["error"] = str(exc)
            return status
        try:
            status["balance_yocto"] = str(self.provider.balance("near"))
        except OutLayerError as exc:
            status["balance_error"] = str(exc)
        try:
            status["policy"] = self.provider.policy()
        except OutLayerError as exc:
            status["policy"] = {"available": False, "error": str(exc)}
        try:
            status["approved_measurements"] = self.provider.approved_measurements()
        except OutLayerError as exc:
            status["approved_measurements"] = {"available": False, "error": str(exc)}
        return status

    # -- prepare ------------------------------------------------------------

    def prepare(
        self,
        *,
        service_id: str,
        destination: str,
        amount_human: Decimal | str,
        request_id: str | None = None,
        idempotency_key: str | None = None,
    ) -> PreparedCustodyTransfer:
        """Build and evaluate a custody transfer. Never sends anything."""
        identity = self.wallet_identity()
        wallet_account = identity.account_id
        # ``parse_amount`` accepts a string or an int, never a float; a Decimal
        # is normalised to its plain string form so the caller may pass either.
        amount_text = format(amount_human, "f") if isinstance(amount_human, Decimal) else amount_human
        amount = parse_amount(amount_text)
        if amount <= 0:
            raise CustodyError("the transfer amount must be positive")
        amount_yocto = _to_yocto(amount)

        digest = custody_digest(
            network=self.network.value,
            wallet_account=wallet_account,
            destination=destination,
            amount_yocto=amount_yocto,
            service_id=service_id,
        )
        request = TransactionRequest(
            request_id=request_id or f"cust_{hashlib.sha256(digest.encode()).hexdigest()[:12]}",
            service_id=service_id,
            operation=CUSTODY_OPERATION,
            chain=f"near-{self.network.value}",
            asset=CUSTODY_ASSET,
            amount=amount,
            destination=destination,
            amount_raw=str(amount),
            idempotency_key=idempotency_key,
            # The digest commits the authorization to the exact operation, so a
            # substituted recipient or amount cannot ride on a valid token.
            transaction_digest=digest,
        )
        decision = self.guard.evaluate(request)
        prepared = PreparedCustodyTransfer(
            network=self.network,
            wallet_account=wallet_account,
            wallet_public_key=identity.public_key,
            destination=destination,
            amount_yocto=amount_yocto,
            amount_human=amount,
            service_id=service_id,
            decision=decision,
            authorization=decision.authorization,
            authorization_id=(
                getattr(decision.authorization, "authorization_id", None)
                if decision.authorization is not None
                else None
            ),
            binding=canonical_fields(
                service_id=service_id,
                operation=CUSTODY_OPERATION,
                chain=f"near-{self.network.value}",
                asset=CUSTODY_ASSET,
                amount=amount,
                destination=destination,
                transaction_digest=digest,
            ),
            transaction_digest=digest,
            idempotency_key=idempotency_key_for(digest),
        )
        return prepared

    def verify_binding(self, prepared: PreparedCustodyTransfer, *, consume: bool = False) -> Any:
        """Re-derive the digest from the operation and validate the authorization.

        The digest is recomputed from the fields the operation would actually be
        sent with, and the authorization authority is asked to validate against
        it. A mismatch is refused *before* the single-use nonce is consumed, so a
        tampered operation cannot burn the authorization.
        """
        if not prepared.authorized:
            raise CustodyError(
                f"refusing to execute: the decision was {prepared.decision.decision.value}"
            )
        rederived = custody_digest(
            network=prepared.network.value,
            wallet_account=prepared.wallet_account,
            destination=prepared.destination,
            amount_yocto=prepared.amount_yocto,
            service_id=prepared.service_id,
        )
        if rederived != prepared.transaction_digest:
            raise CustodyError("the operation does not match the authorized transaction digest")
        expected = fingerprint_of(prepared.binding)
        verification = self.guard.authority.validate(
            prepared.authorization,
            expected=expected,
            consume=consume,
            expected_service_id=prepared.service_id,
        )
        if not verification.valid:
            raise CustodyError(
                f"the authorization does not cover this operation ({verification.state.value})"
            )
        return verification

    # -- execute ------------------------------------------------------------

    def execute(self, prepared: PreparedCustodyTransfer) -> CustodyExecution:
        """Send the authorized operation, then verify settlement independently.

        Reached only for an authorized operation; a BLOCK/HOLD/REQUIRE_APPROVAL
        decision raises before the provider is contacted.
        """
        if not prepared.authorized:
            raise CustodyError(
                f"refusing to execute: the decision was {prepared.decision.decision.value}"
            )
        # Consume the single-use authorization *before* the irreversible send, so
        # the same authorization cannot be replayed even if the send's outcome is
        # unknown. The digest was re-validated immediately above.
        self.verify_binding(prepared, consume=True)

        outcome = self.provider.transfer(
            to=prepared.destination,
            amount_yocto=prepared.amount_yocto,
            idempotency_key=prepared.idempotency_key,
        )
        outcome = self._poll_to_terminal(outcome)

        tx_hash = outcome.tx_hash
        verification = SettlementVerification(
            state=SettlementState.INSUFFICIENT_EVIDENCE,
            source_status="NOT_QUERIED",
            note="no transaction hash was returned by the provider",
        )
        if tx_hash and self.rpc is not None:
            verification = self._verify_onchain(tx_hash, prepared)
        elif tx_hash and self.rpc is None:
            verification = SettlementVerification(
                state=SettlementState.INSUFFICIENT_EVIDENCE,
                source_status="UNAVAILABLE",
                note="no NEAR RPC is configured, so settlement could not be verified",
            )

        return CustodyExecution(
            provider=outcome,
            tx_hash=tx_hash,
            verification=verification,
            authorization_id=prepared.authorization_id,
            transaction_digest=prepared.transaction_digest,
            settlement_verified=verification.state is SettlementState.VERIFIED,
            provider_claimed_success=outcome.claimed_success,
        )

    def _poll_to_terminal(self, outcome: ProviderOutcome) -> ProviderOutcome:
        """Poll an in-flight request to a terminal state.

        A request whose outcome is unknown (a timeout) is **not** resubmitted;
        the caller resolves it from the chain or by request id. Polling is
        bounded, so an operation that never settles is reported as still in
        flight rather than as a success.
        """
        if not outcome.request_id or is_terminal(outcome.state):
            return outcome
        current = outcome
        for _ in range(max(1, self.poll_attempts)):
            if not is_in_flight(current.state):
                break
            self._sleep(self.poll_delay)
            try:
                current = self.provider.request_status(outcome.request_id)
            except OutLayerError:
                break
        return current

    def _verify_onchain(self, tx_hash: str, prepared: PreparedCustodyTransfer) -> SettlementVerification:
        result = self.rpc.tx_status(tx_hash, prepared.wallet_account)
        return verify_custody_transaction(
            transaction_digest=prepared.transaction_digest,
            tx_hash=tx_hash,
            wallet_account=prepared.wallet_account,
            expected_receiver=prepared.destination,
            expected_deposit_yocto=prepared.amount_yocto,
            result=result.data,
            source_status=result.status,
        )
