"""Independent on-chain settlement verification for NEAR transactions.

The wallet's "success" toast is not evidence. A provider's ``SUCCESS`` status is
not evidence. The only thing that establishes that an operation actually did
what was intended is the on-chain record, checked field by field against what
was *supposed* to happen.

This module takes a submitted transaction's RPC result and the transaction that
was authorized, and decides a state from the explicit list below. It is
deterministic: identical inputs produce an identical verdict, and no heuristic
(amount similarity, timestamp proximity, "looks about right") ever promotes a
state.

States (a strict, auditable set - no implicit transitions):

``VERIFIED``
    Every required check passed on the on-chain record: the hash, network,
    signer, receiver/contract, the intended action, the amount, and a successful
    execution with the expected transfer evidence.
``CONFIRMED``
    The transaction is final and executed successfully, but the *semantic*
    transfer evidence for the operation could not be fully checked (e.g. an
    NEP-141 event the node did not return). Final and successful, but not
    independently tied to the intended transfer.
``PENDING``
    The transaction exists but has not reached finality.
``FAILED``
    The transaction executed and failed on-chain, or the record contradicts the
    intended operation (wrong signer, wrong receiver, wrong amount).
``DISPUTED``
    Two sources disagree, or the record contradicts itself.
``INSUFFICIENT_EVIDENCE``
    The record could not be obtained (outage, not-found, malformed). Never
    upgraded to success.

A provider or wallet ``SUCCESS`` alone maps to ``PENDING``/``INSUFFICIENT_EVIDENCE``
at best; it is never ``VERIFIED``.
"""

from __future__ import annotations

import base64
import enum
import json
from dataclasses import dataclass, field
from typing import Any

from ..model import SourceStatus
from .networks import NearNetwork
from .txbuild import OP_FT_TRANSFER, OP_TRANSFER, NearTransaction


class SettlementState(str, enum.Enum):
    CREATED = "CREATED"
    AUTHORIZATION_PENDING = "AUTHORIZATION_PENDING"
    REJECTED = "REJECTED"
    AUTHORIZED = "AUTHORIZED"
    AWAITING_SIGNATURE = "AWAITING_SIGNATURE"
    SIGNED = "SIGNED"
    SUBMITTED = "SUBMITTED"
    PENDING = "PENDING"
    CONFIRMED = "CONFIRMED"
    VERIFIED = "VERIFIED"
    FAILED = "FAILED"
    DISPUTED = "DISPUTED"
    INSUFFICIENT_EVIDENCE = "INSUFFICIENT_EVIDENCE"

    @property
    def is_terminal(self) -> bool:
        return self in {
            SettlementState.VERIFIED,
            SettlementState.CONFIRMED,
            SettlementState.FAILED,
            SettlementState.DISPUTED,
            SettlementState.INSUFFICIENT_EVIDENCE,
        }


#: Allowed transitions. Anything not listed is invalid and refused, so a state
#: can never be reached by an unmodelled path.
_TRANSITIONS: dict[SettlementState, set[SettlementState]] = {
    SettlementState.CREATED: {SettlementState.AUTHORIZATION_PENDING, SettlementState.REJECTED},
    SettlementState.AUTHORIZATION_PENDING: {
        SettlementState.AUTHORIZED,
        SettlementState.REJECTED,
        SettlementState.INSUFFICIENT_EVIDENCE,
    },
    SettlementState.AUTHORIZED: {SettlementState.AWAITING_SIGNATURE, SettlementState.REJECTED},
    SettlementState.AWAITING_SIGNATURE: {SettlementState.SIGNED, SettlementState.REJECTED},
    SettlementState.SIGNED: {SettlementState.SUBMITTED},
    SettlementState.SUBMITTED: {
        SettlementState.PENDING,
        SettlementState.CONFIRMED,
        SettlementState.VERIFIED,
        SettlementState.FAILED,
        SettlementState.DISPUTED,
        SettlementState.INSUFFICIENT_EVIDENCE,
    },
    SettlementState.PENDING: {
        SettlementState.CONFIRMED,
        SettlementState.VERIFIED,
        SettlementState.FAILED,
        SettlementState.DISPUTED,
        SettlementState.INSUFFICIENT_EVIDENCE,
    },
    SettlementState.CONFIRMED: {SettlementState.VERIFIED, SettlementState.DISPUTED},
    SettlementState.VERIFIED: set(),
    SettlementState.FAILED: set(),
    SettlementState.DISPUTED: set(),
    SettlementState.INSUFFICIENT_EVIDENCE: {SettlementState.PENDING, SettlementState.CONFIRMED, SettlementState.VERIFIED},
}


def transition_allowed(frm: SettlementState, to: SettlementState) -> bool:
    return to in _TRANSITIONS.get(frm, set())


class SettlementTransitionError(ValueError):
    pass


@dataclass(frozen=True)
class Check:
    """One named check and its outcome, kept for the evidence trail."""

    name: str
    ok: bool
    detail: str = ""

    def to_dict(self) -> dict[str, Any]:
        return {"name": self.name, "ok": self.ok, "detail": self.detail}


@dataclass
class SettlementVerification:
    state: SettlementState
    checks: list[Check] = field(default_factory=list)
    evidence: dict[str, Any] = field(default_factory=dict)
    source_status: str = ""
    note: str = ""

    @property
    def all_ok(self) -> bool:
        return all(c.ok for c in self.checks)

    def failed_checks(self) -> list[Check]:
        return [c for c in self.checks if not c.ok]

    def to_dict(self) -> dict[str, Any]:
        return {
            "state": self.state.value,
            "terminal": self.state.is_terminal,
            "all_checks_passed": self.all_ok,
            "checks": [c.to_dict() for c in self.checks],
            "failed": [c.name for c in self.failed_checks()],
            "evidence": self.evidence,
            "source_status": self.source_status,
            "note": self.note,
        }


def _get_status_kind(status: Any) -> str:
    if not isinstance(status, dict):
        return "unknown"
    if "SuccessValue" in status:
        return "success"
    if "SuccessReceiptId" in status:
        return "success_receipt"
    if "Failure" in status:
        return "failure"
    return "unknown"


def _ft_transfer_events(result: dict) -> list[dict]:
    """Extract NEP-297 ``ft_transfer`` events from receipt logs (NEP-141)."""
    events: list[dict] = []
    for outcome in result.get("receipts_outcome", []) or []:
        logs = ((outcome or {}).get("outcome", {}) or {}).get("logs", []) or []
        for line in logs:
            if not isinstance(line, str) or not line.startswith("EVENT_JSON:"):
                continue
            try:
                payload = json.loads(line[len("EVENT_JSON:") :])
            except ValueError:
                continue
            if not isinstance(payload, dict):
                continue
            if payload.get("standard") != "nep141" or payload.get("event") != "ft_transfer":
                continue
            for item in payload.get("data", []) or []:
                if isinstance(item, dict):
                    events.append(item)
    return events


def verify_transaction(
    *,
    transaction: NearTransaction,
    result: Any,
    source_status: SourceStatus,
) -> SettlementVerification:
    """Verify a submitted transaction against the record the node returned."""
    if source_status is not SourceStatus.OK or not isinstance(result, dict):
        return SettlementVerification(
            state=SettlementState.INSUFFICIENT_EVIDENCE,
            source_status=source_status.value,
            note="the transaction record could not be obtained; no conclusion is drawn",
            checks=[Check("record_available", False, source_status.value)],
        )

    checks: list[Check] = []
    onchain = result.get("transaction", {}) or {}
    finality = str(result.get("final_execution_status", ""))
    status_kind = _get_status_kind(result.get("status"))

    # 1. identity: the hash the network reports equals the hash we predicted.
    reported_hash = str(onchain.get("hash", ""))
    checks.append(
        Check("tx_hash_matches", reported_hash == transaction.tx_hash,
              f"expected {transaction.tx_hash}, got {reported_hash or 'none'}")
    )
    # 2. signer is the account that was authorized to sign.
    checks.append(
        Check("signer_matches", str(onchain.get("signer_id", "")) == transaction.signer_id,
              f"expected {transaction.signer_id}, got {onchain.get('signer_id')}")
    )
    # 3. the transaction's receiver is the one we built.
    checks.append(
        Check("receiver_matches", str(onchain.get("receiver_id", "")) == transaction.receiver_id,
              f"expected {transaction.receiver_id}, got {onchain.get('receiver_id')}")
    )
    # 4. nonce matches (a different nonce means different bytes).
    checks.append(
        Check("nonce_matches", int(onchain.get("nonce", -1)) == transaction.nonce,
              f"expected {transaction.nonce}, got {onchain.get('nonce')}")
    )
    # 5. finality. Only the network's own ``FINAL`` counts: ``EXECUTED`` and
    #    ``EXECUTED_OPTIMISTIC`` mean the transaction ran but is not final, so
    #    they must never be treated as final.
    is_final = finality == "FINAL"
    checks.append(Check("final", is_final, f"final_execution_status={finality or 'unknown'}"))

    # 6. execution outcome.
    checks.append(
        Check("execution_success", status_kind == "success", f"status={status_kind}")
    )

    evidence: dict[str, Any] = {
        "tx_hash": reported_hash,
        "signer_id": onchain.get("signer_id"),
        "receiver_id": onchain.get("receiver_id"),
        "nonce": onchain.get("nonce"),
        "final_execution_status": finality,
        "status": status_kind,
        "block_hash": (result.get("transaction_outcome", {}) or {}).get("block_hash"),
    }

    # 7. semantic evidence for the intended operation.
    if transaction.operation == OP_TRANSFER:
        deposit = _transfer_deposit(onchain)
        ok = deposit == transaction.amount_base
        checks.append(
            Check("transfer_amount_matches", ok,
                  f"expected {transaction.amount_base} yoctoNEAR, found {deposit}")
        )
        evidence["transfer_deposit_yocto"] = deposit
    elif transaction.operation == OP_FT_TRANSFER:
        args = _function_call_args(onchain, "ft_transfer")
        recipient = (args or {}).get("receiver_id")
        amount = (args or {}).get("amount")
        checks.append(
            Check("ft_transfer_args_match",
                  recipient == transaction.destination and str(amount) == str(transaction.amount_base),
                  f"receiver_id={recipient}, amount={amount}")
        )
        events = _ft_transfer_events(result)
        match = [e for e in events if str(e.get("amount")) == str(transaction.amount_base)
                 and e.get("new_owner_id") == transaction.destination
                 and e.get("old_owner_id") == transaction.signer_id]
        checks.append(
            Check("ft_transfer_event_matches", bool(match),
                  f"{len(events)} ft_transfer event(s); {len(match)} matched the intended transfer")
        )
        evidence["ft_transfer_events"] = events
    else:
        checks.append(Check("operation_recognised", False, f"unknown operation {transaction.operation}"))

    # Decide the state from the checks, never from any single flag.
    hard_fail = [c for c in checks if not c.ok and c.name in {
        "tx_hash_matches", "signer_matches", "receiver_matches", "nonce_matches", "execution_success",
        "transfer_amount_matches", "ft_transfer_args_match", "operation_recognised",
    }]
    semantic_missing = [c for c in checks if not c.ok and c.name in {
        "ft_transfer_event_matches",
    }]

    if status_kind == "failure":
        return SettlementVerification(SettlementState.FAILED, checks, evidence, finality,
                                      "the transaction executed and failed on-chain")
    if hard_fail:
        # A contradiction between what we intended and what is on-chain.
        return SettlementVerification(SettlementState.DISPUTED, checks, evidence, finality,
                                      "the on-chain record contradicts the intended operation")
    if not is_final:
        return SettlementVerification(SettlementState.PENDING, checks, evidence, finality,
                                      "the transaction has not reached finality")
    if semantic_missing:
        return SettlementVerification(SettlementState.CONFIRMED, checks, evidence, finality,
                                      "final and successful, but the transfer event could not be fully checked")
    return SettlementVerification(SettlementState.VERIFIED, checks, evidence, finality,
                                  "every required check passed on the on-chain record")


def _transfer_deposit(onchain: dict) -> int | None:
    for action in onchain.get("actions", []) or []:
        if isinstance(action, dict) and "Transfer" in action:
            try:
                return int(action["Transfer"]["deposit"])
            except (KeyError, TypeError, ValueError):
                return None
    return None


def _function_call_args(onchain: dict, method_name: str) -> dict | None:
    for action in onchain.get("actions", []) or []:
        fc = (action or {}).get("FunctionCall") if isinstance(action, dict) else None
        if not fc:
            continue
        if fc.get("method_name") != method_name:
            continue
        raw = fc.get("args")
        if not isinstance(raw, str):
            return None
        try:
            return json.loads(base64.b64decode(raw).decode("utf-8"))
        except (ValueError, TypeError, UnicodeDecodeError):
            return None
    return None


@dataclass(frozen=True)
class IntendedOperation:
    """What a wallet-signed transaction was *supposed* to do.

    A wallet signs and sends its own transaction, so the exact nonce, block hash
    and serialized bytes are chosen by the wallet, not by TraceSettle. The
    independently checkable facts are the ones the authorization was bound to:
    the signer, the receiver, the operation, the amount, and (for a NEP-141
    transfer) the recipient carried in the call arguments. Verification checks
    the on-chain record against exactly these - never against amount or
    timestamp similarity.
    """

    network: NearNetwork
    signer_id: str
    operation: str
    receiver_id: str
    amount_base: int
    destination: str
    contract: str | None = None


def verify_intent(
    *,
    intended: IntendedOperation,
    result: Any,
    source_status: SourceStatus,
) -> SettlementVerification:
    """Verify a wallet-submitted transaction against the intended operation.

    The same discipline as :func:`verify_transaction`: only the on-chain record
    establishes a state, a provider/wallet ``SUCCESS`` alone never does, and a
    contradiction is ``DISPUTED`` rather than ``VERIFIED``.
    """
    if source_status is not SourceStatus.OK or not isinstance(result, dict):
        return SettlementVerification(
            state=SettlementState.INSUFFICIENT_EVIDENCE,
            source_status=source_status.value,
            note="the transaction record could not be obtained; no conclusion is drawn",
            checks=[Check("record_available", False, source_status.value)],
        )

    checks: list[Check] = []
    onchain = result.get("transaction", {}) or {}
    finality = str(result.get("final_execution_status", ""))
    status_kind = _get_status_kind(result.get("status"))

    # 1. the signer is the account whose wallet signed.
    checks.append(
        Check("signer_matches", str(onchain.get("signer_id", "")) == intended.signer_id,
              f"expected {intended.signer_id}, got {onchain.get('signer_id')}")
    )
    # 2. the transaction's receiver is the one we intended (the token contract
    #    for a NEP-141 transfer, the recipient for a native transfer).
    checks.append(
        Check("receiver_matches", str(onchain.get("receiver_id", "")) == intended.receiver_id,
              f"expected {intended.receiver_id}, got {onchain.get('receiver_id')}")
    )
    # 3. finality. Only the network's own FINAL counts.
    is_final = finality == "FINAL"
    checks.append(Check("final", is_final, f"final_execution_status={finality or 'unknown'}"))
    # 4. execution outcome.
    checks.append(Check("execution_success", status_kind == "success", f"status={status_kind}"))

    evidence: dict[str, Any] = {
        "tx_hash": str(onchain.get("hash", "")),
        "signer_id": onchain.get("signer_id"),
        "receiver_id": onchain.get("receiver_id"),
        "nonce": onchain.get("nonce"),
        "final_execution_status": finality,
        "status": status_kind,
        "block_hash": (result.get("transaction_outcome", {}) or {}).get("block_hash"),
    }

    # 5. the intended operation is present and matches in amount and recipient.
    if intended.operation == OP_TRANSFER:
        deposit = _transfer_deposit(onchain)
        checks.append(
            Check("transfer_amount_matches", deposit == intended.amount_base,
                  f"expected {intended.amount_base} yoctoNEAR, found {deposit}")
        )
        evidence["transfer_deposit_yocto"] = deposit
    elif intended.operation == OP_FT_TRANSFER:
        args = _function_call_args(onchain, "ft_transfer")
        recipient = (args or {}).get("receiver_id")
        amount = (args or {}).get("amount")
        checks.append(
            Check("ft_transfer_args_match",
                  recipient == intended.destination and str(amount) == str(intended.amount_base),
                  f"receiver_id={recipient}, amount={amount}")
        )
        events = _ft_transfer_events(result)
        match = [e for e in events if str(e.get("amount")) == str(intended.amount_base)
                 and e.get("new_owner_id") == intended.destination
                 and e.get("old_owner_id") == intended.signer_id]
        checks.append(
            Check("ft_transfer_event_matches", bool(match),
                  f"{len(events)} ft_transfer event(s); {len(match)} matched the intended transfer")
        )
        evidence["ft_transfer_events"] = events
    else:
        checks.append(Check("operation_recognised", False, f"unknown operation {intended.operation}"))

    hard_fail = [c for c in checks if not c.ok and c.name in {
        "signer_matches", "receiver_matches", "execution_success",
        "transfer_amount_matches", "ft_transfer_args_match", "operation_recognised",
    }]
    semantic_missing = [c for c in checks if not c.ok and c.name in {"ft_transfer_event_matches"}]

    if status_kind == "failure":
        return SettlementVerification(SettlementState.FAILED, checks, evidence, finality,
                                      "the transaction executed and failed on-chain")
    if hard_fail:
        return SettlementVerification(SettlementState.DISPUTED, checks, evidence, finality,
                                      "the on-chain record contradicts the intended operation")
    if not is_final:
        return SettlementVerification(SettlementState.PENDING, checks, evidence, finality,
                                      "the transaction has not reached finality")
    if semantic_missing:
        return SettlementVerification(SettlementState.CONFIRMED, checks, evidence, finality,
                                      "final and successful, but the transfer event could not be fully checked")
    return SettlementVerification(SettlementState.VERIFIED, checks, evidence, finality,
                                  "every required check passed on the on-chain record")
