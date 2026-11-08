"""The real NEAR execution pipeline: sign, submit, verify - durably.

This is the production path that replaces the simulated executor. It composes
the pieces that already exist rather than duplicating them:

* :class:`~tracesettle.near.execution.NearExecutionBoundary` builds the exact
  bytes, evaluates the operator policy, enforces the TEE gate, and re-derives the
  transaction binding before it will accept a signature;
* :class:`~tracesettle.near.verify.verify_transaction` independently reconciles
  the on-chain record against the authorized transaction;
* :class:`~tracesettle.near.ledger.SubmissionLedger` makes the submission
  durable, so an interrupted execution is resolved from the chain, never guessed.

The one rule that shapes the whole module: **a submission whose outcome is
unknown is never blindly resubmitted.** A NEAR transaction hash covers its nonce,
so the *identical* signed bytes can be applied at most once; re-sending them is
therefore idempotent and safe, while sending *different* bytes is never done. A
send that times out is recorded ``UNKNOWN`` and resolved by asking the chain what
happened.

Honest scope: the reference signer is software. A software key is **not**
hardware-protected execution. When the TEE gate is enabled, signing is refused
unless a verified TDX attestation is bound to the exact transaction, so the
attestation is *enforced* - but the module never claims the signature itself was
produced inside an enclave.
"""

from __future__ import annotations

import base64
import hashlib
import time
from dataclasses import dataclass, field
from typing import Any, Protocol

from ..model import SourceStatus
from . import ed25519
from .execution import NearExecutionBoundary, PreparedOperation
from .ledger import SubmissionLedger, SubmissionRecord, SubmissionState
from .networks import NearNetwork
from .tee_signing.evidence_chain import (
    EvidenceChain,
    EvidenceChainStore,
    build_evidence_chain,
    verify_chain_bindings,
)
from .txbuild import NearTransaction
from .verify import SettlementState, SettlementVerification, verify_transaction


class SigningError(ValueError):
    """A transaction could not be signed, or signing was refused."""


class TransactionSigner(Protocol):
    """Something that can sign the exact bytes of a NEAR transaction."""

    @property
    def public_key(self) -> str: ...

    def sign(self, message: bytes) -> bytes: ...


class LocalKeySigner:
    """An in-memory ed25519 signer for a **testnet** key. Never used for mainnet.

    This exists so the pipeline can be exercised end to end without a browser
    wallet. It is deliberately narrow: it refuses to sign for mainnet, it never
    writes the key anywhere, and it is labelled as software signing - the
    hardware-attestation guarantee, when required, comes from the TEE gate at the
    boundary, not from this class.
    """

    def __init__(self, seed: bytes, *, network: NearNetwork, account_id: str) -> None:
        if len(seed) != 32:
            raise SigningError("an ed25519 seed must be exactly 32 bytes")
        if network is NearNetwork.MAINNET:
            raise SigningError(
                "the in-memory signer is testnet-only; refusing to sign for mainnet"
            )
        self._seed = bytes(seed)
        self._network = network
        self._account_id = account_id
        self._public_key = "ed25519:" + _b58(ed25519.public_key(self._seed))

    @property
    def public_key(self) -> str:
        return self._public_key

    @property
    def account_id(self) -> str:
        return self._account_id

    def sign(self, message: bytes) -> bytes:
        return ed25519.sign(message, self._seed)


def _b58(raw: bytes) -> str:
    alphabet = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz"
    n = int.from_bytes(raw, "big")
    out = ""
    while n:
        n, r = divmod(n, 58)
        out = alphabet[r] + out
    pad = len(raw) - len(raw.lstrip(b"\x00"))
    return "1" * pad + (out or "")


@dataclass
class ExecutionResult:
    """The full outcome of one pipeline run, ready to persist and report."""

    state: str
    tx_hash: str
    settlement_state: str
    verification: SettlementVerification | None
    signed_b64: str
    receipt: dict[str, Any] = field(default_factory=dict)
    recovered: bool = False

    @property
    def settled(self) -> bool:
        return self.state == SubmissionState.SETTLED

    def to_dict(self) -> dict[str, Any]:
        return {
            "state": self.state,
            "tx_hash": self.tx_hash,
            "settlement_state": self.settlement_state,
            "verification": self.verification.to_dict() if self.verification else None,
            "receipt": dict(self.receipt),
            "recovered": self.recovered,
        }


class NearExecutionPipeline:
    """Sign, submit, and independently verify a prepared NEAR transaction."""

    def __init__(
        self,
        boundary: NearExecutionBoundary,
        *,
        ledger: SubmissionLedger | None = None,
        finality_attempts: int = 8,
        finality_delay: float = 1.0,
        chain_store: EvidenceChainStore | None = None,
    ) -> None:
        self.boundary = boundary
        self.ledger = ledger if ledger is not None else SubmissionLedger()
        self.config = boundary.config
        self.finality_attempts = finality_attempts
        self.finality_delay = finality_delay
        #: Optional durable evidence chain. ``None`` means the pipeline does not
        #: persist one; the chain is still built and attached to the result.
        self.chain_store = chain_store

    # -- independent pre-sign checks --------------------------------------

    def verify_signing_preconditions(self, prepared: PreparedOperation) -> None:
        """Re-check every precondition *before* a key is touched.

        This is the signer's own verification, independent of the boundary: the
        operation must be authorized, the network must be the one configured, and
        when the TEE gate is on the execution record must be verified, unexpired,
        and bound to the exact bytes about to be signed. Any failure refuses and
        no signature is produced.
        """
        if not prepared.authorized:
            raise SigningError("the operation was not authorized; refusing to sign")

        if prepared.network is not self.config.network:
            raise SigningError(
                f"the operation targets {prepared.network.value} but this signer is "
                f"configured for {self.config.network.value}; refusing to sign"
            )

        if prepared.transaction.signer_id == "" or prepared.transaction.receiver_id == "":
            raise SigningError("the transaction is missing a signer or receiver")

        if self.boundary.tee_required:
            record = self.boundary.tee_authorizer.get(prepared.execution_id or "")
            if record is None:
                raise SigningError("no execution record for this operation; refusing to sign")
            if record.expired:
                raise SigningError("the execution authorization has expired; refusing to sign")
            if not record.tee_verified:
                raise SigningError(
                    "no verified TEE attestation is bound to this execution; refusing to sign"
                )
            digest = self.boundary._transaction_digest(prepared.transaction)
            if digest != record.transaction_digest:
                raise SigningError(
                    "the transaction does not match the authorized execution; refusing to sign"
                )

    # -- the pipeline ------------------------------------------------------

    def execute(
        self,
        prepared: PreparedOperation,
        signer: TransactionSigner,
        *,
        idempotency_key: str = "",
        attempts: int | None = None,
        delay: float | None = None,
    ) -> ExecutionResult:
        """Sign, submit, and verify one authorized operation, durably.

        Idempotent on ``idempotency_key``: a repeat of an already-known submission
        returns the recorded result instead of signing or sending again.
        """
        attempts = self.finality_attempts if attempts is None else attempts
        delay = self.finality_delay if delay is None else delay
        if idempotency_key:
            existing = self.ledger.get_by_idempotency(idempotency_key)
            if existing is not None:
                return self._result_from_record(existing, recovered=True)

        # 1. Independent precondition check (no key touched on failure).
        self.verify_signing_preconditions(prepared)

        # 2. Sign the exact authorized transaction. NEAR signs the *hash* of the
        #    Borsh transaction, not the raw bytes.
        try:
            signature_raw = signer.sign(prepared.transaction.tx_hash_bytes)
        except Exception as exc:  # noqa: BLE001 - a signer failure is a refusal
            raise SigningError(f"the signer refused: {exc}") from exc

        # 3. Accept the signature through the boundary. This enforces the TEE
        #    gate, re-derives the binding, verifies the signature belongs to this
        #    transaction, and consumes the single-use authorization nonce.
        signature_b64 = base64.b64encode(signature_raw).decode("ascii")
        signed_b64, _ = self.boundary.accept_signature(prepared, signature_b64)

        tx = prepared.transaction
        record = SubmissionRecord(
            tx_hash=tx.tx_hash,
            state=SubmissionState.SIGNED,
            network=self.config.network.value,
            signer_id=tx.signer_id,
            receiver_id=tx.receiver_id,
            amount_base=str(tx.amount_base),
            destination=tx.destination,
            signed_b64=signed_b64,
            idempotency_key=idempotency_key,
        )
        self.ledger.put(record)

        return self._submit_and_verify(record, prepared, attempts=attempts, delay=delay)

    def submit_signed(
        self,
        prepared: PreparedOperation,
        signature_b64: str,
        *,
        idempotency_key: str = "",
        attempts: int | None = None,
        delay: float | None = None,
    ) -> ExecutionResult:
        """Submit a transaction signed by a *client* (a connected wallet).

        The server never holds the key: it validates the caller's signature
        against the authorized transaction through the boundary (which enforces
        the TEE gate and the binding and consumes the single-use nonce), records
        the submission durably, then broadcasts and verifies. This is the
        wallet-mediated path, given the same durability and finality handling as
        the in-process signer path.
        """
        attempts = self.finality_attempts if attempts is None else attempts
        delay = self.finality_delay if delay is None else delay
        if idempotency_key:
            existing = self.ledger.get_by_idempotency(idempotency_key)
            if existing is not None:
                return self._result_from_record(existing, recovered=True)

        self.verify_signing_preconditions(prepared)
        signed_b64, _ = self.boundary.accept_signature(prepared, signature_b64)
        tx = prepared.transaction
        record = SubmissionRecord(
            tx_hash=tx.tx_hash,
            state=SubmissionState.SIGNED,
            network=self.config.network.value,
            signer_id=tx.signer_id,
            receiver_id=tx.receiver_id,
            amount_base=str(tx.amount_base),
            destination=tx.destination,
            signed_b64=signed_b64,
            idempotency_key=idempotency_key,
        )
        self.ledger.put(record)
        return self._submit_and_verify(record, prepared, attempts=attempts, delay=delay)

    def _submit_and_verify(
        self,
        record: SubmissionRecord,
        prepared: PreparedOperation | None,
        *,
        attempts: int,
        delay: float,
    ) -> ExecutionResult:
        record.attempts += 1
        record.transition(SubmissionState.SUBMITTING, reason="send in flight")
        self.ledger.put(record)

        result = self.boundary.rpc.send_tx(record.signed_b64, wait_until="INCLUDED_FINAL")

        if result.status is not SourceStatus.OK:
            # The outcome is unknown: the node may or may not have applied it.
            # Never assume failure and never resubmit blindly.
            record.last_error = result.error or result.status.value
            record.transition(
                SubmissionState.UNKNOWN,
                reason=f"submission outcome unknown ({result.status.value})",
            )
            self.ledger.put(record)
            # Try once to resolve it from the chain; if the chain has it, use it.
            resolved = self.resolve_unknown(record.tx_hash, prepared=prepared)
            if resolved is not None:
                return resolved
            return ExecutionResult(
                state=record.state,
                tx_hash=record.tx_hash,
                settlement_state=SettlementState.INSUFFICIENT_EVIDENCE.value,
                verification=None,
                signed_b64=record.signed_b64,
                receipt={"endpoint": result.endpoint, "note": record.last_error},
            )

        record.transition(SubmissionState.SUBMITTED, reason="node returned a result")
        self.ledger.put(record)
        verification = self._verify(record, prepared, result)
        # A node commonly returns an optimistic (non-final) execution status at
        # broadcast time. Poll the chain, bounded, until the execution is final -
        # never *assume* finality, and never inflate a pending state to VERIFIED.
        verification = self._poll_until_final(record, prepared, verification, attempts, delay)
        return self._finalize(record, prepared, verification, endpoint=result.endpoint)

    def _poll_until_final(
        self,
        record: SubmissionRecord,
        prepared: PreparedOperation | None,
        verification: SettlementVerification,
        attempts: int,
        delay: float,
    ) -> SettlementVerification:
        """Poll ``tx_status`` until the execution is final, or the budget runs out.

        Only a still-``PENDING`` verdict is polled; a definitive verdict is
        returned as-is. The outcome is never upgraded without a fresh, final
        on-chain record.
        """
        polls = 0
        while (
            verification.state is SettlementState.PENDING
            and polls < max(0, attempts)
        ):
            polls += 1
            if delay:
                time.sleep(delay)
            result = self.boundary.rpc.tx_status(record.tx_hash, record.signer_id)
            if result.status is not SourceStatus.OK or not isinstance(result.data, dict):
                break
            verification = self._verify(record, prepared, result)
        return verification

    def _verify(
        self, record: SubmissionRecord, prepared: PreparedOperation | None, result: Any
    ) -> SettlementVerification:
        """Reconcile an on-chain record against the authorized transaction.

        With the original transaction available, every semantic check runs
        (amount, receiver, actions). Without it (a recovery of a record we did not
        rebuild), only identity and finality can be checked, so the verdict is
        capped at ``CONFIRMED`` - it is never inflated to ``VERIFIED``.
        """
        if prepared is not None:
            return verify_transaction(
                transaction=prepared.transaction, result=result.data, source_status=result.status
            )
        return self.boundary.verify_only(record.tx_hash, record.signer_id)

    def _finalize(
        self,
        record: SubmissionRecord,
        prepared: PreparedOperation | None,
        verification: SettlementVerification,
        *,
        endpoint: str = "",
    ) -> ExecutionResult:
        if verification.state is SettlementState.VERIFIED:
            record.transition(SubmissionState.SETTLED, reason="independently verified")
        elif verification.state is SettlementState.FAILED:
            record.transition(SubmissionState.FAILED, reason="transaction failed on-chain")
        else:
            # Included but not yet final, or not fully verifiable: keep it
            # pending/unknown rather than claiming settlement.
            record.transition(
                SubmissionState.UNKNOWN,
                reason=f"settlement not established ({verification.state.value})",
            )
        record.settlement = verification.to_dict()
        self.ledger.put(record)

        chain = self._build_chain(record, prepared, verification)
        if chain is not None and self.chain_store is not None:
            self.chain_store.put(chain)

        # Mirror the outcome onto the TEE execution record when one exists.
        if (
            prepared is not None
            and self.boundary.tee_authorizer is not None
            and prepared.execution_id
        ):
            try:
                self.boundary._record_settlement_state(prepared.execution_id, verification)
            except Exception:  # noqa: BLE001 - lifecycle mirroring never fails a settle
                pass

        return ExecutionResult(
            state=record.state,
            tx_hash=record.tx_hash,
            settlement_state=verification.state.value,
            verification=verification,
            signed_b64=record.signed_b64,
            receipt={
                "endpoint": endpoint,
                "explorer_url": self.config.explorer_url(record.tx_hash),
            },
        )

    # -- evidence chain ----------------------------------------------------

    def _build_chain(
        self,
        record: SubmissionRecord,
        prepared: PreparedOperation | None,
        verification: SettlementVerification,
    ) -> EvidenceChain | None:
        """Assemble the authorization-to-settlement chain from the real facts.

        Everything here is read from the objects the pipeline already holds. When
        the prepared operation is absent (a recovery of a record we did not
        rebuild) the earlier stages are simply absent — never invented.
        """
        digest = ""
        authorization = None
        transaction = None
        if prepared is not None:
            digest = prepared.transaction.payload_fingerprint()
            auth = prepared.authorization
            authorization = {
                "id": prepared.authorization_id or getattr(auth, "authorization_id", ""),
                "decision": prepared.decision.decision.value,
                "policy_version": getattr(auth, "policy_version", ""),
                "digest": getattr(auth, "fingerprint", ""),
                "expiry": getattr(auth, "expires_at", ""),
                "network": prepared.transaction.network.value,
                "transaction_digest": digest,
                "receiver_account": prepared.transaction.receiver_id,
                "amount_base": str(prepared.transaction.amount_base),
            }
            transaction = {
                "signer_id": prepared.transaction.signer_id,
                "public_key": prepared.transaction.public_key,
                "receiver_id": prepared.transaction.receiver_id,
                "amount_base": str(prepared.transaction.amount_base),
                "destination": prepared.transaction.destination,
                "nonce": prepared.transaction.nonce,
                "block_hash": prepared.transaction.block_hash,
                "network": prepared.transaction.network.value,
                "transaction_digest": digest,
                "unsigned_bytes_sha256": digest.replace("sha256:", ""),
            }
        if not digest:
            # Recover the digest from the exact signed bytes, which the record holds.
            digest = (
                "sha256:" + hashlib.sha256(self._unsigned_from_record(record)).hexdigest()
                if record.signed_b64
                else ""
            )

        signing = {
            "route": "onchain",
            "public_key": getattr(prepared.transaction, "public_key", "") if prepared else "",
            "transaction_digest": digest,
            "tx_hash": record.tx_hash,
            # The record only holds ``signed_b64`` because ``accept_signature``
            # verified the ed25519 signature over this transaction's hash and then
            # consumed the single-use authorization. A record without signed bytes
            # never passed that gate, so this is a recorded fact, not a proxy on
            # how far settlement got.
            "signature_verified": bool(record.signed_b64),
        }
        # Carry the signature itself, recovered from the exact signed bytes the
        # ledger holds, so a reviewer can re-verify it rather than trust the
        # ``signature_verified`` flag. ``accept_signature`` already checked it, so
        # this is recovery of a recorded fact, not a new trust.
        if record.signed_b64:
            try:
                raw_signature = NearTransaction.signature_from_signed(
                    base64.b64decode(record.signed_b64)
                )
                if raw_signature:
                    signing["signature_b64"] = base64.b64encode(raw_signature).decode("ascii")
            except (ValueError, TypeError):
                pass
        chain = build_evidence_chain(
            transaction_digest=digest,
            authorization=authorization,
            transaction=transaction,
            signing=signing,
            submission={"tx_hash": record.tx_hash, "state": record.state},
            settlement={
                "state": verification.state.value,
                "tx_hash": record.tx_hash,
                "receiver": record.receiver_id,
                "amount_base": record.amount_base,
                "all_checks_passed": verification.all_ok,
                "failed_checks": [c.name for c in verification.failed_checks()],
                "sources": [verification.source_status] if verification.source_status else [],
            },
            network=record.network,
            tx_hash=record.tx_hash,
        )
        return chain

    def _unsigned_from_record(self, record: SubmissionRecord) -> bytes:
        """The exact signed transaction bytes, without the signature trailer."""
        from .txbuild import NearTransaction

        return NearTransaction.unsigned_from_signed_b64(record.signed_b64)

    def verify_evidence_chain(self, tx_hash: str) -> dict[str, Any] | None:
        """Re-check a stored chain's bindings. ``None`` when no chain is stored."""
        if self.chain_store is None:
            return None
        chain = self.chain_store.get(tx_hash)
        if chain is None:
            return None
        binding = verify_chain_bindings(chain)
        return {
            "tx_hash": chain.tx_hash,
            "transaction_digest": chain.transaction_digest,
            "chain_digest": chain.digest(),
            "bound": binding.bound,
            "checks": binding.checks,
            "failures": binding.failures,
        }

    # -- recovery ----------------------------------------------------------

    def reconstruct_transaction(self, record: SubmissionRecord) -> NearTransaction | None:
        """Rebuild the exact transaction from the durable signed bytes.

        Recovery of a record whose original ``PreparedOperation`` is gone (a
        restart, another instance, or a wallet-submitted transaction) can still
        re-derive what was signed from the bytes the ledger stored, so the
        on-chain record can be checked against the amount and actions - not only
        the hash and finality. Returns ``None`` when the bytes cannot be decoded
        faithfully, in which case the caller keeps the weaker, honest check.

        The decoded transaction is cross-checked against the record's own fields:
        a decode that disagrees with the recorded signer, receiver, amount or
        destination is treated as a failure to reconstruct, never trusted.
        """
        if not record.signed_b64:
            return None
        try:
            network = NearNetwork(record.network)
        except ValueError:
            return None
        from .txdecode import TransactionDecodeError, decode_signed_b64

        try:
            decoded = decode_signed_b64(record.signed_b64, network=network)
        except TransactionDecodeError:
            return None
        if decoded.operation == "UNKNOWN":
            # The bytes decoded and verified, but the action set is not one this
            # tool describes, so the amount cannot be re-checked. Do not pretend.
            return None
        # Defence in depth: the durable record and the signed bytes must agree.
        if decoded.signer_id != record.signer_id:
            return None
        if record.receiver_id and decoded.receiver_id != record.receiver_id:
            return None
        if record.amount_base and str(decoded.amount_base) != str(record.amount_base):
            return None
        if record.destination and decoded.destination != record.destination:
            return None
        return decoded.to_transaction()

    def resolve_unknown(
        self, tx_hash: str, *, prepared: PreparedOperation | None = None
    ) -> ExecutionResult | None:
        """Resolve a submission whose outcome is unknown by asking the chain.

        Returns ``None`` when the chain does not (yet) know the transaction, so
        the record stays ``UNKNOWN``. It never sends anything.

        When the original ``prepared`` operation is unavailable but the signed
        bytes are durably recorded, the transaction is reconstructed from those
        bytes and the full semantic verification runs, so a recovered transaction
        reaches the same verdict (``VERIFIED``) as one still in memory. Only when
        the bytes cannot be faithfully reconstructed does the verdict fall back to
        the weaker ``CONFIRMED``-capped check.
        """
        record = self.ledger.get(tx_hash)
        if record is None:
            return None
        result = self.boundary.rpc.tx_status(tx_hash, record.signer_id)
        if result.status is not SourceStatus.OK or not isinstance(result.data, dict):
            return None
        if prepared is not None:
            verification = verify_transaction(
                transaction=prepared.transaction, result=result.data, source_status=result.status
            )
            return self._finalize(record, prepared, verification, endpoint=result.endpoint)
        rebuilt = self.reconstruct_transaction(record)
        if rebuilt is not None:
            verification = verify_transaction(
                transaction=rebuilt, result=result.data, source_status=result.status
            )
            return self._finalize(record, None, verification, endpoint=result.endpoint)
        # The bytes are not reconstructable, so only identity and finality can be
        # reconciled; the amount is not re-checked, so the best we can honestly
        # assert is CONFIRMED-level evidence, mapped below.
        verification = self.boundary.verify_only(tx_hash, record.signer_id)
        return self._finalize(record, prepared, verification, endpoint=result.endpoint)

    def recover(self) -> tuple[ExecutionResult, ...]:
        """Resolve every pending submission. Never sends, never resubmits.

        Called on start-up and on demand. A ``SIGNED`` record that was never sent
        is left as-is (it has no on-chain record to find); a ``SUBMITTING`` or
        ``UNKNOWN`` record is resolved from the chain when the chain knows it.
        """
        results: list[ExecutionResult] = []
        for record in self.ledger.pending():
            resolved = self.resolve_unknown(record.tx_hash)
            if resolved is not None:
                results.append(resolved)
        return tuple(results)

    def resume_signed(self, tx_hash: str) -> ExecutionResult | None:
        """Re-send the *identical* recorded bytes for a never-sent submission.

        Safe by construction: a NEAR transaction's hash covers its nonce, so the
        same bytes can be applied at most once. This is only ever called for a
        record in ``SIGNED`` state (signed, never sent); it is never used to
        retry a transaction whose submission status is unknown.
        """
        record = self.ledger.get(tx_hash)
        if record is None or record.state != SubmissionState.SIGNED:
            return None
        prepared = None  # no prepared transaction: verify by identity only
        return self._submit_and_verify(record, prepared, attempts=1, delay=0.0)  # type: ignore[arg-type]

    def _result_from_record(
        self, record: SubmissionRecord, *, recovered: bool
    ) -> ExecutionResult:
        return ExecutionResult(
            state=record.state,
            tx_hash=record.tx_hash,
            settlement_state=str(record.settlement.get("state", "")),
            verification=None,
            signed_b64=record.signed_b64,
            recovered=recovered,
        )
