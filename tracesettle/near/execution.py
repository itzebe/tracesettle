"""The NEAR execution boundary.

This is the only supported path from an intended operation to a signed,
broadcast NEAR transaction. It enforces, in order and without exception:

1. resolve the network **server-side** and verify its identity against the RPC;
2. resolve the asset and re-check its decimals on-chain;
3. construct the real transaction (validated inputs, current block hash, current
   access-key nonce);
4. evaluate it with the guard, using the *operator's* policy - never a
   client-supplied decision;
5. apply learned safeguards (the guard does this inside ``evaluate``);
6. if the outcome is ALLOW, issue a transaction-bound authorization;
7. hand the exact transaction to the user's wallet for signing;
8. **re-derive** the binding from the final transaction and require an exact
   match with the authorized fields before accepting the signature;
9. broadcast the signed bytes and retrieve the real result;
10. independently verify settlement against the authorized transaction.

Any step that is not a clean success refuses, and no later step runs. In
particular, a transaction whose parameters changed after authorization cannot be
signed: step 8 recomputes the fingerprint from the bytes that would be signed and
compares it to the authorized fingerprint, so a substituted destination, amount,
asset, network, operation, account, nonce, block hash or action is a mismatch and
is refused.

The application holds no key. Signing is the wallet's action; this module accepts
a signature and validates that it belongs to the authorized transaction, then
broadcasts. It never stores, logs or transmits a private key or seed phrase.
"""

from __future__ import annotations

import base64
from collections import OrderedDict
from dataclasses import dataclass, field
from decimal import Decimal
from typing import Any

from ..guard.model import (
    Decision,
    GuardDecision,
    TransactionRequest,
    fingerprint_of,
    parse_amount,
)
from ..guard.service import GuardService
from ..model import SourceStatus
from . import ed25519
from .assets import AssetError, NearAsset, resolve_asset, verify_decimals
from .networks import NetworkConfig, NetworkError, NearNetwork, parse_network, verify_network_identity
from .rpc import NearRpc
from .txbuild import (
    NearTransaction,
    build_ft_transfer,
    build_transfer,
    next_nonce,
)
from .verify import SettlementState, SettlementVerification, verify_transaction


class ExecutionError(ValueError):
    """A lifecycle step could not proceed. The message is client-safe."""


#: The guard's chain id for a NEAR network is network-scoped. The guard's chain
#: allowlist is an operator choice, so listing ``near-testnet`` authorises only
#: testnet and listing ``near-mainnet`` only mainnet: a testnet authorization can
#: never be replayed against a mainnet transaction, because the chain the
#: authorization covers differs.
def guard_chain_for(network: NearNetwork) -> str:
    return f"near-{network.value}"


def binding_chain_for(network: NearNetwork) -> str:
    return f"near-{network.value}"


def _canonical_asset(asset: NearAsset) -> str:
    return asset.identifier


@dataclass
class PreparedOperation:
    """A constructed, evaluated operation, ready for a wallet to sign.

    ``authorization`` is present only when the decision was ALLOW. ``transaction``
    is the exact bytes-bound object the wallet must sign; ``binding`` is the
    canonical parameter set the authorization covers.
    """

    network: NearNetwork
    transaction: NearTransaction
    decision: GuardDecision
    authorization: Any = None
    authorization_id: str | None = None
    binding: dict[str, str] = field(default_factory=dict)

    @property
    def authorized(self) -> bool:
        return self.decision.decision is Decision.ALLOW and self.authorization is not None

    def to_dict(self) -> dict[str, Any]:
        return {
            "network": self.network.value,
            "transaction": self.transaction.to_dict(),
            "decision": self.decision.to_dict(include_authorization=False),
            "authorized": self.authorized,
            "authorization_id": self.authorization_id,
            "binding": dict(self.binding),
        }


@dataclass
class ExecutedOperation:
    """The outcome of a broadcast, with the independent settlement verification."""

    state: SettlementState
    tx_hash: str
    verification: SettlementVerification
    receipt: dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        return {
            "state": self.state.value,
            "tx_hash": self.tx_hash,
            "verification": self.verification.to_dict(),
        }


class PreparedOperationStore:
    """A bounded, expiring, owner-scoped store of prepared operations.

    A prepared operation must survive from the moment it is authorized to the
    moment its signature arrives, so the bytes that are signed are provably the
    bytes that were authorized. The store is:

    * **bounded** - an LRU cap, so a caller cannot exhaust memory;
    * **expiring** - an entry older than the authorization TTL is useless anyway
      (the authorization would be expired), so it is dropped;
    * **owner-scoped** - an entry is readable only by the service that created
      it, so one service can never sign another's prepared transaction; and
    * **single-use** - taking an entry removes it, so a prepared operation cannot
      be signed twice.
    """

    def __init__(self, max_entries: int = 128, ttl_seconds: float = 300.0, clock=None) -> None:
        import threading
        import time

        self._lock = threading.Lock()
        self._entries: "OrderedDict[str, tuple[float, str, PreparedOperation]]" = OrderedDict()
        self._max = max_entries
        self._ttl = ttl_seconds
        self._clock = clock or time.monotonic

    def _prune(self) -> None:
        now = self._clock()
        for key in [k for k, (at, _, _) in self._entries.items() if now - at > self._ttl]:
            self._entries.pop(key, None)

    def store(self, prepared: PreparedOperation, owner: str) -> str:
        import secrets

        prepare_id = "prep_" + secrets.token_urlsafe(18)
        with self._lock:
            self._prune()
            self._entries[prepare_id] = (self._clock(), owner, prepared)
            while len(self._entries) > self._max:
                self._entries.popitem(last=False)
        return prepare_id

    def peek(self, prepare_id: str, owner: str) -> PreparedOperation | None:
        with self._lock:
            self._prune()
            entry = self._entries.get(prepare_id)
        if entry is None:
            return None
        _, entry_owner, prepared = entry
        if entry_owner != owner:
            # Not this owner's entry. Report "not found" rather than "forbidden",
            # so the response cannot be used to probe another owner's ids.
            return None
        return prepared

    def take(self, prepare_id: str, owner: str) -> PreparedOperation | None:
        with self._lock:
            self._prune()
            entry = self._entries.get(prepare_id)
            if entry is None:
                return None
            _, entry_owner, prepared = entry
            if entry_owner != owner:
                return None
            self._entries.pop(prepare_id, None)
        return prepared


class NearExecutionBoundary:
    """The one path that may sign and broadcast a NEAR transaction."""

    def __init__(
        self,
        guard: GuardService,
        config: NetworkConfig,
        *,
        rpc: NearRpc | None = None,
    ) -> None:
        self.guard = guard
        self.config = config
        self.rpc = rpc or NearRpc(config)

    # -- preconditions -----------------------------------------------------

    def verify_network(self) -> None:
        """Confirm the configured RPC really is the network it claims.

        Called before any transaction is built. A mainnet endpoint answering
        while the code believes it is on testnet (or the reverse) is a hard
        error, never a warning.
        """
        status = self.rpc.status()
        if not status.ok or not isinstance(status.data, dict):
            raise ExecutionError(f"network {self.config.network.value} is unreachable ({status.status.value})")
        try:
            verify_network_identity(self.config, status.data)
        except NetworkError as exc:
            raise ExecutionError(str(exc)) from exc

    def _block_hash(self) -> str:
        result = self.rpc.block_hash(finality="final")
        if not result.ok or not isinstance(result.data, dict):
            raise ExecutionError("could not obtain a recent block hash from the network")
        return str(result.data["hash"])

    def _next_nonce(self, account_id: str, public_key: str) -> int:
        result = self.rpc.view_access_key(account_id, public_key)
        if result.status is SourceStatus.NOT_FOUND:
            raise ExecutionError(
                "the supplied public key is not an access key of the signer account"
            )
        if not result.ok or not isinstance(result.data, dict):
            raise ExecutionError("could not read the signer account's access key nonce")
        nonce = result.data.get("nonce")
        if not isinstance(nonce, int):
            raise ExecutionError("the access key returned no nonce")
        return next_nonce(nonce)

    def _verify_asset_decimals(self, asset: NearAsset) -> None:
        if asset.is_native:
            return
        result = self.rpc.call_function(asset.contract or "", "ft_metadata")
        if not result.ok or not isinstance(result.data, dict):
            raise ExecutionError(
                f"could not verify {asset.symbol} decimals on-chain; refusing to build "
                "a transfer with unverified decimals"
            )
        try:
            verify_decimals(result.data, asset)
        except ValueError as exc:
            raise ExecutionError(str(exc)) from exc

    # -- build + authorize -------------------------------------------------

    def prepare(
        self,
        *,
        service_id: str,
        account_id: str,
        public_key: str,
        receiver_id: str,
        asset_identifier: str,
        amount_human: str | Decimal,
        operation: str | None = None,
        network: str | NearNetwork | None = None,
        simulated: bool = False,
        request_id: str | None = None,
        idempotency_key: str | None = None,
        policy_action: str | None = None,
    ) -> PreparedOperation:
        """Build the real transaction and evaluate it with the operator policy.

        Refuses (raising :class:`ExecutionError`) before any signing if the
        network, the asset, the decimals, the block hash or the nonce cannot be
        resolved, so a malformed request never reaches a wallet.
        """
        # 1. Network is resolved server-side. A client-supplied network that is
        #    unknown is an error; a known one is accepted only because the caller
        #    is choosing which *deployment* to act on, and the resolved network is
        #    then verified against the RPC and bound into the authorization.
        requested = parse_network(network)
        if requested is not self.config.network:
            raise ExecutionError(
                f"this server is configured for {self.config.network.value}; "
                f"refusing a {requested.value} operation"
            )
        self.verify_network()

        # 2. Asset identity + decimals, verified on-chain.
        try:
            asset = resolve_asset(self.config.network, asset_identifier)
        except AssetError as exc:
            raise ExecutionError(str(exc)) from exc
        self._verify_asset_decimals(asset)

        # 3. Construct the transaction.
        block_hash = self._block_hash()
        nonce = self._next_nonce(account_id, public_key)
        amount = parse_amount(amount_human) if not isinstance(amount_human, Decimal) else amount_human
        if asset.is_native:
            tx = build_transfer(
                network=self.config.network,
                signer_id=account_id,
                public_key=public_key,
                nonce=nonce,
                receiver_id=receiver_id,
                block_hash=block_hash,
                amount_human=amount,
                service_id=service_id,
            )
            guard_operation = "WITHDRAWAL"
        else:
            tx = build_ft_transfer(
                network=self.config.network,
                signer_id=account_id,
                public_key=public_key,
                nonce=nonce,
                block_hash=block_hash,
                asset=asset,
                receiver_id=receiver_id,
                amount_human=amount,
                service_id=service_id,
            )
            guard_operation = "WITHDRAWAL"

        # 4. Evaluate with the guard. The chain is the bare chain id so the
        #    operator allowlist is unchanged; the network is bound separately.
        guard_asset = asset.identifier.upper()
        request = TransactionRequest(
            request_id=request_id or f"near-{service_id}",
            service_id=service_id,
            operation=operation or guard_operation,
            chain=guard_chain_for(self.config.network),
            asset=guard_asset,
            amount=amount,
            destination=receiver_id,
            amount_raw=str(amount),
            idempotency_key=idempotency_key,
            simulated=simulated,
        )
        decision = self.guard.evaluate(request)

        authorization = None
        authorization_id = None
        if decision.decision is Decision.ALLOW and decision.authorization is not None:
            authorization = decision.authorization
            authorization_id = getattr(authorization, "authorization_id", None)

        return PreparedOperation(
            network=self.config.network,
            transaction=tx,
            decision=decision,
            authorization=authorization,
            authorization_id=authorization_id,
            # The binding is recomputed from the *final* transaction, so it is
            # exactly the parameter set a signature will be checked against.
            binding=tx.guard_canonical_fields(),
        )

    # -- signing boundary --------------------------------------------------

    def verify_binding(self, prepared: PreparedOperation, *, consume: bool = False) -> Any:
        """Validate the authorization against the *final* transaction.

        The expected fingerprint is recomputed from the transaction that would be
        signed - not from the request that preceded it - and handed to the
        authorization authority. The authority recomputes its own fingerprint and
        compares. A destination, amount, asset, network, operation, account,
        nonce, block hash or action change between authorization and signing
        therefore produces a different fingerprint and the authority refuses with
        ``WRONG_PARAMETERS``. Nothing is signed unless the authority returns
        exactly ``VALID``.

        ``consume=True`` spends the single-use nonce, so the same authorization
        cannot sign a second transaction. It is set only at the moment a
        signature is accepted, never by a pre-check.
        """
        if not prepared.authorized:
            raise ExecutionError(
                f"refusing to sign: the decision was {prepared.decision.decision.value}"
            )
        expected = fingerprint_of(prepared.transaction.guard_canonical_fields())
        verification = self.guard.authority.validate(
            prepared.authorization,
            expected=expected,
            consume=consume,
            expected_service_id=prepared.binding.get("service_id") or None,
        )
        if not verification.valid:
            raise ExecutionError(
                "the authorization does not cover this transaction "
                f"({verification.state.value}); refusing to sign"
            )
        return verification

    def accept_signature(
        self, prepared: PreparedOperation, signature_b64: str
    ) -> tuple[str, bytes]:
        """Validate a wallet signature against the authorized transaction.

        Returns the signed transaction as base64 and the raw signature bytes.
        Refuses if the operation was not authorized, if the authorization does not
        cover the final transaction (consuming the single-use nonce on success),
        or if the signature does not verify against the transaction hash and the
        signer's public key. A signature that does not belong to *this*
        transaction is not accepted, so a signature cannot be reused for a
        different payload.
        """
        self.verify_binding(prepared, consume=True)
        try:
            raw = base64.b64decode(signature_b64, validate=True)
        except (ValueError, TypeError) as exc:
            raise ExecutionError("the signature was not valid base64") from exc
        if len(raw) != 64:
            raise ExecutionError("an ed25519 signature must be 64 bytes")
        public_raw = _public_key_raw(prepared.transaction.public_key)
        message = prepared.transaction.tx_hash_bytes
        if not ed25519.verify(raw, message, public_raw):
            raise ExecutionError(
                "the signature does not verify against the authorized transaction; refusing"
            )
        return prepared.transaction.signed_b64(raw), raw

    def broadcast(self, prepared: PreparedOperation, signature_b64: str) -> ExecutedOperation:
        """Validate the signature, submit, and independently verify settlement."""
        signed_b64, _ = self.accept_signature(prepared, signature_b64)
        result = self.rpc.send_tx(signed_b64, wait_until="INCLUDED_FINAL")
        verification = verify_transaction(
            transaction=prepared.transaction,
            result=result.data,
            source_status=result.status,
        )
        return ExecutedOperation(
            state=verification.state,
            tx_hash=prepared.transaction.tx_hash,
            verification=verification,
            receipt={
                "endpoint": result.endpoint,
                "explorer_url": self.config.explorer_url(prepared.transaction.tx_hash),
            },
        )

    def wait_for_final(self, prepared: PreparedOperation, *, attempts: int = 8, delay: float = 1.0) -> SettlementVerification:
        """Poll the transaction until it is final, bounded, then verify it.

        A broadcast may return before the transaction is final. This re-fetches
        the record a bounded number of times and verifies the *final* record
        against the authorized transaction. It never fabricates a final state: if
        the transaction is still not final after the attempts, the last (non-final)
        verification is returned, so the caller sees ``PENDING`` rather than a
        false ``VERIFIED``.
        """
        import time

        last: SettlementVerification | None = None
        for attempt in range(max(1, attempts)):
            result = self.rpc.tx_status(prepared.transaction.tx_hash, prepared.transaction.signer_id)
            last = verify_transaction(
                transaction=prepared.transaction, result=result.data, source_status=result.status
            )
            if last.state.is_terminal:
                return last
            if attempt < attempts - 1:
                time.sleep(delay)
        return last or SettlementVerification(
            state=SettlementState.INSUFFICIENT_EVIDENCE,
            source_status=SourceStatus.NETWORK_ERROR.value,
            note="no transaction record was obtained",
        )

    def verify_only(self, tx_hash: str, signer_account_id: str) -> SettlementVerification:
        """Re-verify an already-submitted transaction from the chain alone.

        Used by the "settlement assurance" view: it takes only a hash and the
        signer, fetches the record, and reports the state - it does not trust any
        earlier "success". Because it cannot re-derive the intended amount without
        the original transaction, it checks everything the record itself
        establishes (hash, finality, execution success) and reports
        ``INSUFFICIENT_EVIDENCE`` rather than claiming a transfer it cannot see.
        """
        result = self.rpc.tx_status(tx_hash, signer_account_id)
        if result.status is SourceStatus.OK and isinstance(result.data, dict):
            # Build a minimal expected transaction purely for the identity checks.
            return _verify_from_record(tx_hash, signer_account_id, result)
        return SettlementVerification(
            state=SettlementState.INSUFFICIENT_EVIDENCE,
            source_status=result.status.value,
            note="the transaction record could not be obtained from the network",
        )


def _verify_from_record(tx_hash: str, signer: str, result) -> SettlementVerification:
    from .verify import Check

    data = result.data
    onchain = data.get("transaction", {}) or {}
    finality = str(data.get("final_execution_status", ""))
    status = data.get("status")
    checks = [
        Check("tx_hash_matches", str(onchain.get("hash", "")) == tx_hash, "hash from the network"),
        Check("signer_matches", str(onchain.get("signer_id", "")) == signer, f"signer={onchain.get('signer_id')}"),
        Check("final", finality == "FINAL", f"final_execution_status={finality or 'unknown'}"),
        Check("execution_success", isinstance(status, dict) and "SuccessValue" in status, "execution outcome"),
    ]
    if not all(c.ok for c in checks):
        state = SettlementState.FAILED if isinstance(status, dict) and "Failure" in status else SettlementState.PENDING
        if not checks[0].ok or not checks[1].ok:
            state = SettlementState.DISPUTED
        return SettlementVerification(state, checks, {"tx_hash": tx_hash}, finality,
                                      "the record was checked but does not fully establish success")
    return SettlementVerification(
        SettlementState.CONFIRMED,
        checks,
        {"tx_hash": tx_hash, "final_execution_status": finality},
        finality,
        "the transaction is final and executed successfully; the intended transfer "
        "could not be re-checked without the original transaction",
    )


def _public_key_raw(public_key: str) -> bytes:
    from ..base58 import b58decode

    key = public_key.strip()
    if key.startswith("ed25519:"):
        key = key[len("ed25519:") :]
    raw = b58decode(key)
    if raw is None or len(raw) != 32:
        raise ExecutionError("public key must be a 32-byte ed25519 key")
    return raw
