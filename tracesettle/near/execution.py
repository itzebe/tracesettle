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
    canonical_fields,
    fingerprint_of,
    parse_amount,
)
from ..guard.service import GuardService
from ..model import SourceStatus
from . import ed25519
from .access_keys import (
    AccessKeyPermission,
    key_supports_operation,
    parse_access_key,
)
from .assets import AssetError, NearAsset, from_base_units, resolve_asset, to_base_units, verify_decimals
from .networks import NetworkConfig, NetworkError, NearNetwork, parse_network, verify_network_identity
from .rpc import NearRpc
from .tee_execution import (
    ExecutionState,
    IllegalTransition,
    TeeExecutionError,
    can_transition,
)
from .txbuild import (
    DEFAULT_FT_TRANSFER_GAS,
    OP_FT_TRANSFER,
    OP_TRANSFER,
    NearTransaction,
    build_ft_transfer,
    build_transfer,
    next_nonce,
)
from .verify import (
    IntendedOperation,
    SettlementState,
    SettlementVerification,
    verify_intent,
    verify_transaction,
)


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
    #: The TEE-bound execution record id, present when the TEE gate is enabled.
    execution_id: str | None = None
    #: The decision nonce an attestation must be bound to, once requested.
    tee_nonce: str | None = None
    #: The verified attestation binding, once it has been established.
    tee_binding: Any = None

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
            "execution_id": self.execution_id,
            "tee_nonce": self.tee_nonce,
            "tee_binding": self.tee_binding.to_dict() if self.tee_binding is not None else None,
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


@dataclass
class PreparedWalletOperation:
    """An operation a **connected wallet** will sign and send itself.

    Unlike :class:`PreparedOperation`, TraceSettle does not build or hold the
    transaction bytes here: the wallet constructs its own transaction (its own
    nonce and block hash) and broadcasts it. What TraceSettle holds is the
    *intent* the authorization is bound to, the transaction-bound authorization,
    and the wallet request the user must approve. Verification later checks the
    on-chain record against that intent.
    """

    network: NearNetwork
    account_id: str
    receiver_id: str
    operation: str
    asset: NearAsset
    amount_base: int
    amount_human: Decimal
    destination: str
    decision: GuardDecision
    wallet_request: dict[str, Any]
    authorization: Any = None
    authorization_id: str | None = None
    binding: dict[str, str] = field(default_factory=dict)

    @property
    def authorized(self) -> bool:
        return self.decision.decision is Decision.ALLOW and self.authorization is not None

    def to_dict(self) -> dict[str, Any]:
        return {
            "network": self.network.value,
            "mode": "wallet",
            "account_id": self.account_id,
            "receiver_id": self.receiver_id,
            "operation": self.operation,
            "asset": self.asset.to_dict(),
            "amount_base_units": str(self.amount_base),
            "amount_human": str(self.amount_human),
            "destination": self.destination,
            "decision": self.decision.to_dict(include_authorization=False),
            "authorized": self.authorized,
            "authorization_id": self.authorization_id,
            "binding": dict(self.binding),
            "wallet_request": self.wallet_request,
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


class PreparedWalletStore:
    """A bounded, expiring, owner-scoped store of wallet operations.

    Identical discipline to :class:`PreparedOperationStore`, but for operations a
    connected wallet will sign and send. ``peek`` is used to describe the intent
    without consuming it; ``take`` is used when a submitted hash is verified, so
    a single authorization verifies at most one submission.
    """

    def __init__(self, max_entries: int = 128, ttl_seconds: float = 300.0, clock=None) -> None:
        import threading
        import time

        self._lock = threading.Lock()
        self._entries: "OrderedDict[str, tuple[float, str, PreparedWalletOperation]]" = OrderedDict()
        self._max = max(1, int(max_entries))
        self._ttl = max(1.0, float(ttl_seconds))
        self._clock = clock or time.monotonic

    def _prune(self) -> None:
        now = self._clock()
        for key in [k for k, (at, _, _) in self._entries.items() if now - at > self._ttl]:
            self._entries.pop(key, None)
        while len(self._entries) > self._max:
            self._entries.popitem(last=False)

    def store(self, prepared: PreparedWalletOperation, owner: str) -> str:
        import secrets

        prepare_id = "wprep_" + secrets.token_urlsafe(18)
        with self._lock:
            self._entries[prepare_id] = (self._clock(), owner, prepared)
            self._prune()
        return prepare_id

    def peek(self, prepare_id: str, owner: str) -> PreparedWalletOperation | None:
        with self._lock:
            self._prune()
            entry = self._entries.get(prepare_id)
            if entry is None:
                return None
            _, entry_owner, prepared = entry
            if entry_owner != owner:
                return None
        return prepared

    def take(self, prepare_id: str, owner: str) -> PreparedWalletOperation | None:
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
        tee_authorizer: Any = None,
        tee_provider: Any = None,
    ) -> None:
        self.guard = guard
        self.config = config
        self.rpc = rpc or NearRpc(config)
        # The TEE trust boundary. When present, a transaction cannot be signed
        # unless a verified hardware attestation is bound to it. When absent the
        # boundary behaves exactly as before; enabling it is an operator decision
        # (``TRACESETTLE_NEAR_TEE_REQUIRED=1``).
        self.tee_authorizer = tee_authorizer
        self.tee_provider = tee_provider

    @property
    def tee_required(self) -> bool:
        return bool(self.tee_authorizer is not None and self.tee_authorizer.require_attestation)

    def _transaction_digest(self, transaction: Any) -> str:
        """The exact digest a TEE binding commits to: the bytes to be signed.

        ``unsigned_bytes`` is precisely what the wallet signs, so the digest
        covers the signer, public key, nonce, receiver, block hash and every
        action (including the encoded transfer amount). A substitution that does
        not change the signed bytes is not a substitution at all, and one that
        does always changes the digest.
        """
        return transaction.unsigned_bytes().hex()

    def _new_execution_record(self, prepared: Any) -> Any:
        """Record the authorized execution so the TEE gate has something to bind."""
        if self.tee_authorizer is None:
            return None
        tx = prepared.transaction
        authorization = prepared.authorization
        nonce = str(getattr(authorization, "nonce", "") or "")
        policy_version = str(getattr(authorization, "version", "") or "")
        record = self.tee_authorizer.create(
            service_id=tx.service_id,
            network=self.config.network.value,
            transaction_digest=self._transaction_digest(tx),
            signer_id=tx.signer_id,
            receiver_id=tx.receiver_id,
            operation=tx.guard_operation,
            asset=tx.guard_asset,
            amount=str(from_base_units(tx.amount_base, tx.asset)),
            destination=tx.destination,
            authorization_id=prepared.authorization_id,
            authorization_nonce=nonce,
            policy_version=policy_version,
        )
        prepared.execution_id = record.execution_id
        return record

    def verify_tee_attestation(self, prepared: Any) -> Any:
        """Fetch a genuine attestation and bind it to the prepared transaction.

        This is the step that makes the TEE participate in execution: without a
        verified, bound attestation the boundary will refuse to accept a
        signature. It fails closed - a provider error or a failed verification
        raises and the record is moved to ``TEE_VERIFICATION_FAILED``.
        """
        if self.tee_authorizer is None or self.tee_provider is None:
            raise ExecutionError(
                "TEE attestation is not available on this deployment; refusing to claim "
                "a verified execution"
            )
        record = self.tee_authorizer.get(prepared.execution_id)
        if record is None:
            raise ExecutionError("no execution record to bind an attestation to")
        from .attestation import derive_nonce

        nonce = derive_nonce(
            transaction_fingerprint=record.execution_digest,
            policy_revision=record.policy_version,
            operation_id=record.execution_id,
        )
        prepared.tee_nonce = nonce.hex()
        self.tee_authorizer.begin_verification(record.execution_id, expected_nonce=nonce.hex())
        attestation = self.tee_provider.attest(nonce)
        try:
            bound = self.tee_authorizer.bind_attestation(
                record.execution_id,
                attestation,
                expected_nonce=nonce.hex(),
                expected_transaction_digest=record.transaction_digest,
            )
        except TeeExecutionError as exc:
            raise ExecutionError(str(exc)) from exc
        prepared.tee_binding = bound.tee_binding
        return bound

    def _enforce_tee(self, prepared: Any, *, consume_record: bool = False) -> None:
        """The TEE gate. Called immediately before a signature is accepted."""
        if self.tee_authorizer is None:
            return
        execution_id = getattr(prepared, "execution_id", None)
        if not execution_id:
            raise ExecutionError(
                "no execution record was created for this operation; refusing to sign"
            )
        try:
            self.tee_authorizer.enforce(
                execution_id,
                transaction_digest=self._transaction_digest(prepared.transaction),
            )
            if consume_record:
                self.tee_authorizer.begin_signing(execution_id)
        except TeeExecutionError as exc:
            raise ExecutionError(str(exc)) from exc

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

    def _read_access_key(self, account_id: str, public_key: str) -> dict[str, Any]:
        """Read the signer's access key view, failing closed on any doubt.

        A missing key is ``NOT_FOUND``; a node outage is an outage. Neither is
        ever treated as "fine, proceed".
        """
        result = self.rpc.view_access_key(account_id, public_key)
        if result.status is SourceStatus.NOT_FOUND:
            raise ExecutionError(
                "the supplied public key is not an access key of the signer account"
            )
        if not result.ok or not isinstance(result.data, dict):
            raise ExecutionError("could not read the signer account's access key")
        return result.data

    def _next_nonce(self, account_id: str, public_key: str) -> int:
        data = self._read_access_key(account_id, public_key)
        nonce = data.get("nonce")
        if not isinstance(nonce, int):
            raise ExecutionError("the access key returned no nonce")
        return next_nonce(nonce)

    def _validate_access_key_permission(
        self, transaction: NearTransaction, access_key: dict[str, Any]
    ) -> Any:
        """Require the key's **on-chain** permission to cover this transaction.

        The nonce read already proves the key exists on the signer account. This
        additionally reads the key's declared permission and refuses when the
        transaction is outside it: a function-call key cannot move native NEAR,
        and cannot call a method or receiver outside its scope. An unrecognised
        permission shape is treated as unrestricted by the analysis, which is
        *not* a safe basis to sign - so it is refused here. Returns the analysis
        so the caller can record what was checked.
        """
        try:
            analysis = parse_access_key(access_key)
        except ValueError as exc:
            raise ExecutionError(f"the access key permission could not be read: {exc}") from exc

        if analysis.permission is AccessKeyPermission.UNKNOWN:
            raise ExecutionError(
                "the access key permission shape is not recognised; refusing to sign "
                "with a key whose scope cannot be established"
            )

        # Only a native transfer moves NEAR. An ``ft_transfer`` attaches the
        # conventional single yoctoNEAR storage deposit, which a function-call
        # key is designed to do; it does not move value.
        moves_near = transaction.operation == OP_TRANSFER
        method_name = "ft_transfer" if transaction.operation == OP_FT_TRANSFER else None
        allowed, reason = key_supports_operation(
            analysis,
            operation="TRANSFER" if transaction.operation == OP_TRANSFER else "FUNCTION_CALL",
            receiver_id=transaction.receiver_id,
            method_name=method_name,
            transfers_near=moves_near,
        )
        if not allowed:
            raise ExecutionError(
                f"the access key does not permit this transaction: {reason}"
            )
        return analysis

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
        access_key = self._read_access_key(account_id, public_key)
        nonce_value = access_key.get("nonce")
        if not isinstance(nonce_value, int):
            raise ExecutionError("the access key returned no nonce")
        nonce = next_nonce(nonce_value)
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

        # 3b. The key's on-chain permission must cover this exact transaction,
        #     or nothing downstream may sign it.
        self._validate_access_key_permission(tx, access_key)

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
            # Bind the exact bytes that will be signed, so the authorization
            # covers the transaction itself and not merely its summary.
            transaction_digest=tx.payload_fingerprint(),
        )
        decision = self.guard.evaluate(request)

        authorization = None
        authorization_id = None
        if decision.decision is Decision.ALLOW and decision.authorization is not None:
            authorization = decision.authorization
            authorization_id = getattr(authorization, "authorization_id", None)

        prepared = PreparedOperation(
            network=self.config.network,
            transaction=tx,
            decision=decision,
            authorization=authorization,
            authorization_id=authorization_id,
            # The binding is recomputed from the *final* transaction, so it is
            # exactly the parameter set a signature will be checked against.
            binding=tx.guard_canonical_fields(),
        )
        # When the TEE gate is on, an authorized operation gets an execution
        # record immediately, so the attestation has an exact digest to bind to.
        if prepared.authorized and self.tee_authorizer is not None:
            self._new_execution_record(prepared)
        return prepared

    # -- signing boundary --------------------------------------------------

    # -- wallet-mediated flow (the wallet signs and sends) -----------------

    def prepare_wallet_operation(
        self,
        *,
        service_id: str,
        account_id: str,
        receiver_id: str,
        asset_identifier: str,
        amount_human: str | Decimal,
        operation: str | None = None,
        network: str | NearNetwork | None = None,
        memo: str | None = None,
        gas: int = DEFAULT_FT_TRANSFER_GAS,
        simulated: bool = False,
        request_id: str | None = None,
        idempotency_key: str | None = None,
        policy_action: str | None = None,
    ) -> PreparedWalletOperation:
        """Authorize an operation a **connected wallet** will sign and send.

        TraceSettle does not build the transaction here (the wallet owns its own
        nonce and block hash); it binds the authorization to the *intent* - the
        signer, the receiver, the operation, the amount and the recipient - and
        returns the exact request the wallet must approve. Nothing is signed or
        broadcast by this server.
        """
        requested = parse_network(network)
        if requested is not self.config.network:
            raise ExecutionError(
                f"this server is configured for {self.config.network.value}; "
                f"refusing a {requested.value} operation"
            )
        self.verify_network()

        try:
            asset = resolve_asset(self.config.network, asset_identifier)
        except AssetError as exc:
            raise ExecutionError(str(exc)) from exc
        self._verify_asset_decimals(asset)

        amount = parse_amount(amount_human) if not isinstance(amount_human, Decimal) else amount_human
        amount_base = to_base_units(amount, asset)
        if amount_base <= 0:
            raise ExecutionError("the amount must be greater than zero")

        if asset.is_native:
            guard_operation = "WITHDRAWAL"
            wallet_request = {
                "signerId": account_id,
                "receiverId": receiver_id,
                "actions": [{"type": "Transfer", "params": {"deposit": str(amount_base)}}],
            }
        else:
            guard_operation = "WITHDRAWAL"
            args: dict[str, Any] = {"receiver_id": receiver_id, "amount": str(amount_base)}
            if memo is not None:
                args["memo"] = memo
            wallet_request = {
                "signerId": account_id,
                "receiverId": asset.contract or "",
                "actions": [{
                    "type": "FunctionCall",
                    "params": {
                        "methodName": "ft_transfer",
                        "args": args,
                        "gas": str(gas),
                        "deposit": "1",
                    },
                }],
            }

        request = TransactionRequest(
            request_id=request_id or f"near-wallet-{service_id}",
            service_id=service_id,
            operation=operation or guard_operation,
            chain=guard_chain_for(self.config.network),
            asset=asset.identifier.upper(),
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

        prepared = PreparedWalletOperation(
            network=self.config.network,
            account_id=account_id,
            receiver_id=wallet_request["receiverId"],
            operation=OP_TRANSFER if asset.is_native else OP_FT_TRANSFER,
            asset=asset,
            amount_base=amount_base,
            amount_human=from_base_units(amount_base, asset),
            destination=receiver_id,
            decision=decision,
            wallet_request=wallet_request,
            authorization=authorization,
            authorization_id=authorization_id,
        )
        prepared.binding = self.wallet_binding_fields(prepared)
        return prepared

    def wallet_binding_fields(self, prepared: PreparedWalletOperation) -> dict[str, str]:
        """The canonical parameter set a wallet operation's authorization covers."""
        return canonical_fields(
            service_id=self._wallet_service_id(prepared),
            operation="WITHDRAWAL",
            chain=guard_chain_for(prepared.network),
            asset=prepared.asset.identifier.upper(),
            amount=from_base_units(prepared.amount_base, prepared.asset),
            destination=prepared.destination,
        )

    @staticmethod
    def _wallet_service_id(prepared: PreparedWalletOperation) -> str:
        return prepared.decision.request.service_id if prepared.decision.request else ""

    def verify_wallet_submission(
        self, prepared: PreparedWalletOperation, tx_hash: str
    ) -> SettlementVerification:
        """Verify a wallet-submitted transaction against the authorized intent.

        The wallet has already signed and broadcast, so there are no bytes to
        bind at this point. What is checked is that the authorization still
        covers the intent (consuming the single-use nonce, so one authorization
        verifies at most one submission) and that the on-chain record matches the
        intent: signer, receiver, operation, amount and recipient. A wallet or
        provider ``SUCCESS`` alone never establishes ``VERIFIED``.
        """
        if not prepared.authorized:
            raise ExecutionError(
                f"refusing to verify: the decision was {prepared.decision.decision.value}"
            )
        expected = fingerprint_of(self.wallet_binding_fields(prepared))
        verification = self.guard.authority.validate(
            prepared.authorization,
            expected=expected,
            consume=True,
            expected_service_id=self._wallet_service_id(prepared) or None,
        )
        if not verification.valid:
            raise ExecutionError(
                "the authorization does not cover this operation "
                f"({verification.state.value}); refusing"
            )
        intended = IntendedOperation(
            network=prepared.network,
            signer_id=prepared.account_id,
            operation=prepared.operation,
            receiver_id=prepared.receiver_id,
            amount_base=prepared.amount_base,
            destination=prepared.destination,
            contract=prepared.asset.contract,
        )
        result = self.rpc.tx_status(tx_hash, prepared.account_id)
        return verify_intent(intended=intended, result=result.data, source_status=result.status)

    def wallet_execution_info(self) -> dict[str, Any]:
        """Describe the wallet flow for the UI. Holds no key and never signs."""
        from .assets import supported_assets

        return {
            "enabled": True,
            "mode": "wallet",
            "network": self.config.network.value,
            "signs": False,
            "broadcasts": False,
            "supported_operations": [
                {
                    "operation": "NATIVE_TRANSFER",
                    "asset": "near:native",
                    "description": "Native NEAR transfer (a plain Transfer action).",
                },
                {
                    "operation": "NEP141_TRANSFER",
                    "asset_identifier_template": "near:<contract>",
                    "description": "NEP-141 ft_transfer call on the token contract.",
                },
            ],
            "supported_assets": [
                {
                    "identifier": a.identifier,
                    "symbol": a.symbol,
                    "decimals": a.decimals,
                    "name": a.name,
                }
                for a in supported_assets(self.config.network)
            ],
            "note": (
                "The connected wallet signs and sends the transaction. This "
                "boundary authorizes the intent, binds it to the transaction, and "
                "independently verifies the on-chain result. It holds no key."
            ),
            "explorer": {
                "testnet": "https://testnet.nearblocks.io/txns/",
                "mainnet": "https://nearblocks.io/txns/",
            },
        }

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
        Refuses if the operation was not authorized, if the signature is malformed
        or does not verify against the transaction hash and the signer's public
        key, or if the authorization does not cover the final transaction.

        The order is deliberate. The signature is decoded and verified *first* -
        that is non-destructive, so a malformed or wrong-transaction signature is
        refused without spending the authorization's single-use nonce, leaving the
        caller free to sign the correct transaction. Only after the signature
        verifies do the destructive checks run: the TEE gate (which moves the
        execution record to ``SIGNING_PENDING``, the only door to signing), then
        the authorization consume. A binding mismatch is refused *before* the
        nonce is consumed, so a tampered transaction cannot burn the authorization
        either.
        """
        # 1. Decode and verify the signature first. These checks touch no
        #    single-use state, so a bad signature leaves the authorization intact.
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

        # 2. Destructive checks last. The TEE gate runs before the authorization
        #    nonce is consumed, so a transaction without a verified, bound
        #    attestation cannot even spend the single-use authorization - let
        #    alone reach the network.
        self._enforce_tee(prepared, consume_record=True)
        self.verify_binding(prepared, consume=True)
        return prepared.transaction.signed_b64(raw), raw

    def broadcast(self, prepared: PreparedOperation, signature_b64: str) -> ExecutedOperation:
        """Validate the signature, submit, and independently verify settlement."""
        signed_b64, _ = self.accept_signature(prepared, signature_b64)
        if self.tee_authorizer is not None and prepared.execution_id:
            self.tee_authorizer.record_state(
                prepared.execution_id, ExecutionState.SIGNED, reason="signature accepted"
            )
        result = self.rpc.send_tx(signed_b64, wait_until="INCLUDED_FINAL")
        if self.tee_authorizer is not None and prepared.execution_id:
            self.tee_authorizer.record_state(
                prepared.execution_id, ExecutionState.SUBMITTED, reason="broadcast attempted"
            )
        verification = verify_transaction(
            transaction=prepared.transaction,
            result=result.data,
            source_status=result.status,
        )
        if self.tee_authorizer is not None and prepared.execution_id:
            self._record_settlement_state(prepared.execution_id, verification)
        return ExecutedOperation(
            state=verification.state,
            tx_hash=prepared.transaction.tx_hash,
            verification=verification,
            receipt={
                "endpoint": result.endpoint,
                "explorer_url": self.config.explorer_url(prepared.transaction.tx_hash),
            },
        )

    def _record_settlement_state(self, execution_id: str, verification: Any) -> None:
        """Map a settlement verdict onto the lifecycle state, never upward."""
        from .verify import SettlementState

        record = self.tee_authorizer.get(execution_id)
        if record is None:
            return
        try:
            if verification.state is SettlementState.VERIFIED:
                # INCLUDED is the necessary predecessor of a verified settlement.
                if can_transition(record.state, ExecutionState.INCLUDED):
                    self.tee_authorizer.record_state(
                        execution_id, ExecutionState.INCLUDED, reason="included on-chain"
                    )
                self.tee_authorizer.record_state(
                    execution_id,
                    ExecutionState.SETTLEMENT_VERIFIED,
                    reason="independent verification",
                )
            elif verification.state is SettlementState.FAILED:
                self.tee_authorizer.record_state(
                    execution_id, ExecutionState.SETTLEMENT_FAILED, reason="settlement failed"
                )
            else:
                self.tee_authorizer.record_state(
                    execution_id,
                    ExecutionState.SETTLEMENT_UNKNOWN,
                    reason=f"settlement not established ({verification.state.value})",
                )
        except IllegalTransition:
            # A state already terminal (e.g. a retried broadcast) is left as-is;
            # the verification result is still returned to the caller.
            pass
        self.tee_authorizer.record_settlement(execution_id, verification.to_dict())

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
