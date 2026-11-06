"""OutLayer Agent Custody provider adapter.

OutLayer holds a wallet's signing key inside an Intel TDX enclave and signs on
request; the key never leaves the enclave and no private key exists for the
application to hold. TraceSettle uses OutLayer as its **custody/signing
provider**: the operator configures one wallet server-side, and TraceSettle's
own authorization firewall decides whether an operation may be sent at all.

Scope, stated honestly:

* This adapter signs and broadcasts a NEAR transfer through OutLayer. It does
  **not** obtain a per-operation Intel TDX quote: the Agent Custody API exposes
  no attestation for wallet signing (only the separate HTTPS WASM *compute* path
  is per-execution attested). What can be verified independently is the worker
  registration on chain - the approved TDX measurement set on
  ``worker.outlayer.testnet`` - which this module reads. That is real evidence
  that the operator approves a measured build, not a claim that this specific
  signature was produced inside it.
* A provider ``status == "success"`` is a **provider claim**. Settlement is
  established only by the independent NEAR RPC verification in
  :mod:`tracesettle.near.outlayer_execution`, never by this field.

Configuration is server-side only. The API key is read from the environment by
:class:`OutLayerConfig`, is sent only as an ``Authorization: Bearer`` header,
and is never returned, logged, or placed in an error message.

The endpoints used are exactly those documented at
``https://app.outlayer.ai/docs/agent-custody`` and in the published OpenAPI
spec (``https://testnet-api.outlayer.ai/openapi.json``): ``POST /wallet/v1/transfer``,
``GET /wallet/v1/address``, ``GET /wallet/v1/balance``, ``GET /wallet/v1/requests/{id}``,
``GET /wallet/v1/audit``. Nothing here is invented.
"""

from __future__ import annotations

import enum
import hashlib
import json
import re
import secrets
from dataclasses import dataclass, field
from typing import Any

from ..httpclient import HttpClient
from ..model import SourceStatus

#: The only host this adapter will send an API key to, per network. The key is
#: network-scoped at OutLayer, so a key minted on testnet means nothing on
#: mainnet and vice versa; the host is the network selector, not a parameter.
OUTLAYER_HOSTS: dict[str, str] = {
    "testnet": "https://testnet-api.outlayer.ai",
    "mainnet": "https://api.outlayer.ai",
}

#: NEAR yoctoNEAR per whole NEAR.
YOCTO_PER_NEAR = 10**24

#: A wallet id is a UUID; a NEAR account id is a bounded string. Both are
#: validated so a malformed or substituted identity is refused before use.
_WALLET_ID_RE = re.compile(r"^[0-9a-fA-F-]{36}$")
_NEAR_ACCOUNT_RE = re.compile(r"^[a-z0-9][a-z0-9._-]{0,63}$")
_HEX64_RE = re.compile(r"^[0-9a-fA-F]{64}$")
#: A NEAR transaction hash is a 32-byte value in **base58**, 43-44 characters.
_B58_ALPHABET = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz"


def _is_near_tx_hash(value: Any) -> bool:
    """True when ``value`` is a base58-encoded 32-byte NEAR transaction hash."""
    if not isinstance(value, str) or not (43 <= len(value) <= 44):
        return False
    n = 0
    for ch in value:
        idx = _B58_ALPHABET.find(ch)
        if idx < 0:
            return False
        n = n * 58 + idx
    # A 32-byte value decodes to at most 2**256 - 1.
    return n < (1 << 256)


class OutLayerError(ValueError):
    """A configuration or provider error that must never be worked around."""


class OutLayerUnavailable(OutLayerError):
    """The provider could not be reached, or answered unusably."""


class ProviderState(str, enum.Enum):
    """What a provider request resolved to.

    The vocabulary is deliberately the same as the rest of the product's:
    ``success`` is a *provider claim*; ``unknown`` means the outcome could not be
    established and the request must **not** be blindly resubmitted.
    """

    SUCCESS = "success"
    PENDING = "pending"
    PROCESSING = "processing"
    PENDING_APPROVAL = "pending_approval"
    FAILED = "failed"
    REFUNDED = "refunded"
    REJECTED = "rejected"
    UNKNOWN = "unknown"


#: Provider statuses that are terminal.
_TERMINAL = frozenset(
    {
        ProviderState.SUCCESS,
        ProviderState.FAILED,
        ProviderState.REJECTED,
        ProviderState.REFUNDED,
    }
)

#: Provider statuses that are not terminal and may be polled.
_IN_FLIGHT = frozenset(
    {ProviderState.PENDING, ProviderState.PROCESSING, ProviderState.PENDING_APPROVAL}
)

#: The provider's documented ``RequestStatus`` enum, mapped onto the local
#: vocabulary. Every value the OpenAPI document lists is present, so a status the
#: provider genuinely returns is never silently read as ``UNKNOWN``.
#:
#: ``completed`` is the provider's terminal *success* synonym (its own idempotency
#: documentation groups ``success``/``completed`` together as the terminal success
#: states), so it maps to ``SUCCESS``; ``approved`` is the in-flight state after a
#: multisig approval, so it maps to ``PROCESSING``; ``cancelled`` is terminal and
#: never executed, so it maps to ``REJECTED``; ``needs_review`` is terminal but
#: unresolved and is deliberately left as ``UNKNOWN`` - never a success, never a
#: plain failure. A status outside this map still resolves to ``UNKNOWN``.
_STATUS_MAP: dict[str, ProviderState] = {
    "success": ProviderState.SUCCESS,
    "completed": ProviderState.SUCCESS,
    "failed": ProviderState.FAILED,
    "partially_failed": ProviderState.FAILED,
    "rejected": ProviderState.REJECTED,
    "cancelled": ProviderState.REJECTED,
    "refunded": ProviderState.REFUNDED,
    "pending": ProviderState.PENDING,
    "pending_deposit": ProviderState.PROCESSING,
    "processing": ProviderState.PROCESSING,
    "approved": ProviderState.PROCESSING,
    "pending_approval": ProviderState.PENDING_APPROVAL,
    "needs_review": ProviderState.UNKNOWN,
}


def provider_state(raw: Any) -> ProviderState:
    """Map a provider status string onto :class:`ProviderState`.

    Every status the provider's OpenAPI document lists is mapped (see
    :data:`_STATUS_MAP`), so a status the provider genuinely returns is not read
    as ``UNKNOWN``. A status outside that set is ``UNKNOWN`` - never ``SUCCESS``.
    A provider that starts returning a new status word must not be read as a
    completed operation.
    """
    if not isinstance(raw, str):
        return ProviderState.UNKNOWN
    return _STATUS_MAP.get(raw.strip().lower(), ProviderState.UNKNOWN)


def is_terminal(state: ProviderState) -> bool:
    return state in _TERMINAL


def is_in_flight(state: ProviderState) -> bool:
    return state in _IN_FLIGHT


@dataclass(frozen=True)
class OutLayerConfig:
    """Server-side provider configuration.

    Built from the environment by :func:`config_from_env`. The API key is
    required: a configured provider without a key is a hard failure, never a
    silent fallback to an unauthenticated call.
    """

    api_key: str
    network: str = "testnet"
    wallet_id: str = ""
    timeout: float = 30.0

    def __post_init__(self) -> None:
        if not self.api_key or not isinstance(self.api_key, str):
            raise OutLayerError("an OutLayer API key is required (TRACESETTLE_OUTLAYER_API_KEY)")
        if not self.api_key.startswith("wk_"):
            raise OutLayerError("the OutLayer API key must be a 'wk_' bearer key")
        if self.network not in OUTLAYER_HOSTS:
            raise OutLayerError(
                f"unsupported OutLayer network {self.network!r}; "
                f"expected one of {sorted(OUTLAYER_HOSTS)}"
            )
        if self.wallet_id and not _WALLET_ID_RE.match(self.wallet_id):
            raise OutLayerError("the configured OutLayer wallet id is malformed")

    @property
    def base_url(self) -> str:
        return OUTLAYER_HOSTS[self.network]

    @property
    def is_testnet(self) -> bool:
        return self.network == "testnet"

    def to_dict(self) -> dict[str, Any]:
        """A serialisable view that never contains the API key."""
        return {
            "provider": "outlayer",
            "network": self.network,
            "base_url": self.base_url,
            "wallet_id": self.wallet_id or None,
            "is_testnet": self.is_testnet,
            "configured": True,
        }


@dataclass
class ProviderOutcome:
    """The result of one provider request, with the raw evidence preserved."""

    state: ProviderState
    request_id: str | None
    tx_hash: str | None
    raw_status: str
    http_status: int | None = None
    detail: str = ""
    #: The provider's own ``request_hash`` (present on ``pending_approval``).
    request_hash: str | None = None
    #: A per-operation attestation, when the provider supplies one. OutLayer's
    #: Agent Custody signing API does not, so this is normally ``None`` - and a
    #: ``None`` attestation never becomes a TEE claim.
    attestation: dict[str, Any] | None = None
    #: The unmodified provider body, kept for independent investigation.
    evidence: dict[str, Any] = field(default_factory=dict)

    @property
    def claimed_success(self) -> bool:
        return self.state is ProviderState.SUCCESS

    def to_dict(self) -> dict[str, Any]:
        return {
            "state": self.state.value,
            "request_id": self.request_id,
            "tx_hash": self.tx_hash,
            "raw_status": self.raw_status,
            "http_status": self.http_status,
            "detail": self.detail,
            "request_hash": self.request_hash,
            "claimed_success": self.claimed_success,
        }


@dataclass
class WalletIdentity:
    wallet_id: str
    network: str
    account_id: str
    public_key: str

    def to_dict(self) -> dict[str, Any]:
        return {
            "wallet_id": self.wallet_id,
            "network": self.network,
            "account_id": self.account_id,
            "public_key": self.public_key,
        }


class OutLayerCustodyProvider:
    """A thin, honest client for the OutLayer Agent Custody API.

    Every method returns a typed outcome or raises :class:`OutLayerError`. A
    network failure is never turned into a success, and a request whose outcome
    is unknown is reported as ``UNKNOWN`` rather than retried blindly.
    """

    def __init__(self, config: OutLayerConfig, *, client: HttpClient | None = None) -> None:
        self.config = config
        self._client = client if client is not None else HttpClient(timeout=config.timeout)

    # -- internals ----------------------------------------------------------

    def _headers(self) -> dict[str, str]:
        # The key travels only here, only as a bearer header. It is never placed
        # in a URL (so it cannot reach a proxy log) or in a response body.
        return {"Authorization": f"Bearer {self.config.api_key}"}

    def _url(self, path: str) -> str:
        return f"{self.config.base_url}{path}"

    @staticmethod
    def _request_id(payload: Any) -> str | None:
        if isinstance(payload, dict):
            value = payload.get("request_id")
            if isinstance(value, str) and value.strip():
                return value.strip()
        return None

    @staticmethod
    def _tx_hash(payload: Any) -> str | None:
        """The transaction hash, from the top level or the nested ``result``.

        ``/wallet/v1/transfer`` returns ``tx_hash`` at the top level; a polled
        ``/wallet/v1/requests/{id}`` nests it under ``result``. Both are read so
        the hash is never lost to a response-shape difference.
        """
        if not isinstance(payload, dict):
            return None
        for container in (payload, payload.get("result")):
            if not isinstance(container, dict):
                continue
            for key in ("tx_hash", "transaction_hash"):
                value = container.get(key)
                if _is_near_tx_hash(value):
                    return value.strip()
        return None

    def _outcome_from(self, result: Any, *, expect_hash: bool) -> ProviderOutcome:
        """Turn a :class:`FetchResult` into a :class:`ProviderOutcome`.

        A transport failure yields ``UNKNOWN`` with the request id when one can
        still be read - that is what lets a caller resolve the outcome from the
        chain instead of resubmitting.
        """
        if result.status is SourceStatus.OK and isinstance(result.data, dict):
            raw_status = str(result.data.get("status", "")).strip().lower()
            state = provider_state(raw_status)
            return ProviderOutcome(
                state=state,
                request_id=self._request_id(result.data),
                tx_hash=self._tx_hash(result.data),
                raw_status=raw_status,
                http_status=result.http_status,
                detail="provider response",
                request_hash=(
                    str(result.data.get("request_hash"))
                    if isinstance(result.data.get("request_hash"), str)
                    else None
                ),
                attestation=(
                    result.data.get("attestation")
                    if isinstance(result.data.get("attestation"), dict)
                    else None
                ),
                evidence=dict(result.data),
            )
        if result.status is SourceStatus.TIMEOUT or result.status is SourceStatus.NETWORK_ERROR:
            # The request may or may not have reached the provider. This is the
            # ambiguous case: the outcome is UNKNOWN and must be resolved by
            # request id, never by resubmitting.
            return ProviderOutcome(
                state=ProviderState.UNKNOWN,
                request_id=self._request_id(result.data),
                tx_hash=self._tx_hash(result.data),
                raw_status="",
                http_status=result.http_status,
                detail=(
                    "the provider did not answer; the operation's outcome is unknown "
                    "and must not be resubmitted"
                ),
            )
        if result.status is SourceStatus.UNAUTHORIZED:
            raise OutLayerError("the OutLayer API key was rejected (401)")
        return ProviderOutcome(
            state=ProviderState.UNKNOWN,
            request_id=self._request_id(result.data),
            tx_hash=self._tx_hash(result.data),
            raw_status="",
            http_status=result.http_status,
            detail=f"the provider answered unusably ({result.status.value})",
        )

    # -- read-only operations ----------------------------------------------

    def address(self, chain: str = "near") -> WalletIdentity:
        """Resolve the wallet's NEAR account and public key."""
        result = self._client.get_json(
            self._url("/wallet/v1/address"), {"chain": chain}, headers=self._headers()
        )
        if result.status is SourceStatus.UNAUTHORIZED:
            raise OutLayerError("the OutLayer API key was rejected (401)")
        if result.status is not SourceStatus.OK or not isinstance(result.data, dict):
            raise OutLayerUnavailable(
                f"could not read the OutLayer wallet address ({result.status.value})"
            )
        data = result.data
        wallet_id = str(data.get("wallet_id", "")).strip()
        account_id = str(data.get("address", "")).strip()
        public_key = str(data.get("public_key", "")).strip()
        if not account_id or not _NEAR_ACCOUNT_RE.match(account_id):
            raise OutLayerUnavailable("the provider returned a malformed NEAR account id")
        if self.config.wallet_id and wallet_id and wallet_id != self.config.wallet_id:
            # A configured wallet id that does not match the key is a
            # misconfiguration: refuse rather than sign for the wrong wallet.
            raise OutLayerError(
                "the configured wallet id does not match the wallet the API key resolves to"
            )
        return WalletIdentity(
            wallet_id=wallet_id, network=self.config.network, account_id=account_id, public_key=public_key
        )

    def balance(self, chain: str = "near") -> int:
        """The wallet's native balance, in yoctoNEAR. An unreadable balance is an error."""
        result = self._client.get_json(
            self._url("/wallet/v1/balance"), {"chain": chain}, headers=self._headers()
        )
        if result.status is SourceStatus.UNAUTHORIZED:
            raise OutLayerError("the OutLayer API key was rejected (401)")
        if result.status is not SourceStatus.OK or not isinstance(result.data, dict):
            raise OutLayerUnavailable(f"could not read the OutLayer wallet balance ({result.status.value})")
        raw = result.data.get("balance")
        try:
            return int(str(raw))
        except (TypeError, ValueError) as exc:
            raise OutLayerUnavailable("the provider returned a non-numeric balance") from exc

    def policy(self) -> dict[str, Any]:
        """The wallet's current policy, verbatim. Never interpreted as approval."""
        result = self._client.get_json(self._url("/wallet/v1/policy"), None, headers=self._headers())
        if result.status is not SourceStatus.OK or not isinstance(result.data, dict):
            return {"available": False, "source_status": result.status.value}
        return {"available": True, **result.data}

    def request_status(self, request_id: str) -> ProviderOutcome:
        """Poll one request by id. This is how an unknown outcome is resolved."""
        if not request_id or not isinstance(request_id, str):
            raise OutLayerError("a request id is required to poll a request")
        result = self._client.get_json(
            self._url(f"/wallet/v1/requests/{request_id}"), None, headers=self._headers()
        )
        return self._outcome_from(result, expect_hash=True)

    def audit(self) -> list[dict[str, Any]]:
        """The provider's audit events, verbatim, for independent investigation."""
        result = self._client.get_json(self._url("/wallet/v1/audit"), None, headers=self._headers())
        if result.status is not SourceStatus.OK or not isinstance(result.data, dict):
            return []
        events = result.data.get("events")
        return list(events) if isinstance(events, list) else []

    # -- the signing operation ---------------------------------------------

    def transfer(self, *, to: str, amount_yocto: int, idempotency_key: str | None = None) -> ProviderOutcome:
        """Send a native NEAR transfer through the TEE custody wallet.

        This is the only operation the execution boundary calls, and it is
        reached only after TraceSettle's own controls returned ALLOW. The
        ``X-Idempotency-Key`` header makes a retried *identical* request
        idempotent at the provider; it is supplied by the caller, which derives
        it from the authorized operation so the same operation cannot be sent
        twice under different keys.
        """
        if not _NEAR_ACCOUNT_RE.match(to or ""):
            raise OutLayerError("the transfer recipient is not a valid NEAR account id")
        if not isinstance(amount_yocto, int) or amount_yocto <= 0:
            raise OutLayerError("the transfer amount must be a positive integer of yoctoNEAR")
        headers = self._headers()
        if idempotency_key:
            headers = {**headers, "X-Idempotency-Key": str(idempotency_key)}
        result = self._client.post_json(
            self._url("/wallet/v1/transfer"),
            {"chain": "near", "to": to, "amount": str(amount_yocto)},
            headers=headers,
        )
        return self._outcome_from(result, expect_hash=True)

    # -- independent TEE evidence ------------------------------------------

    def approved_measurements(self) -> dict[str, Any]:
        """Read the register-contract's admin-approved TDX measurement set.

        This is the on-chain trust anchor for the OutLayer enclave fleet: the
        contract at ``worker.outlayer.{testnet,near}`` holds the TDX measurements
        (MRTD + RTMR0-3) that its owner has approved, and a worker can only
        register a key if its attestation quote matches one of them. Reading it
        is a real, independent check - it does not require trusting a
        ``verified: true`` field - but it proves *which builds are approved*, not
        that a given signature came from one.
        """
        account = (
            "worker.outlayer.testnet" if self.config.is_testnet else "worker.outlayer.near"
        )
        rpc_url = (
            "https://rpc.testnet.fastnear.com" if self.config.is_testnet else "https://rpc.mainnet.fastnear.com"
        )
        result = self._client.post_json(
            rpc_url,
            {
                "jsonrpc": "2.0",
                "id": "tracesettle-outlayer",
                "method": "query",
                "params": {
                    "request_type": "call_function",
                    "finality": "final",
                    "account_id": account,
                    "method_name": "get_approved_measurements",
                    "args_base64": "",
                },
            },
        )
        if result.status is not SourceStatus.OK or not isinstance(result.data, dict):
            return {"available": False, "source_status": result.status.value, "account": account}
        raw = result.data.get("result", {}).get("result")
        if not isinstance(raw, list):
            return {"available": False, "source_status": "MALFORMED", "account": account}
        try:
            measurements = json.loads(bytes(raw).decode("utf-8"))
        except (ValueError, UnicodeDecodeError):
            return {"available": False, "source_status": "MALFORMED", "account": account}
        count = len(measurements) if isinstance(measurements, list) else 0
        return {
            "available": True,
            "account": account,
            "count": count,
            "measurements": measurements if isinstance(measurements, list) else [],
        }


def config_from_env(environ: Any, *, guard_required: bool = True) -> OutLayerConfig | None:
    """Build a config from the environment, or ``None`` when OutLayer is off.

    Enabling OutLayer without an API key is a hard failure, never a silent
    fallback: an operator who asked for the provider must get the provider or a
    clear start-up error.
    """
    enabled = str(environ.get("TRACESETTLE_OUTLAYER_ENABLED", "")).strip().lower() in {
        "1",
        "true",
        "yes",
        "on",
    }
    if not enabled:
        return None
    api_key = str(environ.get("TRACESETTLE_OUTLAYER_API_KEY", "")).strip()
    if not api_key:
        raise OutLayerError(
            "TRACESETTLE_OUTLAYER_ENABLED is set but TRACESETTLE_OUTLAYER_API_KEY is empty; "
            "refusing to start without provider credentials"
        )
    network = str(environ.get("TRACESETTLE_OUTLAYER_NETWORK", "testnet")).strip() or "testnet"
    wallet_id = str(environ.get("TRACESETTLE_OUTLAYER_WALLET_ID", "")).strip()
    timeout_raw = str(environ.get("TRACESETTLE_OUTLAYER_TIMEOUT_SECONDS", "30")).strip() or "30"
    try:
        timeout = float(timeout_raw)
    except ValueError as exc:
        raise OutLayerError("TRACESETTLE_OUTLAYER_TIMEOUT_SECONDS must be a number") from exc
    return OutLayerConfig(api_key=api_key, network=network, wallet_id=wallet_id, timeout=timeout)


def idempotency_key_for(transaction_digest: str, *, salt: str = "") -> str:
    """A stable idempotency key for an authorized operation.

    Derived from the transaction digest, so the *same* authorized operation maps
    to the *same* key across retries - which is what makes the provider's
    idempotency meaningful - while a different operation gets a different key.
    """
    material = f"TRACESETTLE-OUTLAYER-IDEMPOTENCY-V1\x00{transaction_digest}\x00{salt}".encode()
    return hashlib.sha256(material).hexdigest()


def random_idempotency_key() -> str:
    """A fresh idempotency key, for a caller that has no digest to bind to."""
    return secrets.token_hex(16)
