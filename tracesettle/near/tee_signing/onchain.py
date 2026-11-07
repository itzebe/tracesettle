"""The **free** TEE signing route: OutLayer's on-chain ``request_execution``.

This is the route the Mission 25 live run proved works end to end. It is
different from :class:`tracesettle.near.tee_signing.provider.OutLayerSigningProvider`
in exactly one way that matters for cost: the HTTPS ``POST /call/{owner}/{project}``
path needs a prepaid **USD stablecoin** balance, while the on-chain
``outlayer.<net>.request_execution`` path is paid from the caller's **NEAR**
balance, and on testnet NEAR is free.

What the enclave does, and what it does not
-------------------------------------------

The enclave runs the TraceSettle guest module (``guest/signing-module``) inside
an Intel TDX TEE. The guest composes the NEAR ``sha256(borsh(Transaction))``
digest from the structured signing request and asks the ``outlayer:signing-keys``
host to sign it with a key that is **derived inside the enclave and never
leaves it**. The key is a normal NEAR ed25519 key, so the transaction it signs
is a real transaction the network accepts.

The honesty rules, unchanged from the rest of the product:

* A provider ``success`` is a **claim**. This module returns the enclave's own
  output; it does not, by itself, prove settlement. Settlement is established
  by the independent NEAR RPC verification elsewhere in the product.
* The signature is verified locally, over the exact digest, before it is
  returned — a signature that does not verify is refused, never returned.
* The caller's account seed is **never** held by this module. The caller passes
  a ``sign`` callable (see :class:`OnChainCaller`), so the private key stays with
  the caller and never enters the provider, a log, or a response.
* Nothing here is invented: every field read back (``execution_requested``,
  ``execution_completed``, ``SuccessValue``) is a documented OutLayer event or
  the NEAR RPC's own receipt outcome.
"""

from __future__ import annotations

import base64
import json
from dataclasses import dataclass
from typing import Any, Callable

from ...base58 import b58decode
from ...model import SourceStatus
from .. import borsh, ed25519
from ..rpc import NearRpc
from .provider import ProviderCapability, SigningResult, TeeProviderError, TeeProviderUnavailable
from .request import TeeSigningRequest

#: The OutLayer executor account, per network. Testnet is free; mainnet is not.
OUTLAYER_EXECUTORS: dict[str, str] = {
    "testnet": "outlayer.testnet",
    "mainnet": "outlayer.near",
}

#: The guest operation that returns the derived key without signing.
OP_PUBLIC_KEY = "public_key"

#: The default NEAR RPC per network.
DEFAULT_RPC: dict[str, str] = {
    "testnet": "https://rpc.testnet.near.org",
    "mainnet": "https://rpc.mainnet.near.org",
}


class OnChainTeeError(TeeProviderError):
    """A refusal or failure on the on-chain TEE signing path."""


@dataclass
class OnChainCaller:
    """The account that pays for and submits the ``request_execution`` call.

    The **private key is not here**: ``sign`` is a callable that takes the 32-byte
    transaction digest and returns the 64-byte ed25519 signature. The caller owns
    the key; this module never sees it, never stores it and never logs it.
    """

    account_id: str
    public_key: str  # "ed25519:<base58>"
    sign: Callable[[bytes], bytes]

    def public_key_raw(self) -> bytes:
        from ..tee_signing.boundary import _b58_decode

        return _b58_decode(self.public_key.split(":")[-1])


@dataclass
class OnChainTeeConfig:
    """Where the guest wasm lives and how much resource to buy for one run."""

    network: str = "testnet"
    wasm_url: str = ""
    #: The sha256 of the wasm bytes, hex. The worker refuses a file whose bytes
    #: do not match, so this is the approved-build identity.
    wasm_sha256: str = ""
    build_target: str = "wasm32-wasip2"
    rpc_url: str = ""
    max_instructions: int = 10_000_000_000
    max_memory_mb: int = 256
    max_execution_seconds: int = 30
    #: The NEAR attached to the call. Any unused amount is refunded to the caller
    #: (``payment_refunded`` in the ``execution_completed`` event), so a generous
    #: deposit costs nothing beyond what the run actually used.
    attach_yocto: int = 1_000_000_000_000_000_000_000_000
    #: The gas limit for the call. The executor compiles the wasm on the first
    #: run, so this is generous.
    gas: int = 300_000_000_000_000

    def executor(self) -> str:
        # Testnet only. The whole product refuses to sign for mainnet, and this
        # route is no exception: on mainnet the caller's NEAR is real money and
        # the enclave's key would be a real mainnet key, so it is refused here
        # rather than at the edge.
        if self.network == "mainnet":
            raise OnChainTeeError(
                "on-chain TEE signing is testnet-only; it will not sign for mainnet"
            )
        try:
            return OUTLAYER_EXECUTORS[self.network]
        except KeyError as exc:
            raise OnChainTeeError(f"no OutLayer executor is known for {self.network!r}") from exc

    def rpc(self) -> str:
        return self.rpc_url or DEFAULT_RPC.get(self.network, "")


def _extract_success_value(receipts_outcome: list[dict[str, Any]]) -> dict[str, Any] | None:
    """The guest's stdout: the final receipt's base64 ``SuccessValue``.

    OutLayer returns the WASM's stdout to the caller's receipt, so the *last*
    receipt that carries a JSON ``SuccessValue`` is the guest's answer.
    """
    answer: dict[str, Any] | None = None
    for ro in receipts_outcome:
        status = (ro.get("outcome") or {}).get("status")
        if not isinstance(status, dict):
            continue
        value = status.get("SuccessValue")
        if not isinstance(value, str) or not value:
            continue
        try:
            decoded = base64.b64decode(value).decode("utf-8")
            parsed = json.loads(decoded)
        except (ValueError, UnicodeDecodeError):
            continue
        if isinstance(parsed, dict) and "status" in parsed:
            answer = parsed
    return answer


def _extract_events(receipts_outcome: list[dict[str, Any]]) -> dict[str, Any]:
    """The OutLayer ``EVENT_JSON`` lifecycle events, keyed by event name."""
    events: dict[str, Any] = {}
    for ro in receipts_outcome:
        for line in (ro.get("outcome") or {}).get("logs", []):
            if not isinstance(line, str) or not line.startswith("EVENT_JSON:"):
                continue
            try:
                parsed = json.loads(line[len("EVENT_JSON:") :])
            except ValueError:
                continue
            name = parsed.get("event")
            if name and parsed.get("data"):
                events[name] = parsed["data"][0]
    return events


class OutLayerOnChainSigningProvider:
    """Sign through OutLayer's on-chain ``request_execution`` (free on testnet)."""

    def __init__(
        self,
        *,
        caller: OnChainCaller | None,
        config: OnChainTeeConfig,
        rpc: NearRpc | None = None,
    ) -> None:
        self._caller = caller
        self._config = config
        self._rpc = rpc or NearRpc(config.rpc())
        #: Filled by the last :meth:`sign`, for evidence. Public on purpose.
        self.last_run: dict[str, Any] = {}

    @property
    def name(self) -> str:
        return "outlayer:signing-keys-onchain"

    def capability(self) -> ProviderCapability:
        if self._caller is None:
            return ProviderCapability(
                provider=self.name,
                available=False,
                detail=(
                    "no caller account is configured; the on-chain TEE signing route "
                    "needs an account to submit request_execution (free on testnet)"
                ),
                requires_payment=False,
            )
        if not (self._config.wasm_url and self._config.wasm_sha256):
            return ProviderCapability(
                provider=self.name,
                available=False,
                detail=(
                    "the guest wasm url and its sha256 must both be configured; the "
                    "worker refuses a wasm whose bytes do not match the hash"
                ),
                requires_payment=False,
            )
        return ProviderCapability(
            provider=self.name,
            available=True,
            detail=(
                f"real Intel TDX enclave via {self._config.executor()}.request_execution; "
                f"paid in {self._config.network} NEAR"
            ),
            requires_payment=False,
        )

    # -- the enclave call ---------------------------------------------------

    def _call_args(self, input_data: str) -> dict[str, Any]:
        return {
            "source": {
                "WasmUrl": {
                    "url": self._config.wasm_url,
                    "hash": self._config.wasm_sha256,
                    "build_target": self._config.build_target,
                }
            },
            "resource_limits": {
                "max_instructions": self._config.max_instructions,
                "max_memory_mb": self._config.max_memory_mb,
                "max_execution_seconds": self._config.max_execution_seconds,
            },
            "input_data": input_data,
            "response_format": "Json",
        }

    def _submit(self, input_data: str) -> dict[str, Any]:
        """Build, sign and broadcast one ``request_execution``, return the outcome."""
        caller = self._caller
        if caller is None:
            raise TeeProviderUnavailable("no caller account is configured for the on-chain route")

        block = self._rpc.block_hash()
        if block.status is not SourceStatus.OK or not isinstance(block.data, dict):
            raise OnChainTeeError("the NEAR RPC did not return a block hash")
        block_hash = block.data.get("hash")
        if not isinstance(block_hash, str):
            raise OnChainTeeError("the NEAR RPC block hash was not a string")

        key = self._rpc.view_access_key(caller.account_id, caller.public_key)
        if key.status is not SourceStatus.OK or not isinstance(key.data, dict):
            raise OnChainTeeError("the caller's access key could not be read")
        nonce = int(key.data.get("nonce", 0)) + 1

        from ...base58 import b58decode

        raw_block = b58decode(block_hash)
        if raw_block is None or len(raw_block) != 32:
            raise OnChainTeeError("the NEAR RPC block hash was not 32 base58 bytes")

        args = self._call_args(input_data)
        action = borsh.action_function_call(
            "request_execution",
            json.dumps(args, separators=(",", ":")).encode("utf-8"),
            self._config.gas,
            self._config.attach_yocto,
        )
        tx = borsh.transaction(
            caller.account_id,
            caller.public_key_raw(),
            nonce,
            self._config.executor(),
            raw_block,
            (action,),
        )
        digest = borsh.transaction_hash(tx)
        signature = caller.sign(digest)
        if not ed25519.verify(signature, digest, caller.public_key_raw()):
            raise OnChainTeeError("the caller's own signature does not verify; refusing")
        signed = tx + borsh.signature_ed25519(signature)

        sent = self._rpc.send_tx(base64.b64encode(signed).decode("ascii"))
        if sent.status is not SourceStatus.OK or not isinstance(sent.data, dict):
            raise OnChainTeeError(
                f"the request_execution call was not accepted: {sent.error or sent.status}"
            )
        return sent.data

    def public_key(self) -> str:
        """Run the guest's ``public_key`` op and return the TEE-derived key.

        A driver calls this **first**: the enclave's key is not known in advance,
        so the transaction that key will sign is built with this value.
        """
        result = self._submit(json.dumps({"guest_op": OP_PUBLIC_KEY}))
        answer = _extract_success_value(result.get("receipts_outcome", []))
        if not answer or answer.get("status") != "ok":
            raise OnChainTeeError(
                "the enclave did not return a public key: "
                + json.dumps(answer or _extract_events(result.get("receipts_outcome", [])))[:300]
            )
        key = answer.get("public_key")
        if not isinstance(key, str) or not key.startswith("ed25519:"):
            raise OnChainTeeError("the enclave returned an unusable public key")
        return key

    def sign(self, request: TeeSigningRequest) -> SigningResult:
        cap = self.capability()
        if not cap.available:
            raise TeeProviderUnavailable(cap.detail)

        result = self._submit(json.dumps(request.to_dict()))
        receipts = result.get("receipts_outcome", [])
        events = _extract_events(receipts)
        answer = _extract_success_value(receipts)
        if not answer or answer.get("status") != "ok":
            message = answer.get("message") if isinstance(answer, dict) else None
            raise OnChainTeeError(
                "the enclave refused to sign: "
                + str(message or events.get("execution_completed") or "no answer")
            )

        public_key = answer.get("public_key")
        signature_b64 = answer.get("signature")
        signed_b64 = answer.get("signed_transaction")
        if not (isinstance(public_key, str) and isinstance(signature_b64, str) and isinstance(signed_b64, str)):
            raise OnChainTeeError("the enclave output carried no signature or signed transaction")
        try:
            signature = base64.b64decode(signature_b64, validate=True)
            signed_bytes = base64.b64decode(signed_b64, validate=True)
        except (ValueError, base64.binascii.Error) as exc:
            raise OnChainTeeError("the enclave output was not valid base64") from exc
        if len(signature) != 64:
            raise OnChainTeeError("the enclave signature is not a 64-byte ed25519 signature")

        # The digest the enclave reports must be the one we authorized.
        reported = str(answer.get("transaction_digest", ""))
        if reported != request.transaction_digest:
            raise OnChainTeeError(
                "the enclave signed a different transaction digest than was authorized; refusing"
            )

        # Verify the returned signature locally, over the exact authorized digest,
        # before it is handed on. A signature that does not verify is refused, so
        # no caller has to trust the enclave's word for this.
        enclave_key = b58decode(public_key.split(":")[-1])
        try:
            digest_bytes = bytes.fromhex(request.transaction_digest.split(":")[-1])
        except ValueError as exc:
            raise OnChainTeeError("the authorized digest was not hex") from exc
        if enclave_key is None or len(digest_bytes) != 32 or not ed25519.verify(
            signature, digest_bytes, enclave_key
        ):
            raise OnChainTeeError(
                "the enclave's signature does not verify over the authorized digest; refusing"
            )

        completed = events.get("execution_completed") or {}
        self.last_run = {
            "events": events,
            "public_key": public_key,
            "transaction_digest": reported,
            "tx_hash": answer.get("tx_hash", ""),
            "manifest_len": answer.get("manifest_len"),
            "payment_charged": completed.get("payment_charged"),
            "payment_refunded": completed.get("payment_refunded"),
            "resources_used": completed.get("resources_used"),
            "success": completed.get("success"),
        }
        return SigningResult(
            provider=self.name,
            public_key=public_key,
            signature_raw64=signature,
            signed_bytes=signed_bytes,
            transaction_digest=reported,
            request_digest=request.digest(),
            execution_id=str(answer.get("authorization_id") or ""),
            build_hash="sha256:" + self._config.wasm_sha256,
            attestation_url="",
            simulated=False,
            raw={"output_keys": sorted(answer.keys()), "on_chain": True},
        )


__all__ = [
    "OnChainCaller",
    "OnChainTeeConfig",
    "OnChainTeeError",
    "OutLayerOnChainSigningProvider",
    "OUTLAYER_EXECUTORS",
]
