"""The TEE signing provider: an interface, OutLayer's implementation, and a
deterministic stand-in used only in tests.

The provider is the narrow seam between TraceSettle and a remote attested
enclave. It does exactly two things: it runs the guest module with a canonical
signing request, and it returns the signed transaction bytes plus the evidence
needed to verify them. It never receives a private key, and it never returns one.

Two implementations ship here:

* :class:`OutLayerSigningProvider` — the real route. It POSTs the canonical
  request to OutLayer's ``/call/{owner}/{project}`` endpoint (the transport for
  the ``outlayer:signing-keys`` WASI-P2 guest) and reads back the signature, the
  public key, the execution id and the attestation URL. With no credential it
  reports :class:`ProviderCapability` unavailable and **refuses** — it never
  silently falls back to a software signer.
* :class:`LocalStandInSigningProvider` — a test double that signs with a **real**
  ed25519 key over the **real** digest. It exists so the adapter, the binding
  rules and the verification can be exercised without a paid call. It is labelled
  ``simulated`` in every result and is never selectable in production config.
"""

from __future__ import annotations

import base64
import hashlib
import json
from dataclasses import dataclass, field
from typing import Any, Mapping, Protocol

from .. import ed25519
from .request import TeeSigningRequest


class TeeProviderError(RuntimeError):
    """The provider was reached but the signing did not complete. Fail closed."""


class TeeProviderUnavailable(TeeProviderError):
    """No usable provider is configured. Refuse; never substitute a software key."""


@dataclass(frozen=True)
class ProviderCapability:
    """An honest statement about whether a real signing route is configured."""

    provider: str
    available: bool
    detail: str
    requires_payment: bool = False
    simulated: bool = False

    def to_dict(self) -> dict[str, Any]:
        return {
            "provider": self.provider,
            "available": self.available,
            "detail": self.detail,
            "requires_payment": self.requires_payment,
            "simulated": self.simulated,
        }


@dataclass
class SigningResult:
    """What the provider returns. Never accepted without independent checks."""

    provider: str
    public_key: str  # "ed25519:<base58>"
    signature_raw64: bytes
    signed_bytes: bytes
    transaction_digest: str
    request_digest: str
    execution_id: str = ""
    build_hash: str = ""
    attestation_url: str = ""
    simulated: bool = False
    raw: dict[str, Any] = field(default_factory=dict)

    @property
    def signature_b64(self) -> str:
        return base64.b64encode(self.signature_raw64).decode("ascii")

    def to_dict(self) -> dict[str, Any]:
        return {
            "provider": self.provider,
            "public_key": self.public_key,
            "signature_b64": self.signature_b64,
            "transaction_digest": self.transaction_digest,
            "request_digest": self.request_digest,
            "execution_id": self.execution_id,
            "build_hash": self.build_hash,
            "attestation_url": self.attestation_url,
            "simulated": self.simulated,
        }


class SigningProvider(Protocol):
    """A remote, attested enclave that signs the exact authorized digest."""

    @property
    def name(self) -> str: ...

    def capability(self) -> ProviderCapability: ...

    def sign(self, request: TeeSigningRequest) -> SigningResult: ...


# ---------------------------------------------------------------------------
# OutLayer — the real route
# ---------------------------------------------------------------------------

#: The host this adapter will send a payment key to, per network. The key is
#: network-scoped, so the host is the selector, not a parameter.
OUTLAYER_HOSTS: dict[str, str] = {
    "testnet": "https://testnet-api.outlayer.ai",
    "mainnet": "https://api.outlayer.ai",
}

#: The provider identity recorded in evidence and pinned by the operator.
OUTLAYER_PROVIDER = "outlayer:signing-keys"


def _b58(raw: bytes) -> str:
    alphabet = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz"
    n = int.from_bytes(raw, "big")
    out = ""
    while n:
        n, r = divmod(n, 58)
        out = alphabet[r] + out
    pad = len(raw) - len(raw.lstrip(b"\x00"))
    return "1" * pad + (out or "")


class OutLayerSigningProvider:
    """Run the signing guest on OutLayer and read back the enclave's answer.

    The request is sent as ``input`` to the guest, which composes and signs the
    NEAR digest. The provider's API key is read from server-side config, sent
    only as the ``X-Payment-Key`` header, and never returned, logged or placed in
    an error message.
    """

    def __init__(
        self,
        *,
        client: Any,
        network: str,
        owner: str,
        project: str,
        payment_key: str | None = None,
        approved_build: str = "",
        timeout: float | None = None,
    ) -> None:
        self.client = client
        self.network = network
        self.owner = owner
        self.project = project
        self._payment_key = payment_key
        self.approved_build = approved_build
        self.timeout = timeout
        self.host = OUTLAYER_HOSTS.get(network, OUTLAYER_HOSTS["testnet"])

    @property
    def name(self) -> str:
        return OUTLAYER_PROVIDER

    def capability(self) -> ProviderCapability:
        if not self.owner or not self.project:
            return ProviderCapability(
                provider=self.name,
                available=False,
                detail=(
                    "No OutLayer signing project is configured. Set the owner and "
                    "project so the signing guest can be addressed."
                ),
                requires_payment=True,
            )
        if not self._payment_key:
            return ProviderCapability(
                provider=self.name,
                available=False,
                detail=(
                    "No OutLayer payment key is configured. OutLayer bills per "
                    "execution and failed executions are not refunded, so with no "
                    "credential this boundary refuses to sign rather than fall back "
                    "to a software key."
                ),
                requires_payment=True,
            )
        return ProviderCapability(
            provider=self.name,
            available=True,
            detail=(
                "An OutLayer signing project and payment key are configured. A real "
                "call bills per execution."
            ),
            requires_payment=True,
        )

    def sign(self, request: TeeSigningRequest) -> SigningResult:
        cap = self.capability()
        if not cap.available:
            raise TeeProviderUnavailable(cap.detail)

        url = f"{self.host}/call/{self.owner}/{self.project}"
        headers = {"Content-Type": "application/json"}
        # The key is sent only here, and never echoed.
        if self._payment_key:
            headers["X-Payment-Key"] = self._payment_key
        body = {"input": request.to_dict(), "async": False}
        status, payload = self._post(url, body, headers)
        if status is None:
            raise TeeProviderError("the OutLayer signing call could not be completed")
        if status != 200:
            raise TeeProviderError(
                f"the OutLayer signing call was refused (HTTP {status})"
            )
        output = payload.get("output")
        if not isinstance(output, Mapping):
            raise TeeProviderError("the OutLayer signing call returned no output object")
        return self._parse_output(request, output, payload)

    def _post(
        self, url: str, body: dict[str, Any], headers: dict[str, str]
    ) -> tuple[int | None, dict[str, Any]]:
        """POST JSON and parse JSON. A transport failure is ``(None, {})``."""
        data = json.dumps(body).encode("utf-8")
        try:
            if hasattr(self.client, "post_json"):
                return self.client.post_json(url, data, headers=headers)
            result = self.client.post(url, data=data, headers=headers)
        except Exception:  # noqa: BLE001 - a transport failure is not an acceptance
            return None, {}
        return self._coerce(result)

    @staticmethod
    def _coerce(result: Any) -> tuple[int | None, dict[str, Any]]:
        if result is None:
            return None, {}
        if isinstance(result, tuple) and len(result) == 2:
            status, payload = result
        else:
            status = getattr(result, "status", None)
            payload = getattr(result, "json", None)
            if callable(payload):
                payload = payload()
            payload = payload if isinstance(payload, Mapping) else {}
        if not isinstance(payload, Mapping):
            payload = {}
        return (int(status) if status is not None else None), dict(payload)

    def _parse_output(
        self,
        request: TeeSigningRequest,
        output: Mapping[str, Any],
        payload: Mapping[str, Any],
    ) -> SigningResult:
        signature_b64 = output.get("signature")
        public_key = output.get("public_key")
        if not isinstance(signature_b64, str) or not isinstance(public_key, str):
            raise TeeProviderError("the OutLayer output carried no signature or public key")
        try:
            signature = base64.b64decode(signature_b64, validate=True)
        except (ValueError, base64.binascii.Error) as exc:
            raise TeeProviderError("the OutLayer signature is not valid base64") from exc
        if len(signature) != 64:
            raise TeeProviderError("the OutLayer signature is not a 64-byte ed25519 signature")
        signed_b64 = output.get("signed_transaction")
        if not isinstance(signed_b64, str):
            raise TeeProviderError("the OutLayer output carried no signed transaction")
        try:
            signed_bytes = base64.b64decode(signed_b64, validate=True)
        except (ValueError, base64.binascii.Error) as exc:
            raise TeeProviderError("the signed transaction is not valid base64") from exc
        return SigningResult(
            provider=self.name,
            public_key=public_key,
            signature_raw64=signature,
            signed_bytes=signed_bytes,
            transaction_digest=str(output.get("transaction_digest") or request.transaction_digest),
            request_digest=str(output.get("request_digest") or request.digest()),
            execution_id=str(payload.get("call_id") or output.get("execution_id") or ""),
            build_hash=str(output.get("wasm_hash") or self.approved_build),
            attestation_url=str(payload.get("attestation_url") or output.get("attestation_url") or ""),
            simulated=False,
            raw={"output_keys": sorted(str(k) for k in output.keys())},
        )


# ---------------------------------------------------------------------------
# Deterministic stand-in — tests only, never production
# ---------------------------------------------------------------------------


class LocalStandInSigningProvider:
    """Sign the exact digest with a real ed25519 key, for tests.

    This is **not** a TEE and never claims to be. It exists so the adapter, the
    digest binding, the signature verification and the evidence ladder can be
    exercised without a paid call. Every result is labelled ``simulated`` and the
    boundary records that provenance. Production code paths never construct this
    class; a test does.
    """

    def __init__(self, *, seed: bytes, build_hash: str = "sha256:" + "0" * 64) -> None:
        if len(seed) != 32:
            raise TeeProviderError("a stand-in seed must be exactly 32 bytes")
        self._seed = bytes(seed)
        self._public = ed25519.public_key(self._seed)
        self.build_hash = build_hash

    @property
    def name(self) -> str:
        return "local-stand-in"

    def capability(self) -> ProviderCapability:
        return ProviderCapability(
            provider=self.name,
            available=True,
            detail="A deterministic stand-in signs with a real ed25519 key. Test only.",
            requires_payment=False,
            simulated=True,
        )

    def sign(self, request: TeeSigningRequest) -> SigningResult:
        # The guest signs sha256(borsh(tx)) — here the digest the request commits
        # to, which the transaction's payload_fingerprint() also produced.
        digest_hex = request.transaction_digest.split(":")[-1]
        digest = bytes.fromhex(digest_hex)
        signature = ed25519.sign(digest, self._seed)
        return SigningResult(
            provider=self.name,
            public_key="ed25519:" + _b58(self._public),
            signature_raw64=signature,
            signed_bytes=b"",
            transaction_digest=request.transaction_digest,
            request_digest=request.digest(),
            execution_id="stand-in-" + hashlib.sha256(request.canonical_bytes()).hexdigest()[:16],
            build_hash=self.build_hash,
            attestation_url="",
            simulated=True,
            raw={"note": "deterministic stand-in; not a TEE"},
        )
