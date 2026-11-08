"""The TEE signing boundary: one provider that signs the exact authorized digest.

This package closes the last gap in the trusted execution chain. The rest of the
product decides *whether* a payment may happen and *verifies* what happened; this
is the only place that asks a **remote, attested** enclave to produce the ed25519
signature over the exact NEAR transaction digest TraceSettle authorized.

The provider it targets is **OutLayer Signing Keys** (``outlayer:signing-keys``),
the one documented route that signs a caller-computed digest inside an Intel TDX
enclave. The research that selected it — and the reason every other candidate was
rejected — is in ``evidence/mission24/provider_research.md``.

Honest scope, stated once and repeated at each layer:

* The provider is **paid** (OutLayer bills per execution). No free tier covers a
  raw-digest signature, so with no configured credential the boundary reports
  ``PROVIDER_UNAVAILABLE`` and **refuses to sign** — it never falls back to a
  software key. ``evidence/mission24/free_access_and_credentials.md`` records the
  exact owner action required to run it live.
* A verified attestation proves *some* approved enclave ran *some* build. It does
  **not** by itself prove *this* transaction was signed. That proof is the
  ``report_data``/task-hash commitment to the signing request, which
  :mod:`tracesettle.near.tee_signing.attestation` checks separately.
* The private key never reaches the host module: the guest receives a public key
  or a signature, never the key. The adapter only ever holds the provider's API
  credential, which is server-side config and never returned or logged.
"""

from __future__ import annotations

from .request import (
    SIGNING_DOMAIN,
    TeeSigningRequest,
    build_signing_request,
    digest_for,
)
from .provider import (
    TeeProviderError,
    TeeProviderUnavailable,
    SigningProvider,
    SigningResult,
    ProviderCapability,
    OutLayerSigningProvider,
    LocalStandInSigningProvider,
)
from .attestation import (
    AttestationClaim,
    AttestationVerdict,
    verify_signing_attestation,
)
from .boundary import (
    TeeSignatureEvidence,
    TeeSigningBoundary,
    TeeSigningRefusal,
)
from .onchain import (
    OnChainCaller,
    OnChainTeeConfig,
    OnChainTeeError,
    OutLayerOnChainSigningProvider,
)
from .build_verify import (
    BuildVerdict,
    ReproducibleBuildError,
    build_input_digest,
    verify_build,
)
from .evidence_chain import (
    ChainBinding,
    EvidenceChain,
    EvidenceChainError,
    EvidenceChainStore,
    build_evidence_chain,
    verify_chain_bindings,
)
from .outlayer_attestation import (
    AttestationClaim as OutLayerAttestationClaim,
    OutLayerAttestationError,
    OutLayerAttestationVerdict,
    attestation_api_host,
    fetch_attestation,
    task_hash_v1,
    verify_outlayer_attestation,
)

__all__ = [
    "SIGNING_DOMAIN",
    "TeeSigningRequest",
    "digest_for",
    "build_signing_request",
    "TeeProviderError",
    "TeeProviderUnavailable",
    "SigningProvider",
    "SigningResult",
    "ProviderCapability",
    "OutLayerSigningProvider",
    "LocalStandInSigningProvider",
    "AttestationClaim",
    "AttestationVerdict",
    "verify_signing_attestation",
    "TeeSignatureEvidence",
    "TeeSigningBoundary",
    "TeeSigningRefusal",
    "OnChainCaller",
    "OnChainTeeConfig",
    "OnChainTeeError",
    "OutLayerOnChainSigningProvider",
    "BuildVerdict",
    "ReproducibleBuildError",
    "build_input_digest",
    "verify_build",
    "ChainBinding",
    "EvidenceChain",
    "EvidenceChainError",
    "EvidenceChainStore",
    "build_evidence_chain",
    "verify_chain_bindings",
    "OutLayerAttestationClaim",
    "OutLayerAttestationError",
    "OutLayerAttestationVerdict",
    "attestation_api_host",
    "fetch_attestation",
    "task_hash_v1",
    "verify_outlayer_attestation",
]
