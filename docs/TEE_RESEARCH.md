# Verifiable-execution (TEE) research

This records whether verifiable execution could materially strengthen
TRACESETTLE, and what was decided. It is research: nothing here is integrated,
and no TEE protection is claimed anywhere in the product.

The zero-budget rule governs the decision. If verification would cost money or
require a financial commitment, it is not used.

## OutLayer

Sources: `app.outlayer.ai/docs/getting-started`, `app.outlayer.ai/docs/pricing`.

**What it offers.** OutLayer runs every execution inside an Intel TDX
confidential VM and emits a hardware-signed attestation covering the code, the
input, the output, and the worker identity. A caller can, in principle, verify
that a specific computation ran unmodified on a specific input.

**Pricing.** The pricing page describes a dynamic, pay-per-resource model:
`base_fee + instructions × rate + time × rate`. It is a paid service, and
**failed executions are not refunded**.

**Decision: not integrated.** The cost and the no-refund policy are a financial
commitment, which the zero-budget rule forbids. `assess_verifiable_execution(
"outlayer", requires_payment=True)` therefore returns `NOT_ATTEMPTED` and claims
no protection. The code models the option; it does not use it.

**Could it help?** Yes, in principle, and in one specific place. TRACESETTLE's
weakest honest statement is about its **audit log**: an in-place edit, reorder or
removal is detected by chain recomputation, but a whole-log rewrite with
recomputed digests is not. A verifiable execution that computed each record's
digest inside a TEE, with the attestation anchored on chain, would close that
gap — the rewrite would no longer be indistinguishable. That is a real
strengthening. It is also a paid dependency, so it stays a documented option
rather than a build.

## NEAR AI Cloud

The NEAR Intents Agent API runs in an attested TEE and publishes transparency
proofs. That is relevant to trusting a **policy read**: an attestation could
show that the policy bytes came from the expected code.

**Decision at the time: not claimed.** TRACESETTLE did not verify that
attestation itself; it read the policy over HTTP and reported the read's
availability, not that the provider's TEE held. `NEAR_AI_CLOUD_NOTES` records
this, and `assess_verifiable_execution` returns `ABSENT` or `UNVERIFIABLE` when no
attestation is verified. (A later change adds genuine local verification of the
gateway's real TDX quote; see the update at the end. The policy-read decision is
unchanged: verification is offered as an independent capability and is not wired
into the read path.)

## The rule the code enforces

`assess_verifiable_execution` claims TEE protection **only** when an attestation
is supplied **and** a verifier accepts it. Every other path — payment required,
no attestation, no verifier, a verifier that rejects or raises — reports no
protection. A TEE claim without a verified attestation is not a security
property, so the code never makes one.

## What would change the decision

* An OutLayer free tier or a self-hosted verifier with no payment.
* A funded budget, with the human's explicit approval, to anchor the audit-log
  digest through a TEE.
* A NEAR AI Cloud attestation that can be verified locally against a published
  key.

None of these was available under the zero-budget rule at the time this section
was written, so none was integrated then. (The third item — local verification of
a NEAR AI Cloud attestation against a published key — was subsequently achieved at
no cost; see the update at the end of this document. The first two remain out of
scope.)

---

## Update: genuine local verification of a real NEAR AI Cloud TDX quote

The "what would change the decision" list above named a *NEAR AI Cloud
attestation that can be verified locally against a published key*. That is now
available and is implemented — at no cost, with no paid infrastructure.

**What was built.** `tracesettle/near/tdx.py` is a self-contained Intel TDX quote
verifier (standard library plus the in-repo `p256` module). It parses the v4
quote layout, extracts the TD report body, the quote signature, the attestation
key and the certification data, and verifies:

1. the quote signature (ECDSA-P256) under the attestation key in the quote;
2. the PCK certificate chain up to the **pinned** Intel SGX Root CA
   (`INTEL_SGX_ROOT_CA_SHA256 =
   44a0196b2b99f889b8e149e95b807a350e7424964399e885a7cbb8ccfab674d3`);
3. the attestation key is bound to the Quoting Enclave report
   (`QE report_data[0:32] = sha256(AK_raw64 || qe_auth_data)`);
4. `report_data` binds a fresh caller nonce, the signing address and the TLS key;
5. the event log replays to RTMR0..3.

`tracesettle/near/attestation.py` fetches the gateway's real quote from the
public NEAR AI Cloud attestation endpoint and runs the verifier. The quote, the
nonce, the signing address and the TLS fingerprint are all cross-checked against
the gateway's echoed fields, so a quote that does not match the claimed session
is refused.

**Evidence.** A real quote was fetched live and verified; with Intel PCS
collateral validation enabled all sixteen checks pass (`status: VERIFIED`,
`collateral_verified: true`, TCB `UpToDate`, PCK not revoked, QE identity match);
a quote with a single flipped bit in `report_data` is
refused, and a quote for a different nonce is refused. The capture is kept at
`evidence/raw/nearai_cloud_gateway_attestation.json`, and a copy lives inside the
package (`tracesettle/near/fixtures/attestation_nearai_cloud.json`) so the
structural invariants are checkable from a package-only copy.

**What is still not claimed.** This is *verification of a real hardware quote*,
not a TEE-integrated execution path. The guard's decisions do not depend on it;
the executor still simulates execution and broadcasts nothing.

Intel PCS collateral **is** now verified (`tracesettle/near/collateral.py`): the
signed TCB Info (TCB-level matching and freshness), the signed PCK CRL
(revocation) and the signed QE Identity, each walked to the pinned Intel root.
Live-verified against Intel's TDX certification service: TCB `UpToDate`, the PCK
certificate is not revoked, and the QE identity matches. This closes the earlier
gap where revocation and TCB freshness were unchecked; what remains out of scope
is a TEE-integrated *signing* path (the executor is still a simulator) and live
provider-policy integration. The two structural invariants
`tee_attestation_verification_is_genuine` and
`tee_attestation_is_bound_to_the_decision_nonce` hold this boundary.
