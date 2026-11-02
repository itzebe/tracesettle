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

**Decision: not claimed.** TRACESETTLE does not verify that attestation itself.
It reads the policy over HTTP and reports the read's availability; it does not
assert that the provider's TEE held. `NEAR_AI_CLOUD_NOTES` records this, and
`assess_verifiable_execution` returns `ABSENT` or `UNVERIFIABLE` when no
attestation is verified.

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

None of these is available under the zero-budget rule, so none is integrated.
