# Mission 27 — the durable evidence contract

What must survive a process restart so the signing event can be independently
re-verified. The contract is satisfied by the **existing** models — one field was
added (`signature_algorithm`); no table was redesigned.

## Where the evidence lives

Two durable stores, both SQLite (`journal_mode=WAL`, `synchronous=FULL`):

1. **Submission ledger** — `near/ledger.py` · `SubmissionLedger` (table
   `submissions`, one JSON blob per transaction). This is the record a recovery
   reads and the record `verify_recorded_signature` reads.
2. **Evidence chain** — `near/tee_signing/evidence_chain.py` · `EvidenceChainStore`
   (one row per stage, digest-chained). This is the authorization-to-settlement
   binding.

Both are configured with a path (`TRACESETTLE_NEAR_LEDGER_DB`, and the chain store
alongside it); with no path each is in-memory, and the honest consequence — a
restart loses the ability to re-verify — is stated, not hidden.

## The fields, and which claim each supports

| Required evidence | Field | Where | Claim it supports |
|---|---|---|---|
| Execution ID | `PreparedOperation.execution_id`; chain `SIGNATURE.execution_id` | `near/execution.py`, chain | which signing operation this is |
| Authorization record ID | chain `AUTHORIZATION.id`; `PreparedOperation.authorization_id` | chain, `near/execution.py` | the authorization this signature is for |
| Authorization decision + policy provenance | chain `AUTHORIZATION.decision`, `.policy_version`, `.digest`, `.expiry` | chain | what was authorized, under which policy |
| Network ID | `SubmissionRecord.network`; chain `AUTHORIZATION.network`, `chain.network` | ledger, chain | the network the digest is for |
| Signer account | `SubmissionRecord.signer_id`; chain `PREPARED_TRANSACTION.signer_id` | ledger, chain | who signed |
| **Signer public key** | recovered from signed bytes (`_record_facts`) → chain `SIGNATURE.public_key` | ledger bytes → chain | the key the signature must verify under |
| Receiver account | `SubmissionRecord.receiver_id`; chain `AUTHORIZATION`/`SIGNATURE.receiver_account` | ledger, chain | the authorized recipient |
| **Canonical transaction bytes** | `SubmissionRecord.signed_b64` | ledger | the exact bytes signed (the root of every re-check) |
| **Transaction digest** | recomputed from the bytes (`verify_recorded_signature`); chain `*.transaction_digest` | derived, chain | the message the signature covers |
| **Signature** | recovered from the bytes (`_record_facts`) → chain `SIGNATURE.signature_b64` | ledger bytes → chain | the cryptographic proof |
| **Signature algorithm** | `SubmissionRecord.signature_algorithm`; chain `SIGNATURE.signature_algorithm` | ledger, chain | which rule verifies it |
| Signing provider identity | chain `SIGNATURE.provider` (from the durable execution record) | chain | *reported* provider, never assumed |
| Provider execution ID | chain `SIGNATURE.execution_id` | chain | the provider run |
| Attestation evidence | chain `ATTESTATION.*` (`level`, `verified`, `quote_verified`, `worker_measurement`, `measurement_approved`, `wasm_hash`) | chain | a *verified* TEE claim, when one exists |
| Approved build / WASM digest | chain `SIGNATURE.approved_build`, `ATTESTATION.wasm_hash` | chain | the operator-pinned build |
| Worker identity / measurements | chain `ATTESTATION.worker_measurement`, `.measurement_approved` | chain | the measured enclave identity |
| Input/output commitment | chain `ATTESTATION.*` (run input/output commitment from the provider) | chain | the run bound to this request and signature |
| Signing timestamp | `SubmissionRecord.created_at`/`updated_at`, chain `created_at` | ledger, chain | when the record was written |
| Authorization expiry | chain `AUTHORIZATION.expiry` | chain | the authorization's lifetime |
| Broadcast transaction hash | `SubmissionRecord.tx_hash`; chain `BROADCAST.tx_hash`, `chain.tx_hash` | ledger, chain | what was sent |
| Settlement verification state | chain `SETTLEMENT.state`, `.all_checks_passed` | chain | the independent on-chain verdict |

**Never stored:** private keys, seeds, signing material. `EvidenceChain` refuses
any of `_FORBIDDEN_KEYS` at construction, and no adapter returns key material.

## The binding rules (enforced, not described)

`verify_chain_bindings` fails closed on: a differing transaction digest, network,
receiver, amount, signer public key, approved build, or broadcast hash — and on a
signature that does not verify over the recorded digest under the recorded key
(verified with the **named algorithm**; an algorithm the product cannot verify is
a failure). The ledger additionally refuses to overwrite recorded signed bytes.

## The four separate claims (kept separate on purpose)

The mission requires these to be distinguishable. In this implementation they are:

| Claim | Established by | Not established by |
|---|---|---|
| The signature is cryptographically valid for this exact transaction | `verify_recorded_signature` (digest recomputed from persisted bytes + ed25519) | the mere presence of a signature field |
| The signature was produced by the claimed **provider** | chain `SIGNATURE.provider` (a *reported* value) | a provider's own word alone; the product labels it reported |
| The signature was produced inside a genuine **TEE** | chain `ATTESTATION` populated only from a *verified*, nonce-bound, transaction-bound attestation | a valid signature; the console shows "TEE attestation verified: no" when it is not established |
| The signature was produced by the **approved build and worker** | chain `ATTESTATION.measurement_approved`, `wasm_hash` vs `SIGNATURE.approved_build` | a hash merely existing |

The console "Durable signature evidence" panel renders each row from the real
verdict; the provider/TEE/build/settlement rows are shown as "no" with the reason
when the durable record does not carry that evidence, never inferred from a valid
signature.

---

# Mission 28 addendum — the enclave-provenance fields (2026-11-08)

Mission 27's contract covers the *durability* half. Mission 28 adds the
*provenance* half: the fields that let a reviewer prove the signature came from a
genuine Intel TDX enclave running the approved build, not merely from some key.

These are **not** new durable fields — they are read from the attestation the
provider publishes and the run capture, both of which are public on-chain data.
Nothing here is stored in the ledger, so no schema changed.

| Provenance evidence | Source | Claim it supports |
|---|---|---|
| Intel TDX quote (signed) | `attestation.tdx_quote` | the platform is a genuine Intel TDX enclave |
| Task-Hash commitment | `attestation` fields → `task_hash_v1` recomputed | this quote is for **this** run's request |
| Attested `output_hash` | `attestation.output_hash` | the enclave produced **this** output |
| Attested `input_hash` | `attestation.input_hash` | the enclave received **this** input |
| Worker measurement | `attestation.worker_measurement` | which measured enclave identity ran |
| Worker approved on-chain | register `is_measurements_approved` | the measurement is the operator-approved one |
| Approved build / WASM digest | `attestation.wasm_hash`, `executed_wasm_sha256` | the approved build ran |
| Execution binding | `attestation.transaction_hash` | this attestation is for this execution |
| Provider execution id | `attestation.request_id` / `task_id` | which provider run |

## The level ladder (kept separate, never collapsed)

`signing_provenance.verify_attested_signing` returns exactly one of:

* `TEE_SIGNING_VERIFIED` — the enclave provenance **and** the signature both hold;
* `SIGNATURE_VERIFIED` — the signature is genuine for the exact transaction, but
  the enclave provenance did not hold;
* `NOT_VERIFIED` — the attestation could not be established (e.g. not published);
* `REFUTED` — the quote verified but a binding failed.

A valid signature alone reaches `SIGNATURE_VERIFIED` at most. This is the
distinction Mission 27 said must be preserved, now enforced in code and covered by
the invariant `near_attested_signing_binds_the_enclave_output_to_the_transaction`.

## The decisive binding

`enclave_output_hash_binds_the_receipt` requires the Intel-attested
`output_hash` to equal `sha256(receipt SuccessValue)`; `attested_output_is_this_
signing_output` requires that parsed output to equal the recorded signing output
field for field. Together they are why substituting the signed transaction is
refused: the enclave's own signed commitment no longer matches.
