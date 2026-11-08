# Mission 27 — the actual signature data flow

Every line below is a reference into the shipped implementation. The mission's
central question was whether TraceSettle durably preserves enough cryptographic
evidence to independently re-verify, **after a process restart**, that the exact
transaction it authorized was signed by the claimed signer. This file traces the
real path and names the defect that broke the "after a restart" half of it.

## The path, stage by stage

| # | Step | File · symbol |
|---|------|---------------|
| 1 | Transaction built (Borsh V0 `Transaction` + action) | `near/txbuild.py` · `NearTransaction.build_transfer`, `unsigned_bytes()` |
| 2 | Digest over the exact unsigned bytes (`sha256`) | `near/txbuild.py` · `NearTransaction.tx_hash_bytes`, `payload_fingerprint()` |
| 3 | Authorization bound to the digest (byte-level binding) | `near/execution.py` · `PreparedOperation`; `guard/authorization.py` `canonical_fields(transaction_digest=…)` |
| 4 | Signing request sent to the provider | `near/execution.py` · `NearExecutionBoundary.prepare` → pipeline |
| 5 | Signature received (base64, ed25519 over the digest) | `near/pipeline.py` · `NearExecutionPipeline.execute` / `submit_signed` |
| 6 | Signature checked and single-use authorization consumed | `near/execution.py` · `NearExecutionBoundary.accept_signature` (ed25519 verify over `tx.tx_hash_bytes`, `authority.validate` consumes the nonce) |
| 7 | Signed bytes serialized (unsigned ‖ 1-byte tag ‖ 64-byte sig) | `near/txbuild.py` · `NearTransaction.signed_bytes(signature)` |
| 8 | **Signed bytes persisted before broadcast** | `near/pipeline.py` · `execute` → `SubmissionRecord(signed_b64=…)` → `ledger.put` |
| 9 | Broadcast | `near/pipeline.py` · `_submit_and_verify` → `boundary.send_tx` |
| 10 | Durable evidence chain assembled | `near/pipeline.py` · `_build_chain` → `tee_signing/evidence_chain.build_evidence_chain` |
| 11 | Recovery of an unknown outcome | `near/pipeline.py` · `resolve_unknown` / `recover` → `reconstruct_transaction` |
| 12 | Independent signature re-verification from the record | `near/pipeline.py` · `verify_recorded_signature` |
| 13 | Settlement verification (on-chain read-back) | `near/verify.py` · `verify_transaction` |
| 14 | Reviewer surfaces | `guard/api.py` · `GET /api/guard/near/execution/signature/<tx>`, `.../chain/<tx>`; console "Durable signature evidence" |

## The questions, answered from the implementation

1. **Where is the signature first received?** `pipeline.execute` (from the
   `TransactionSigner`) and `pipeline.submit_signed` (a wallet). Both hand it to
   `boundary.accept_signature`.
2. **Where is its public key obtained?** From the transaction the pipeline holds
   (`prepared.transaction.public_key`) during a live run, and — after a restart —
   from the **exact signed bytes** via the strict decoder
   (`pipeline._record_facts` → `txdecode.decode_signed_b64(...).public_key`).
3. **Where is the exact transaction digest calculated?** `NearTransaction`
   computes `sha256(unsigned_bytes)`. `verify_recorded_signature` recomputes it
   from the persisted bytes (`digest_source: recomputed_from_persisted_signed_bytes`).
4. **Where is the signed transaction serialized?** `NearTransaction.signed_bytes`
   (unsigned ‖ tag ‖ signature); the pipeline stores it base64 in
   `SubmissionRecord.signed_b64`.
5. **Where is it persisted?** `near/ledger.py` · `SubmissionLedger.put` writes the
   `SubmissionRecord.to_json()` blob into the SQLite `submissions` table
   (`journal_mode=WAL`, `synchronous=FULL`). The evidence chain is separately
   persisted by `tee_signing/evidence_chain.EvidenceChainStore`.
6. **Where is the signature independently verified?** `verify_recorded_signature`
   recomputes the digest from the persisted bytes and re-runs `ed25519.verify`
   over it under the key the bytes name; the chain's
   `_check_signature_over_digest` re-verifies it a second way from the stage data.
7. **Does verification survive a fresh process restart?** **Yes, now.** It did
   **not** before this mission — see the defect below. The invariant
   `near_recorded_signature_survives_a_restart` and
   `tests/test_near_durable_signature.py` prove it against a real SQLite
   close/reopen.
8. **Does recovery use the original signed bytes?** Yes —
   `reconstruct_transaction` decodes `record.signed_b64` with the strict,
   round-trip-checked `txdecode` decoder and re-derives the transaction; the
   recovered submission then reaches `VERIFIED`, not merely `CONFIRMED`.
9. **Is the signature cryptographically linked to the authorization record?**
   Yes, by two independent bindings: the authorization is signed over
   `canonical_fields(transaction_digest=…)` at mint time, and the evidence chain's
   `verify_chain_bindings` requires the AUTHORIZATION stage's
   receiver/amount/network/digest to equal the SIGNATURE stage's.
10. **Can an attacker substitute the signature, public key, bytes or attestation
    independently?** No. The signature is verified over the digest recomputed
    from the same bytes (substituting either breaks it); the ledger refuses to
    overwrite the recorded signed bytes (`SubmissionLedgerError`); the chain fails
    closed if the signer public key or any stage field disagrees; and a signature
    labelled with an algorithm the product cannot verify is refused rather than
    checked with the wrong rule.

## The defect this mission fixes

`SubmissionRecord.to_dict()` omitted `signed_b64` (and no algorithm was stored).
`SubmissionLedger.put` persists `to_json()` → `to_dict()`, so the SQLite blob
never carried the signed bytes, and `from_json()` read `""` back. Consequences,
both proven by a real close/reopen:

* `reconstruct_transaction` returned `None` after a restart, so Mission 22
  recovery silently capped at `CONFIRMED` instead of reaching `VERIFIED`;
* the durable evidence chain could not recover the signature from the bytes, so
  its ed25519 re-verification was **skipped** — reported as a limitation, but a
  real loss of the independent check.

Mission 26's regression test passed only because it used an **in-memory** ledger
within one process; it never restarted the store. A second, smaller gap: on the
recovery path `_build_chain` sourced the signer public key only from the prepared
operation, so the rebuilt chain recorded an empty `public_key` and the
`signer_public_key_agrees` check could not run.

## Fix summary

* `ledger.py`: persist `signed_b64` and a new `signature_algorithm`; refuse to
  overwrite recorded signed bytes (SQLite **and** in-memory, the latter now with
  value semantics so a mutated copy cannot change what is stored).
* `pipeline.py`: `_record_facts` recovers digest/signature/public key from the
  durable bytes (cross-checked against the record); `_build_chain` sources facts
  from the record as well as the prepared operation; new
  `verify_recorded_signature` recomputes the digest and re-verifies ed25519 from
  the record alone; `_attestation_stage`/`_approved_build` record the provider,
  attestation and approved-build provenance when present.
* `evidence_chain.py`: carry `signature_algorithm` into the SIGNATURE stage and
  verify with the named algorithm (refuse one it cannot verify).
* `guard/api.py` + `console.py`: expose the re-verification per transaction and
  render the separate, truthful claims.

---

# Mission 28 addendum — genuine enclave provenance (2026-11-08)

Mission 27 established the **durability** half: the exact signed bytes survive a
restart, so the ed25519 signature can be re-checked. It stated plainly that a
stored signature does **not** prove genuine TEE execution. Mission 28 closes that
gap with a chain of commitments that reaches from the Intel-signed quote to the
signature.

## The chain, and where each link is checked

```
Intel-signed TDX quote
  └─ report_data[0:32] = Task Hash V1(record fields)      outlayer_attestation.task_hash_v1
       └─ output_hash = sha256(enclave stdout, verbatim)   outlayer_attestation._check_payloads
            └─ that stdout, parsed, IS sign_transaction.output   signing_provenance._outputs_equal
                 └─ output.signed_transaction bytes
                      └─ sha256(borsh(unsigned)) == output.transaction_digest   NearTransaction.unsigned_from_signed
                           └─ b58(digest) == output.tx_hash
                                └─ ed25519(sig, digest, output.public_key) verifies   near/ed25519.verify
```

`near/tee_signing/signing_provenance.py::verify_attested_signing` runs each link
as a **separately named check** and returns a verdict whose level is
all-of:

| Level | Meaning |
|---|---|
| `TEE_SIGNING_VERIFIED` | every link holds: a genuine Intel TDX enclave, running the approved build, produced this exact signed transaction |
| `SIGNATURE_VERIFIED` | the signature is genuine for the exact transaction, but the enclave provenance did not hold |
| `NOT_VERIFIED` | the attestation could not be established |
| `REFUTED` | the quote verified but a binding did not |

## The decisive link

The enclave's `output_hash` — which Intel signed into the quote — equals
`sha256(receipt SuccessValue)`, and that SuccessValue *is* the signing output that
carries `signed_transaction`. A host that swapped the signed transaction after the
enclave produced it would change the stdout bytes, so `output_hash` would no
longer match. This is why the verdict is not a restatement: the bytes are
re-hashed here and compared to a value the attacker cannot forge without Intel's
signature.

## Reviewer commands

```
$ python3 -m tracesettle signing-provenance verify \
      --run tracesettle/near/fixtures/onchain_tee_run.json \
      --attestation tracesettle/near/fixtures/onchain_tee_attestation.json
RESULT: PASS   (level TEE_SIGNING_VERIFIED, 7/7 checks)

$ python3 -m tracesettle signing-provenance verify \
      --run tracesettle/near/fixtures/onchain_tee_run.json \
      --fetch --execution-tx 9aqdmyBq4GE7zhvnwHcgGVU9mfyUrx4KbKRG26TuierY
RESULT: PASS   (fetched live from the free OutLayer endpoint + public NEAR RPC)
```
