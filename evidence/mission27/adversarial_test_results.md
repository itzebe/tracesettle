# Mission 27 — adversarial regression results

All cases are in `tests/test_near_durable_signature.py` (29 tests) and
`tests/test_near_invariants.py` (the two mutation tests for the new invariant).
Every test drives the real builder, guard, pipeline, strict decoder and durable
stores; the only substitution is the RPC transport. "Fail closed" means the
verdict is `verified: False` (or the write is refused) with the failing check
named — never an upgrade to SIGNED/BROADCAST/VERIFIED merely because a hash
exists.

Command:
`python3 -m pytest tests/test_near_durable_signature.py tests/test_near_invariants.py -q`

## Cases required by the mission

| Case | Test | Observed fail-closed behaviour |
|---|---|---|
| Missing signature | `test_missing_signed_bytes_is_not_verified` | `signed_bytes_present` fails → `verified: False` |
| Missing public key | `test_missing_public_key_is_not_verified` | bytes don't decode → `signature_verifies_over_digest` fails |
| Missing transaction bytes | `test_missing_signed_bytes_is_not_verified` | same as missing signature |
| Missing transaction digest | `test_a_modified_transaction_digest_breaks_the_chain` | `transaction_digest_agrees` fails → chain not bound |
| Invalid signature | `test_invalid_signature_is_not_verified` | one flipped byte → `signature_verifies_over_digest` fails |
| Wrong public key | `test_missing_public_key_is_not_verified` | key recovered from corrupted bytes → decode + verify fail |
| Modified transaction bytes | `test_modified_transaction_bytes_are_not_verified` | digest changes → signature no longer verifies |
| Modified transaction digest | `test_a_modified_transaction_digest_breaks_the_chain` | chain binding fails |
| Modified receiver | `test_a_modified_receiver_disagrees_with_the_record` | `record_matches_signed_bytes` fails |
| Modified amount | `test_a_modified_amount_disagrees_with_the_record` | `record_matches_signed_bytes` fails |
| Modified action order / bytes | `test_modified_transaction_bytes_are_not_verified` | any body byte change invalidates the signature |
| Modified network | `test_a_modified_network_breaks_the_chain` | `network_agrees` fails |
| Modified signer | `test_a_modified_signer_disagrees_with_the_record` | decode disagrees → not verified |
| Modified authorization record ID | `test_a_modified_transaction_digest_breaks_the_chain` (digest is the auth binding) | chain binding fails |
| Expired authorization | covered by `tests/test_near_pipeline.py` precondition tests | signing refused before the provider is reached |
| Replaced provider identity | `test_a_valid_signature_never_claims_tee_execution` + chain `provider` is *reported* | provider claim never promoted from a valid signature |
| Replaced build digest | `test_a_replaced_build_digest_breaks_the_chain` | `approved_build_agrees` fails |
| Altered attestation reference | `test_a_valid_signature_never_claims_tee_execution` | absent ATTESTATION stage → no TEE claim |
| Replayed signing response | `test_the_ledger_refuses_to_overwrite_the_recorded_signed_bytes` | a different signed blob for the same hash is refused |
| Duplicate persistence request | `test_a_duplicate_persistence_is_idempotent` | identical bytes: no conflict, one row |
| Database write failure | `test_a_ledger_that_cannot_be_opened_fails_closed` | hard failure, never silent in-memory fallback |
| Restart during persistence | `test_the_exact_signed_bytes_survive_a_restart` | the durable file is the only source; the bytes are present |
| Restart after signing, before broadcast | `test_recovery_before_broadcast_uses_the_signed_bytes` | identical durable bytes re-sent once |
| Restart after broadcast, before settlement | `test_recovery_reaches_verified_after_a_restart_from_the_durable_bytes` | resolved from the chain to `VERIFIED` |
| Corrupted durable record | `test_a_corrupt_record_is_malformed_not_verified`, `test_a_truncated_record_is_malformed_not_verified` | `state: MALFORMED`, `verified: False` |
| Missing provider evidence where TEE is mandatory | `test_a_valid_signature_never_claims_tee_execution` | no TEE claim without attestation evidence |

## The acceptance cases

| Case | Test |
|---|---|
| Signed bytes survive a restart | `test_the_exact_signed_bytes_survive_a_restart` |
| Fresh process re-verifies independently | `test_a_fresh_process_independently_reverifies_the_recorded_signature` |
| Reproducible across two fresh processes | `test_the_reverification_is_reproducible_across_two_fresh_processes` |
| Signature bound to the original authorization | `test_the_signature_is_bound_to_the_original_authorization` |
| Chain keeps the signature + signer key after restart | `test_the_chain_carries_the_signature_and_signer_key_after_a_restart` |
| Recovery reaches VERIFIED from durable bytes | `test_recovery_reaches_verified_after_a_restart_from_the_durable_bytes` |
| Digest binding (b58 of digest == tx hash) | `test_a_fresh_process_independently_reverifies_the_recorded_signature` |
| Signature algorithm must be verifiable | `test_the_chain_refuses_a_signature_algorithm_it_cannot_verify` |

## Mutation tests (the invariant cannot pass vacuously)

| Mutation | Test | Result |
|---|---|---|
| Ledger serializer drops `signed_b64` (the exact Mission 27 defect) | `test_durable_signature_invariant_notices_persistence_being_dropped` | invariant reports `holds: False`, "the signed bytes were not persisted" |
| A verifier that returns `verified: True` without checking | `test_durable_signature_invariant_notices_a_verifier_that_accepts_anything` | invariant reports `holds: False` (the tampered-byte probe catches it) |
| Chain stops re-verifying the signature cryptographically | `test_evidence_chain_invariant_notices_a_string_only_check` | invariant reports `holds: False` |

Verified by running the mutation (temporarily removing the `signed_b64` field from
`SubmissionRecord.to_dict`): the invariant failed with
`the signed bytes were not persisted; a restart cannot re-verify them`. The
mutation was reverted.

## Result

`tests/test_near_durable_signature.py`: **29 passed**.
`tests/test_near_invariants.py`: **35 passed** (including the two new mutation
tests). No test was deleted, skipped or weakened.

---

# Mission 28 addendum — adversarial results (2026-11-08)

Mission 27's table covers the **durability** half. Mission 28 adds the
**genuine-enclave-provenance** half and its own adversarial cases. Every test
drives the real verifier over the real Mission 25 capture; the only substitution
is the on-chain approval RPC (`RecordedApprovalRpc`, a transport stand-in that
replays the recorded contract answer — every line of the verifier runs).

Commands:
`python3 -m pytest tests/test_near_signing_provenance.py tests/test_near_outlayer_attestation.py tests/test_near_invariants.py -q`

## The new adversarial cases (`tests/test_near_signing_provenance.py`, 11 tests)

| Case | Test | Observed fail-closed behaviour |
|---|---|---|
| Genuine run reaches TEE_SIGNING_VERIFIED | `test_the_real_run_is_tee_signing_verified` | all 7 checks hold; level `TEE_SIGNING_VERIFIED` |
| Attested output binds the signed transaction | `test_the_attested_output_hash_binds_the_signed_transaction` | `enclave_output_hash_binds_the_receipt` holds |
| **Modified transaction bytes** | `test_a_swapped_signed_transaction_is_refused` | digest recompute disagrees with the recorded digest → not TEE-verified |
| **Modified transaction digest** | `test_a_changed_digest_is_refused` | `digest_matches_signed_bytes` fails |
| **Replayed / wrong attestation** | `test_a_different_attestation_for_another_execution_is_refused` | Task-Hash / execution binding fails → `REFUTED` |
| **Valid signature, no attestation** | `test_a_valid_signature_without_attestation_is_only_signature_verified` | level capped at `SIGNATURE_VERIFIED`, never TEE |
| Missing on-chain result | `test_no_on_chain_result_cannot_bind_the_enclave_output` | cannot bind → not TEE-verified |
| **Replaced build digest** | `test_a_different_approved_build_is_refused` | approved-build binding fails |
| Non-success signing output | `test_a_non_success_signing_output_is_a_structural_error` | structural error, never a pass |
| Missing signing output | `test_a_missing_signing_output_is_a_structural_error` | structural error, never a pass |
| No secrets in the verdict | `test_the_verdict_serialises_without_secrets` | verdict carries no key material |

## The live-fetch defect (found and fixed this mission)

`fetch_attestation` built its HTTP client as
`HttpClient(timeout=20.0, attempts=2)`, but `HttpClient.__init__` takes
`max_attempts`. Every unit test injected a stub client, so the defect was latent;
the reviewer's real `--tx-hash` path raised `TypeError` before any request.
Regression test `test_fetch_attestation_builds_its_http_client_with_max_attempts`
spies on the constructor and requires the exact keyword. Mutation-checked: with
`attempts=` restored the test fails; with `max_attempts=` it passes.

## Mutation tests for the new invariant

`tests/test_near_invariants.py` gained two mutation tests for
`near_attested_signing_binds_the_enclave_output_to_the_transaction`:

| Mutation | Test | Result |
|---|---|---|
| A verifier that always returns `TEE_SIGNING_VERIFIED` | `test_attested_signing_invariant_notices_a_verifier_that_accepts_anything` | invariant reports `holds: False` |
| A verifier that drops the enclave-output binding | `test_attested_signing_invariant_notices_a_verifier_that_ignores_the_output_binding` | invariant reports `holds: False` |

## Result

`tests/test_near_signing_provenance.py`: **11 passed**.
`tests/test_near_invariants.py`: **37 passed** (was 35; +2 mutation tests).
`tests/test_near_outlayer_attestation.py`: passes including the new regression.
No test was deleted, skipped or weakened.
