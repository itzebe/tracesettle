# Mission 26 — The authorization-to-settlement evidence chain

Recorded 2026-11-08. The reviewer artifact is
`evidence/mission26/evidence_chain_m25.json`, assembled from the shipped capture
`tracesettle/near/fixtures/onchain_tee_run.json` (the real 2026-11-07 on-chain TEE
signing run). Nothing in the artifact is invented; every value is read from the
capture.

## The gap Mission 25 left

Mission 22-25 checked each link of the trusted chain in a different place: the
guard decided, the boundary bound a digest, the pipeline broadcast and verified.
Nothing assembled those facts into **one** record, so an independent reviewer had
to trust that the pieces belonged together. A signature could be verified, and a
settlement could be verified, without any single artifact proving they were the
*same* transaction.

## What the chain is

`tracesettle/near/tee_signing/evidence_chain.py` assembles one `EvidenceChain`
with a row per stage:

```
AUTHORIZATION → PREPARED_TRANSACTION → TEE_EXECUTION → ATTESTATION
             → SIGNATURE → BROADCAST → FINALITY → SETTLEMENT
```

`verify_chain_bindings` re-checks that every populated stage names the **same**
transaction identity. An absent stage is not a contradiction (a chain built right
after authorization is legitimately short); a *conflicting* value is a failure.

The named checks:

| Check | Meaning |
| --- | --- |
| `transaction_digest_agrees` | the signed digest equals the authorized digest |
| `network_agrees` | the network is the one authorized |
| `receiver_agrees` | the signed receiver equals the authorized one |
| `amount_agrees` | the signed amount equals the authorized one |
| `signer_public_key_agrees` | the signer key is the one the attestation names |
| `approved_build_agrees` | the attested build is the pinned approved build |
| `broadcast_hash_agrees` | the broadcast hash is the hash of the exact signed bytes, and the settlement names it |
| `signature_verifies_over_the_digest` | the ed25519 signature is **re-verified** against the signer key over the recorded digest — the one check that is not string equality |

A substituted digest, receiver, amount, network, signer or settlement each
**breaks** the chain. A signature that is well-formed but does not verify also
breaks it, though every string field still agrees — a check that compared strings
would miss that, so the chain re-runs the ed25519 verification itself (offline,
with the in-package `ed25519` and `base58`). A missing signature field is skipped
as a limitation, never passed.

## The real capture binds

```
$ python3 -m tracesettle chain verify evidence/mission26/evidence_chain_m25.json
stages:
  - ATTESTATION
  - AUTHORIZATION
  - BROADCAST
  - FINALITY
  - PREPARED_TRANSACTION
  - SETTLEMENT
  - SIGNATURE
  - TEE_EXECUTION
chain_digest: sha256:0cd37928663508ad57cf92ce82b07c4b7bcd2f2de9ba2cae8021617b1abe0682
bound: True
checks:
  [OK ] transaction_digest_agrees
  [OK ] network_agrees
  [OK ] receiver_agrees
  [OK ] amount_agrees
  [OK ] signer_public_key_agrees
  [OK ] approved_build_agrees
  [OK ] broadcast_hash_agrees
  [OK ] signature_verifies_over_the_digest
RESULT: PASS
```

The settlement hash agrees with the broadcast hash agrees with the signed bytes'
hash — `F27Erv42DhGhaTqNXPhsf5KXedfQvP3cd1Vbz9aZnQPj` — and the signer key
`ed25519:H3dd94sk1df1t2PVyQWjD9cyzDAKh2WceAFmP3tWdC2a` agrees with the
attestation's. The chain digest is stable across runs.

## Reachable over HTTP

The chain is persisted by the pipeline when a store is configured
(`TRACESETTLE_NEAR_CHAIN_DB`), and served read-only at:

```
GET /api/guard/near/execution/chain/<tx_hash>   # one chain + its binding check
GET /api/guard/near/execution/chains            # the stored chains
```

A regression test (`tests/test_near_acceptance.py::test_http_evidence_chain_route_is_reachable_and_bound`)
drives the **real server** over a real socket: prepare → submit → read the chain
back and require `binding.bound is True` with the settlement stage's checks all
passing. A route registered in `GuardAPI` but not reachable through the server's
dispatch fails here.

## Honest limits

* The chain proves the *layers agree*; it does not re-decide anything. It records
  what each layer concluded and proves they refer to one transaction.
* A chain with a stage never populated is `bound` but incomplete; the reviewer
  sees which stages are present and which are absent.
* The signature re-verification runs whenever the chain carries a signature. The
  pipeline now recovers the signature from the exact signed bytes the submission
  ledger holds, so a chain written by a real run *does* carry it and the check
  runs; a chain assembled from a partial source that omits the signature skips the
  check (a limitation, never a pass).
* The chain is durable per instance (SQLite), not shared across instances.
