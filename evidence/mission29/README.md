# Mission 29 — release verification evidence

Date: 2026-11-08. **Testnet only. Zero cost. No mainnet, no paid call, no deploy.**
All numbers below were produced by commands run on this branch; none are copied
from a prior mission.

## What this directory proves

| File | Proves |
| --- | --- |
| `live_tee_signing.json` / `.md` / `.py` | a **fresh** genuine Intel TDX enclave (OutLayer on-chain route, free testnet NEAR) signed a real NEAR testnet transaction; full 7-link provenance to `TEE_SIGNING_VERIFIED` |
| `provider_authorization.md` | the NEAR Intents Agent API policy endpoint is real (live `401` without a key); the gate is implemented and fail-closed; the exact credential blocker |
| `../mission27/independent_restart_verification.{py,json}` | **cross-process** post-restart independent re-verification of the recorded signature (this mission) |

## Independent re-reads performed this mission (read-only, free)

- Enclave-signed transfer `7dffFM6trTHVRUEBYXVnLscASersQA29RktWfSmvnMZ2` →
  `FINAL`, signer `ee678ff2b2243fa83e63582f7e017027470be84c55f8deaef87f72244f1a6fb7`
  (`rpc.testnet.near.org`).
- Enclave `request_execution` tx `GMpwjDeTXo57PjfmNcXMq6sqFD3F8RwJxfTZ67SJ6nTQ` →
  `FINAL`, signer `ts-m29-2c05f8.testnet`, receiver `outlayer.testnet`.
- **The signing identity is genuine:** the enclave public key
  `ed25519:H3dd94sk1df1t2PVyQWjD9cyzDAKh2WceAFmP3tWdC2a` decodes (base58, 32 bytes)
  to exactly `ee678ff2…a6fb7`, the implicit account that signed the transfer. The
  key and the on-chain signer are the same identity, not a coincidence.

## Cross-process restart verification (the Mission 27 acceptance test, strengthened)

`independent_restart_verification.py` signs in **process A**, then a genuinely
fresh `python -c` **process B** opens only the SQLite ledger file and:

1. reads the persisted signed bytes (`signed_bytes_present`),
2. recomputes the NEAR digest `sha256(borsh(Transaction))` from them
   (`digest_recomputed`, `digest_source=recomputed_from_persisted_signed_bytes`),
3. re-verifies the ed25519 signature over that digest under the key the bytes name
   (`signature_verifies_over_digest`),
4. strictly decodes and re-serializes to the same bytes (`decode_round_trips`),
5. confirms the decoded signer/receiver/amount/destination equal the record
   (`record_matches_signed_bytes`).

Result: `verified: true`, `state: VERIFIED`, all five checks hold. Then the driver
tampers one byte of the persisted bytes on disk; the fresh process returns
`verified: false`, `state: UNVERIFIED`, failing exactly `decode_round_trips`,
`signature_verifies_over_digest`, `record_matches_signed_bytes`. So the check is
not vacuous.

## Full-suite and gate results (this branch, `feat/mission29-release-closure`)

| Check | Command | Result |
| --- | --- | --- |
| Full suite (filesystem) | `python -m pytest tests/ -q` | **1952 passed, 34 skipped** |
| Full suite (PostgreSQL 16) | `TRACESETTLE_TEST_PG_DSN=… pytest tests/ -q` | **1976 passed, 10 skipped** |
| NEAR durable-signature + decode + provenance + chain + build | `pytest tests/test_near_durable_signature.py tests/test_near_txdecode.py tests/test_near_signing_provenance.py tests/test_near_evidence_chain.py tests/test_near_reproducible_build.py -q` | **89 passed** |
| Invariant mutation tests (signing) | `pytest tests/test_near_invariants.py -k "durable_signature or evidence_chain or attested_signing or onchain"` | **7 passed** |
| Guard invariants | `invariants.check_all()` | **64/64 hold, 0 failing** |
| Static analysis | `python -m pyflakes tracesettle/ tests/ demo/ evidence/` | clean |
| Compile | `python -m compileall -q tracesettle/` | OK |
| Offline demo determinism | `demo/demonstrate.py --offline` ×2 | md5 `4864f13c1c08cf1b8b871a64102848bf` (identical, matches baseline) |
| Docker image | `docker build` + run | non-root uid 10001, `/api/health` 200, `Server: TRACESETTLE` |
| Docker fail-closed | run with `0.0.0.0` and no credentials | refuses to start (exit 2) |
| Secret scan | high-signal patterns over every blob in every ref | no real credential |

## What is genuinely proven vs what is not

**Genuinely proven (this mission, live):** a real Intel TDX enclave signed a real
NEAR testnet transaction; the enclave key is the on-chain signer; the persisted
bytes re-verify the signature in a fresh process; the signature is bound to the
authorized transaction.

**Not proven / access-blocked:** a *successful authenticated* live read of the
NEAR Intents Agent API policy (no `X-API-Key` in a zero-budget environment; the
endpoint is real and answers `401`). The provider policy gate is enforced in code
and fail-closed, but its live authenticated read is integration-tested only.

## Constraints honoured

No mainnet. No paid call. No credential exposed. No merge of PR #26 (it was
integrated to master by the release-closure work, not by this mission). No
deploy. No repository-visibility change. No signing of any mainnet transaction.
