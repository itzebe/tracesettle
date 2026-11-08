# Mission 27 — limitations

Stated plainly, so nothing here is read as more than it is.

## What is established

* The exact signed NEAR transaction bytes are durably persisted (SQLite) before
  broadcast, and once written they cannot be silently replaced.
* After a process restart, a fresh instance recomputes the NEAR digest from those
  persisted bytes and independently re-verifies the ed25519 signature over it
  under the signer key the bytes name. This is proven against a real
  close/reopen, not an in-memory shortcut.
* The signed transaction is bound to the original authorization: the evidence
  chain's binding check fails if the receiver, amount, network, signer key,
  approved build or digest disagree between stages.

## What is NOT established by a stored signature

* **Genuine TEE execution.** A cryptographically valid signature does not prove it
  was produced inside an Intel TDX enclave. The chain's `ATTESTATION` stage is
  populated only from a *verified, nonce-bound, transaction-bound* attestation; in
  the offline pipeline used here it is absent, so the console reports "TEE
  attestation verified: no". The genuine-quote path is covered separately by the
  Mission 26 attestation work and the live hardware harness.
* **Provider identity.** The chain records the provider the durable execution
  record names, as a *reported* value; it is not independently proven here.
* **The approved build.** Recorded from the operator pin when one is configured
  (`SIGNATURE.approved_build` / `ATTESTATION.wasm_hash`); with no TEE signing
  boundary configured it is empty, and the chain records a limitation.
* **Settlement.** A stored signature says nothing about the on-chain outcome; that
  is established only by the independent settlement verification reading the chain
  back.

## Scope and environment

* **No live enclave signature was produced in this mission.** The OutLayer
  `/call` signing route is paid and fails non-refundably; the free on-chain route
  was exercised in Mission 25. This mission's work is offline and deterministic.
* **Testnet only.** Every run here is `testnet`; the network binding in the chain
  makes a cross-network substitution a real refusal. No mainnet activity occurred.
* **The RPC transport is substituted in tests.** `FakeNearRpc` stands in for the
  network boundary; the builder, guard, pipeline, strict decoder and stores are the
  real code paths. The on-chain read-back itself is exercised by the live testnet
  work recorded elsewhere.
* **In-memory default.** With no `TRACESETTLE_NEAR_LEDGER_DB` (and no chain-store
  path) the stores are in-memory, so a restart loses the ability to re-verify.
  That is the documented loopback default, not a defect — the durable capability
  is what a configured path provides.

## Persistence is per-instance

The SQLite ledger and chain store are durable for **one** instance, not shared
across instances. Multi-instance shared state exists for the guard's nonce/limit
state (PostgreSQL backend) but the execution ledger/chain here are file-backed.
Treating them as shared would be wrong.

## Tamper-detection honesty

The evidence chain is digest-linked and the binding checks fail closed, so an
in-place edit of a stage is detected. A whole-store rewrite with recomputed
digests is **not** detected by the chain alone — the same honesty note that
applies to the guard's audit log applies here. External anchoring (publishing a
chain digest) is the mitigation, and is out of scope for this mission.
