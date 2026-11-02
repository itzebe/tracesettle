# External audit-chain anchoring — design and proposal

> **STATUS: NOT IMPLEMENTED.** TraceSettle exposes the audit-chain head digest so
> a deployment *can* anchor it, but no anchoring is performed by the code today.
> Nothing in this document describes a feature that exists. This is a proposal.

## 1. The gap

`tracesettle/guard/audit.py` builds a SHA-256 hash chain over every
security-relevant event (evaluation, authorization issuance, signing attempt,
refusal, incident). Each record's digest covers the previous record's digest, so
in-place edits, reorders, and deletions break the chain from that point, and
`AuditLog.verify()` proves it by recomputation.

The module states its own limit plainly: this is **tamper-evidence, not
tamper-proofness**. A party who can rewrite the entire log can recompute every
digest and produce a chain that verifies. Detecting that requires an **external
anchor**: a copy of the head digest the attacker cannot rewrite.

Today `AuditLog.head_digest` returns the latest record's digest (or the genesis
digest for an empty log). Nothing publishes it. That is the gap.

## 2. What an anchor must prove

- A specific head digest (and ideally the sequence number it covers) existed at
  or before a point in time.
- It must be independently verifiable without trusting the TraceSettle host.
- It must not leak sensitive data — publish only a digest, never record contents.

## 3. Options considered

| Option | Cost | Permanence | Public verifiability | Operational complexity | Key management |
| --- | --- | --- | --- | --- | --- |
| **OpenTimestamps (Bitcoin)** | Free | Bitcoin-chain (~10y+ proven) | Anyone, offline, no third party at verify time | Low: submit digest, later upgrade the proof | None (no keys) |
| **Sigstore Rekor** | Free (public log) | Transparency log, append-only | Yes, with monitors | Low–medium | Signing key for the entry |
| **Public blockchain (e.g. NEAR, Ethereum) tx with the digest in data** | Gas per tx ($1–50) | Chain | Yes | Medium (wallet, key) | A funded key — extra custody risk |
| **Immutable object storage (WORM bucket)** | Storage only | Vendor-dependent | Only with the vendor's guarantee | Low | Cloud credentials |
| **RFC 3161 timestamp authority** | Free–low | Trust the TSA | Yes | Low | None |

### Recommendation

**Primary: OpenTimestamps.** It is free, needs no key (so it adds no custody
risk), and the proof verifies against the Bitcoin chain with no third party
trusted at verification time. Its cost profile matches a low-frequency anchor
(e.g. one digest per batch or per hour). It is the only option that satisfies the
**$0 constraint with no credit-card commitment**, which is why it is the sole
recommendation here.

**Secondary (defence in depth): Sigstore Rekor**, which adds a transparency-log
monitor that alarms on inconsistency. This is optional and can follow later.

Avoid putting digests on a public chain with a funded key: it adds key custody
and spend risk for no benefit over OpenTimestamps at this scale, and it would
require a purchase.

## 4. Recommended architecture

1. **Generate the head digest.** Already available: `AuditLog.head_digest` (plus
   `len(AuditLog)` for the covered sequence). No new cryptography.
2. **Publish the digest externally.** On a schedule (e.g. every N records or
   every hour), submit `(sequence, head_digest)` to OpenTimestamps calendar
   servers. The calendar returns a pending `.ots` proof.
3. **Record the external reference.** Store the `.ots` proof (and later the
   upgraded Bitcoin-verified proof) alongside the sequence/digest, outside the
   rewriteable log — e.g. in the audit volume and mirrored to independent
   storage.
4. **Verify the anchor independently.** A verifier re-reads the local log,
   recomputes the digest for the anchored sequence, and checks the `.ots` proof
   against Bitcoin. Neither step trusts the TraceSettle host.
5. **Detect divergence.** The monitor keeps the last anchored digest it verified
   in storage the operator cannot write. If a later anchor does not extend the
   previously verified chain (same prefix, higher sequence), that is a
   divergence — tampering, a restore-from-backup, or a bug — and must alarm.

## 5. Code changes this would require (proposal only — do not implement yet)

- A new module, e.g. `tracesettle/guard/anchoring.py`, with:
  - `anchor_head(audit_log, submitter)` — submit `(sequence, head_digest)` to a
    calendar; return a proof object. Failures are recorded, never crash the
    request path.
  - `verify_anchor(records, proof)` — recompute and check.
  - A `Submitter` protocol so the calendar client is injectable and testable
    without network access (mirrors the existing `FakeOpener` test approach).
- Config: `TRACESETTLE_GUARD_ANCHOR_ENABLED`, `TRACESETTLE_GUARD_ANCHOR_INTERVAL`,
  `TRACESETTLE_GUARD_ANCHOR_PATH` (where proofs are stored).
- A scheduler (a small thread or a `tracesettle anchor` subcommand) — the anchor
  must not run inside the request path.
- Tests: proof round-trip with a fake submitter; divergence detection; a failed
  submit leaves the log intact and raises an alert, not an exception.

## 6. Anchoring does not replace the existing guarantees

Anchoring adds "this log existed by time T". It does not make the log
tamper-proof in real time, and it does not remove the need for the monitor in
step 5 — an anchor that is never checked proves nothing. Treat the monitor as
part of the feature, not an add-on.

## 7. Interim mitigation available today

Until anchoring is implemented, a deployment can manually preserve the head
digest: read `GET /api/guard/metrics` (or the audit file) and copy the head
digest into an independent, append-only place (a signed release, a public gist,
an email to an auditor) on a schedule. This is weaker than OpenTimestamps (it
trusts the operator) but strictly better than keeping the digest only on the host
being audited.
