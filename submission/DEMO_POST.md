# Demo post — DRAFT (not posted)

The human publishes this. It has not been posted anywhere. Attach the demo video
or screenshots of the run.

---

Built at NEAR HACKATHON.

When a cross-chain swap goes wrong, the evidence is scattered across a service
status page, an origin-chain receipt, a NEAR transaction, and a destination
receipt — and each one speaks a different language. TRACESETTLE is a read-only
investigator for NEAR Intents (1Click) swaps. Give it a deposit address and it
reconstructs what actually happened, then keeps one distinction explicit: what is
independently verified on-chain, versus what a service merely reports.

It never signs, never holds funds, and never claims money was recovered.

In the demo it takes a real completed ETH → USDC swap and marks all four stages
independently CONFIRMED — source deposit, bridge credit, NEAR settlement
(verified by finding the intent hash in on-chain intent-execution logs), and
destination delivery (verified against the token, recipient, and amount in the
receipt logs) — for a final verdict of SETTLED_VERIFIED.

Then it shows the opposite: given only an intent hash, it refuses to overstate the
result. It returns SETTLED_REPORTED_ONLY and says exactly which stages it cannot
reach and why.

The part I care about most: a reported failure is not treated as proof funds were
lost, a reported refund of zero is not treated as proof no refund can occur, and a
transaction hash is never treated as proof that the event it describes is true.

Read-only, Python standard library, no API keys. Repo in the comments.

#NEAR #NEARIntents #hackathon

---

Notes for the human:
- Replace "Repo in the comments" with the actual public repository link, or put
  the link in the post body.
- Do not claim universal multi-chain support. Only chains with a configured public
  RPC can be independently verified.
- Do not claim cryptographic proof. The bridge credit is strong, identifier-based,
  on-chain corroboration; the memo is the bridge's own statement of which origin
  transaction it credited.
- Do not claim a live refund was verified. No real refunded transaction has been
  independently verified yet; refund handling is covered by labelled synthetic
  tests only. The demo does not show a refund.
- The demo's verified case is a real swap, but it depends on public endpoints being
  reachable at recording time. If a source is down the tool says so rather than
  showing a cached result, so record the demo while the endpoints respond.
