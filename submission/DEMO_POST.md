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

Then a real refunded swap: the service reports a refund, and the tool treats that
report as a claim, not a fact. It looks for the actual Bitcoin payout to the
intent's on-chain withdrawal recipient and confirms it only when it can be tied to
this intent by an explicit identifier — the provider naming the transaction, or
exactly one confirmed payout matching — and then validating the raw bytes itself.
When the provider named the refund transaction (as its record did on 2026-10-19),
the refund reads CONFIRMED and the verdict is REFUND_VERIFIED. When it names
nothing and several payouts match, the refund stays a reported claim and reads
UNAVAILABLE — a missing correlation, never a failed refund. It never picks a payout
by amount or timestamp, and it never claims the refund was verified without a
transaction it checked.

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
- Do not claim a refund is verified without a transaction the tool checked. The
  demo includes a real refunded swap; whether the refund confirms depends on what
  the provider exposes at recording time. If the provider names the transaction (as
  its record did on 2026-10-19) the verdict is REFUND_VERIFIED; if it names nothing
  and several payouts match, the refund stays UNAVAILABLE. State the outcome the
  run actually showed rather than a fixed one.
- The demo's verified case is a real swap, but it depends on public endpoints being
  reachable at recording time. If a source is down the tool says so rather than
  showing a cached result, so record the demo while the endpoints respond.
