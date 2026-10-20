# Submission payload — DRAFT (not sent)

Do not send this. Fill every value from the human's answers, print the payload,
and wait for their explicit confirmation. The example values below are placeholders
shaped like the contract; they must never be sent as-is.

Generate `requestId` once and reuse it on retries:

```sh
uuidgen | tr A-Z a-z
```

## Fields the human must decide

| Field | Rule | Value |
| --- | --- | --- |
| requestId | UUID, generated once, reused on retries | _(generate)_ |
| projectName | 2–80 chars, unique (case-insensitive) | `TRACESETTLE` _(confirm)_ |
| leadName | 2–80 chars | _(ask)_ |
| email | valid email, max 160 chars, unique | _(ask)_ |
| size | one of `1`, `2 - 4`, `4 - 6`, `6 - 8`, `8+` | _(ask)_ |
| tracks | ids from the Tracks table | _(ask; likely `defi`, `security`)_ |
| nearAddress | mainnet account, lowercase, 2–64 chars | _(ask; human creates it)_ |
| projectUrl | public repository URL, max 300 chars | _(ask)_ |
| demoUrl | public demo post URL, max 300 chars | _(ask)_ |
| idea | 20–2000 chars | _(draft below)_ |
| consent | `true` only after the human agrees to the notice | _(ask)_ |

Do not add other fields. A non-empty `website` field is a spam trap and rejects
the submission.

## Draft `idea` text (edit before sending)

TRACESETTLE is a read-only settlement investigator for NEAR Intents (1Click)
cross-chain swaps. When a swap is disputed, the evidence is spread across a 1Click
status record, an origin-chain receipt, a NEAR transaction, and a destination
receipt, each with its own status vocabulary. TRACESETTLE reconstructs that
evidence, separates what is independently verified on-chain from what a service
merely reports, flags contradictions and gaps, and produces an evidence-backed
report. NEAR is central: the tool reads NEAR RPC transaction and DIP-4
intent-execution event logs to confirm settlement by finding the investigated
intent hash on-chain, and reads the bridge transfer memo to link an origin-chain
transaction to the NEAR deposit credit by an explicit identifier rather than by
amount or timestamp. It keeps "missing" and "unavailable" distinct from "failed":
a refund it cannot check stays UNAVAILABLE, never "no refund". It is deterministic,
standard-library only, and never signs, submits, or moves funds.

## Send command (only after confirmation)

```sh
curl -sS -X POST https://nearhackathon.com/api/applications \
  -H 'Content-Type: application/json' \
  -d '{"requestId":"<uuid>","projectName":"TRACESETTLE","leadName":"<name>","email":"<email>","size":"<size>","tracks":["defi","security"],"nearAddress":"<account>.near","projectUrl":"<repo url>","demoUrl":"<demo post url>","idea":"<idea>","consent":true}'
```

Response handling:

| Status | Meaning | Action |
| --- | --- | --- |
| 201 | Saved | Done. Tell the human. |
| 400 | Field failed validation | Fix the listed fields, resend with the same requestId. |
| 403 | Not open, or cross-site | Tell the human. Do not retry. |
| 409 | Name or email already used | Ask the human. Do not rename to work around it. |
| 413 | Body too large | Shorten `idea`. |
| 503 | Storage unavailable | Wait a minute, resend with the same requestId. |

Do not commit this payload: it contains personal data.
