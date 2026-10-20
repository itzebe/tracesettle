# Publication checklist (draft — nothing here has been done yet)

Status: **not published, not pushed, not deployed, not posted.** This file is a
plan for the human to execute. Every step that leaves this machine is marked
DO NOT AUTOMATE.

## Hard rules from HACKATHON.md

- The repository must be **public** by 2026-11-14T23:59:00Z. Judges cannot open a
  private repository.
- The **human** publishes the demo post on X. An agent must not post on their
  behalf.
- The submission is sent **once**. A second submission with the same project name
  or email is rejected.
- Never without explicit human confirmation: send the submission, post publicly,
  make the repository public, push, sign transactions, deploy to mainnet, commit
  secrets.

## 1. Repository visibility

- [ ] Confirm the project name is final and unique across the hackathon.
- [ ] Create the public repository (human action).
- [ ] Push `master` with the audit history intact (human action — this workspace
      has **no git remote**, so nothing has been pushed).
- [ ] Confirm the README renders and the "do X → see Y" steps work from a clean
      clone with only the Python standard library.
- [ ] Confirm `tests/fixtures/synthetic/README.md` and `evidence/README.md`
      clearly label synthetic vs. real captures.
- [ ] Confirm no secrets, keys, `.env` files, or personal data are committed.
      (`git ls-files` review; `config.py` documents that it holds no secrets.)

## 2. Required links

- [ ] Public repository URL.
- [ ] Public demo post URL (X), with the demo video or screenshots attached.
- [ ] NEAR payout account (a named `*.near` account or 64-char implicit account).
      The human creates it in a NEAR wallet. Never invent one.

## 3. Demo post (human posts)

- [ ] Records a short demo: run `python3 demo/demonstrate.py` or the web UI on the
      real deposit address, showing `SETTLED_VERIFIED` with four `CONFIRMED`
      stages and the incomplete case.
- [ ] Post states the project was built at NEAR HACKATHON and attaches the demo
      media.
- [ ] Draft text is in `submission/DEMO_POST.md` (below).

## 4. Submission payload

- [ ] Collect every value under "What the human decides" (see `submission/SUBMISSION.md`).
- [ ] Generate `requestId` once: `uuidgen | tr A-Z a-z`.
- [ ] Print the full JSON payload and get the human's yes.
- [ ] POST to `https://nearhackathon.com/api/applications`.
- [ ] Do not commit the payload (it contains personal data).

## 5. Compliance checks already satisfied in-repo

- [x] No signing, custody, transaction submission, or recovery capability.
- [x] No private keys or seed phrases requested or stored.
- [x] No paid APIs or paid infrastructure; standard library only at runtime.
- [x] No fabricated balances, transaction hashes, timestamps, or live-status badges.
- [x] Synthetic fixtures are labelled and never presented as live evidence.
- [x] Read-only guarantee stated in the README and in every generated report.

## 6. Track selection (human decides)

The project fits at least:

- `defi` — cross-chain settlement via NEAR Intents.
- `security` — evidence integrity, read-only guarantees, no fabricated claims.

Choose every track that genuinely fits. One submission per team regardless.
