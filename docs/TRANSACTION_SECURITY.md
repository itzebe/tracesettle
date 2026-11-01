# Transaction Security: Guard, Authorization Firewall, Reference Signer

This document describes the security layer that sits *in front of* a signer. It
is deliberately explicit about what it can and cannot do, because the difference
matters.

## 0. The honest claim

TRACESETTLE is read-only. It does not hold funds, does not hold keys, and cannot
stop an arbitrary blockchain transaction.

What it does is provide an **enforcement boundary**: a component that a signer is
expected to call, and that refuses to release a transaction unless a
TraceSettle-issued, transaction-bound authorization is present, unexpired,
unused, and bound to exactly those transaction parameters. If the signer is
wired to call it, an unauthorized transaction never reaches the signing
operation. If the signer is not wired to call it, TraceSettle can still evaluate,
alert and record — but it cannot enforce.

The reference signer in `tracesettle/guard/signer.py` is a real, working
implementation of that boundary, including the executor that is *not* called on
refusal. It simulates execution; it never signs a real transaction and never
touches a chain.

## 1. The vertical slice

```
Transaction Request
   -> Risk Evaluation          (guard/rules.py: seven deterministic controls)
   -> Policy Decision          (guard/model.py: ALLOW | REQUIRE_APPROVAL | HOLD | BLOCK)
   -> Transaction-bound Authorization
                               (guard/authorization.py: HMAC-signed, parameter-bound,
                                single-use, short-lived)
   -> Independent Signer Validation
                               (guard/signer.py: re-derives the binding from the
                                transaction it was asked to sign, never trusts a flag)
   -> Execution or Refusal     (SimulatedExecutor, or a refusal with no executor call)
   -> Audit Record             (guard/audit.py: hash-chained, verifiable)
```

## 2. Controls (`guard/rules.py`)

Every control runs on every request. There is no short-circuit: the decision
carries the full picture, not the first reason found.

| Control | What it checks | Blocking findings |
| --- | --- | --- |
| `IDENTITY_ALLOWLIST` | the service is registered, enabled, and allowed this operation, chain and asset | `UNAUTHORIZED_SERVICE_IDENTITY`, `SERVICE_IDENTITY_DISABLED` |
| `DESTINATION_POLICY` | the destination is not on the denylist and, if the policy is allowlist-only, is on the allowlist | `DESTINATION_DENIED`, `UNAPPROVED_DESTINATION`, `MISSING_DESTINATION` |
| `AMOUNT_LIMITS` | the amount is within the per-transaction limit; amounts above the approval threshold need a human | `AMOUNT_EXCEEDS_LIMIT`, `AMOUNT_REQUIRES_APPROVAL` |
| `VELOCITY` | request rate, blocked-request rate, and the rolling per-asset volume a new request would produce | `REQUEST_VELOCITY_EXCEEDED`, `ABNORMAL_BLOCK_RATE`, `WINDOW_VOLUME_EXCEEDED` |
| `REJECTED_AUTHORIZATION_ATTEMPTS` | how many signing attempts this service had refused recently | `REPEATED_AUTHORIZATION_REJECTIONS` |
| `CLIENT_ASSERTED_APPROVAL` | whether the caller supplied its own approval or bypass flags | `CLIENT_ASSERTED_APPROVAL_IGNORED` |
| `REQUEST_INTEGRITY` | required parameters present and non-empty, amount non-zero | `MISSING_*`, `ZERO_AMOUNT` |

Amounts are `decimal.Decimal` throughout. A limit of `0.3` admits `0.3` and
refuses `0.30000000000000004`; a float comparison could not tell them apart. This
is asserted by the `amounts_are_exact_decimals` invariant.

Destination comparison normalises case only for EVM hex addresses. NEAR accounts,
Bitcoin addresses and base58 values are compared exactly, because case is
significant for them.

## 3. Decision and explanation

Each decision carries: a decision id, a timestamp, the request reference, the
policy id and version, every control result with its outcome and the policy that
produced it, the findings, a human-readable summary and explanation, and — for
ALLOW only — an authorization.

| Decision | Meaning | Authorization issued |
| --- | --- | --- |
| `ALLOW` | every control passed | yes |
| `REQUIRE_APPROVAL` | a human decision is needed | no |
| `HOLD` | rate or volume anomaly; retry later | no |
| `BLOCK` | a blocking finding | no |

## 4. Authorization (`guard/authorization.py`)

An authorization is a signed statement of exactly what was approved. It is not a
bearer token and it is not a claim by the caller.

Bound fields: `service_id`, `operation`, `chain`, `asset`, `amount`,
`destination`. Also carried: `authorization_id`, `nonce`, `issued_at`,
`expires_at`, `key_id`, and a `fingerprint` over the canonical binding.

- **Signature.** HMAC-SHA256 over the canonical JSON of the claim, using a key
  from `TRACESETTLE_GUARD_AUTH_KEY` (hex or base64, at least 32 bytes). With no
  key configured an ephemeral key is generated and the response reports
  `ephemeral: true`, so the operator can see that authorizations will not
  outlive the process.
- **Expiry.** Default 90 seconds (`TRACESETTLE_GUARD_AUTH_TTL`). Short by
  design: the window in which a leaked authorization is useful is small.
- **Single use.** The nonce is consumed atomically on successful validation. A
  second attempt is `REPLAYED`.
- **Verification levels.** `verify_only` checks validity without consuming the
  nonce, for a UI preview. `sign` consumes.

Validation states, each a distinct refusal reason:

`MISSING`, `MALFORMED`, `BAD_SIGNATURE`, `UNKNOWN_KEY`, `WRONG_SERVICE`,
`WRONG_PARAMETERS`, `NOT_YET_VALID`, `EXPIRED`, `REPLAYED`, `REVOKED`, `VALID`.

`WRONG_PARAMETERS` is the important one. The signer recomputes the canonical
binding from the transaction it was asked to sign and compares. A genuine,
unexpired, unused authorization minted for a *different* transaction is refused,
because the binding does not match. This is why an authorization is
transaction-bound rather than just authenticated.

## 5. Reference signer (`guard/signer.py`)

`ReferenceSigner.sign(SignRequest)` validates first and only then calls the
executor. On any non-`VALID` state it returns `SignOutcome.REFUSED` and the
executor is never invoked. The tests assert the executor call count directly, so
"refused" means "nothing was executed", not merely "a status was returned".

The receipt for a successful simulated execution states in its own text that it
is simulated and that no key was used.

## 6. Audit log (`guard/audit.py`)

Append-only, JSON Lines, hash-chained: each record carries the previous record's
digest and its own digest over all fields. `verify()` recomputes the chain.

Detected: a field edit, a digest edit, a reorder, a removal, a bad link.

**Not detected: a whole-log rewrite where every digest is recomputed.** An
attacker with write access to the file can produce a self-consistent chain. That
is why `head_digest` is exposed: anchoring it elsewhere (a log sink, another
host, a transparency log) is what would close the gap, and that anchoring is not
implemented here. The product therefore does not claim the log is tamper-proof;
it claims in-place modification is detectable. The test
`test_whole_log_rewrite_with_recomputed_digests_is_not_detected` asserts this
limit so the claim cannot drift into something stronger than the code supports.

A persistent log resumes its chain from the file on start-up. Without that, a
restart would begin a new chain at genesis and the persisted log would no longer
verify end to end.

## 7. Monitoring (`guard/monitor.py`)

Counters for evaluated, allowed, blocked, pending, authorizations issued,
executions, refusals, and open incidents. Incidents carry a code, severity,
status, and the identifiers involved, and can be acknowledged and resolved
(which is itself audited).

Incident codes include `UNAPPROVED_DESTINATION`, `DENIED_DESTINATION_ATTEMPT`,
`AMOUNT_LIMIT_BREACH`, `WINDOW_VOLUME_EXCEEDED`, `UNAUTHORIZED_SERVICE_IDENTITY`,
`REPEATED_BLOCKED_REQUESTS`, `REPEATED_AUTHORIZATION_REJECTIONS`,
`CLIENT_ASSERTED_APPROVAL`, and `SIGNER_REFUSAL`.

Severity is compared by an explicit `rank`, never by the severity's string value:
`"MEDIUM"` sorts after `"HIGH"` alphabetically, so a string comparison would
silently downgrade an outcome. This was a real defect caught by a test.

## 8. Structural invariants (`guard/invariants.py`)

Twelve guarantees, each checked by *running the real code* against an isolated
service, exposed at `GET /api/guard/invariants` and asserted in
`tests/test_guard_invariants.py`:

| Invariant | Guarantee |
| --- | --- |
| `non_allow_never_authorizes` | no BLOCK/HOLD/REQUIRE_APPROVAL decision carries an authorization |
| `refusal_never_reaches_the_executor` | a refused signing attempt never calls the executor |
| `authorization_is_bound_to_parameters` | a token bound to other parameters is refused as `WRONG_PARAMETERS` |
| `authorization_is_single_use` | a second use is refused as `REPLAYED` |
| `expiry_is_enforced` | a token outside its window is refused |
| `client_assertions_never_allow` | caller-supplied approval flags never produce ALLOW |
| `audit_chain_detects_modification` | an edited record is detected |
| `no_key_material_in_output` | no response or metric carries the signing key |
| `unregistered_identity_never_executes` | an unregistered identity is blocked and nothing executes |
| `amounts_are_exact_decimals` | `0.3` is admitted, `0.30000000000000004` is refused |
| `service_identity_cannot_be_forged` | a credential authenticates one identity; a mismatched `service_id` is refused |
| `service_credentials_are_hashed_at_rest` | only a one-way hash is stored; the plaintext secret never appears |

Every checker is also mutation-tested: the guarded behaviour is deliberately
broken and the checker is shown to notice. A checker that cannot fail proves
nothing.

## 9. HTTP interface

All routes are same-origin, stdlib-only, and return JSON. The console page is a
single document with no third-party origins and a restrictive
`Content-Security-Policy`.

| Method | Path | Purpose |
| --- | --- | --- |
| `GET` | `/console` | the security operations console |
| `GET` | `/api/guard/policy` | the active policy |
| `GET` | `/api/guard/metrics` | counters and current state |
| `GET` | `/api/guard/incidents` | incidents (`?status=`, `?limit=`) |
| `POST` | `/api/guard/incidents/{id}/status` | acknowledge or resolve |
| `GET` | `/api/guard/audit` | audit records (`?verify=1` to check the chain) |
| `GET` | `/api/guard/scenarios` | the three labelled simulation scenarios |
| `GET` | `/api/guard/invariants` | run the twelve structural checks now |
| `POST` | `/api/guard/evaluate` | evaluate a transaction request |
| `POST` | `/api/guard/sign` | attempt a signing through the reference signer |

Controls:

- `TRACESETTLE_API_KEY` gates the guard endpoints with a constant-time
  comparison. `GET /console` and `GET /api/health` stay open. Unset means open,
  which suits a loopback-only deployment; a public bind with it unset refuses to
  start (see *Fail-closed startup* below).
- **Per-service authentication.** When a credential store is configured, the two
  service-facing routes (`evaluate`, `sign`) also require a valid
  `X-Service-Credential`. The credential resolves to one `service_id`, and a
  request whose declared `service_id` differs is refused with `403`. The
  administrative routes (incident status) stay gated by the API key alone, so the
  two authentication planes remain separate. When no store is configured the
  behaviour is unchanged.
- Per-client rate limiting keyed on the socket peer address, so a spoofed
  `X-Forwarded-For` cannot bypass it. `429` carries `Retry-After`.
- Request bodies are bounded by `TRACESETTLE_GUARD_MAX_BODY_BYTES` (8 KiB) and
  rejected before being read.
- The signing key is never returned by any endpoint, and the console never
  receives it.

## 9b. Per-service authentication (`serviceauth.py`)

The policy layer evaluates a transaction for the service the request *names*. On
its own that lets one service name another and inherit its policy. Each service
can be issued a credential, and the credential — not the request body — is the
source of identity:

- `ServiceRegistry` stores only a one-way `sha256:` hash per credential; the
  plaintext secret is returned once, at mint time, and never persisted.
- `authenticate()` compares in constant time over every credential, so the check
  does not reveal which credential matched or how many exist.
- A credential can expire (`expires_at`) or be revoked; either is refused.
  `rotate()` issues a new secret and revokes the previous one (overlap optional).
- `guard/api.py` compares the request's declared `service_id` against the
  authenticated identity and refuses a mismatch with `403`. This is checked in
  the API, not only in the socket handler, so a direct caller cannot bypass it.
- Manage credentials with `python3 -m tracesettle credentials mint|list|revoke`;
  `list` and `revoke` never print a secret, and the store is written `0600`.
  The read-modify-write of the store is serialised with an exclusive lock
  (`<store>.lock`), so two concurrent commands cannot lose one another's change
  or silently restore a credential the other just revoked.

## 9c. Fail-closed startup (`securityconfig.py`)

`serve` validates its posture *before* opening a socket and refuses to start when
it would expose protected endpoints without authentication:

- A non-loopback bind requires `TRACESETTLE_API_KEY` **and**
  `TRACESETTLE_GUARD_AUTH_KEY`; otherwise the process exits `2` naming the missing
  variables. Only a value that provably parses as loopback is treated as local,
  so an unknown or empty host fails closed.
- `TRACESETTLE_REQUIRE_SERVICE_AUTH` without a credential store refuses to start
  on any binding.
- There is no override: a public bind without the required credentials always
  refuses to start, so no environment variable can expose the endpoints.

## 10. Running it

```sh
python3 -m tracesettle serve --port 8080
# then open http://127.0.0.1:8080/console
```

The console has three labelled simulation scenarios. They are simulations: the
transactions are fixtures and no chain is touched. Their memory/decision
outcomes are real — the same code path that handles a live request — but the
transactions themselves are not real, and the console says so on the page.

## 11. Configuration

| Variable | Default | Purpose |
| --- | --- | --- |
| `TRACESETTLE_GUARD_AUTH_KEY` | ephemeral | HMAC key for authorizations (hex or base64, ≥32 bytes) |
| `TRACESETTLE_GUARD_AUTH_TTL` | 90 | authorization lifetime in seconds |
| `TRACESETTLE_GUARD_POLICY` | built-in | path to a JSON policy override |
| `TRACESETTLE_GUARD_AUDIT_LOG` | in-memory | path to a persistent audit log |
| `TRACESETTLE_GUARD_MAX_BODY_BYTES` | 8192 | request body cap |
| `TRACESETTLE_API_KEY` | unset | guards the guard endpoints |
| `TRACESETTLE_SERVICE_CREDENTIALS` | unset | path to a per-service credential store |
| `TRACESETTLE_SERVICE_CREDENTIALS_JSON` | unset | inline credential store (precedence over the path) |
| `TRACESETTLE_REQUIRE_SERVICE_AUTH` | unset | require a service credential on every service-facing request |

A policy file overrides only the fields it names; everything else keeps the
default, so a partial file is a valid override.

## 12. What is not implemented

Stated plainly, so nothing is mistaken for done:

- **Enforcement is only as strong as the signer's willingness to call the
  boundary.** TraceSettle cannot revoke a key it does not hold.
- **No external anchoring of the audit head digest**, so a full rewrite of a
  persistent log is not detectable by the tool alone.
- **No hardware-backed key.** The authorization key is a process secret; a
  compromise of that key allows forging authorizations.
- **No multi-signature approval flow.** `REQUIRE_APPROVAL` records the need; the
  approval itself is a future integration.
- **No live chain submission.** The executor is simulated by design; the
  read-only invariant is not traded away for a demo.
- **No durable incident store.** Incidents are in memory and reset on restart;
  the audit log can persist, incidents cannot yet.
- **No NEAR-side on-chain policy enforcement** (for example a function-call key
  scoped to an approved contract and method). That is the natural next step for
  the `security` track and is not built.
