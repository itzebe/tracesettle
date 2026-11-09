# Mission 30 — test and verification results

All results are from commands actually run in this session. A check that was not
run is not listed as passing.

## Test suites

| Command | Result |
| --- | --- |
| `.venv/bin/python -m pytest tests/ -q` (filesystem only) | **1970 passed, 34 skipped** |
| `TRACESETTLE_TEST_PG_DSN=… pytest tests/ -q` (PostgreSQL 16) | **1994 passed, 10 skipped** |
| `pytest tests/test_near_policy.py -q` | 44 passed |
| `pytest tests/test_tee_verify_cli.py tests/test_near_policy.py -q` | 57 passed |
| `pytest tests/test_near_durable_signature.py -q` | 29 passed |
| `pytest tests/test_guard_invariants.py tests/test_near_invariants.py -q` | 141 passed |

The 14 new tests added by this mission are in `tests/test_near_policy.py` (7
`PolicyView` regression tests) and `tests/test_tee_verify_cli.py` (4 provider-auth
CLI tests) plus 3 earlier policy tests.

## Static analysis and build

| Check | Result |
| --- | --- |
| `.venv/bin/python -m pyflakes tracesettle/ tests/ evidence/mission30/provider_probe.py` | clean |
| `.venv/bin/python -m compileall -q tracesettle/` | OK |
| `demo/demonstrate.py --offline` run twice | byte-identical, md5 `4864f13c1c08cf1b8b871a64102848bf` |

## Mutation test — the `PolicyView` fix is not vacuous

Neutralising the envelope handling (`body = raw` instead of the nested `policy`)
made three tests fail:

```
FAILED tests/test_near_policy.py::test_policy_view_rules_are_read_from_the_nested_policy
FAILED tests/test_near_policy.py::test_policy_view_native_methods_use_the_documented_array_form
FAILED tests/test_near_policy.py::test_adapter_reads_a_policy_view_from_the_provider
3 failed, 41 passed
```

The fix was restored; `44 passed`.

## Live, read-only provider probes (no key sent)

From `provider_probe.json`:

| Call | HTTP | Result |
| --- | --- | --- |
| `GET /openapi.json` | 200 | "NEAR Intents Agent API", securitySchemes `[ApiKey, GrantToken]`, 40 `/v1/…` paths |
| `GET /v1/network` | 200 | `network: mainnet`, `contract_id: outlayer.near`, `status.overall: operational` |
| `GET /v1/whoami` (no key) | 401 | `invalid_api_key` — the documented auth boundary |

The authenticated read path was exercised against the real host with an
obviously-invalid key; the provider answered `401 invalid_api_key`, and the CLI
classified it correctly as "the provider rejected the key" without printing the
key. A live `200` requires a valid key, which is `ACCESS-BLOCKED` in this
runtime (see `limitations.md`).
