# NEAR integration fixtures

Every file here is **synthetic**. It reproduces the *shape* documented by the
providers so the NEAR integration can be exercised deterministically and
offline, with no network and no cost. None of it is live provider state, and no
file here is presented as evidence about a real agent, account, or transaction.

| File | Reproduces | Source of the shape |
| --- | --- | --- |
| `policy_in_force.json` | an applied, provider-synced agent policy | `docs.agentsonintents.com/integration/agent-api/policies-and-limits` |
| `policy_not_applied.json` | a signed-but-not-applied policy update | same |
| `policy_native_transfer.json` | a policy with `native.near.transfer` on | `.../agent-api/native-accounts` |
| `access_keys.json` | full-access, function-call and gas keys | `docs.near.org/protocol/accounts-contracts/access-keys` |
| `README.md` | this provenance note | — |

The fixtures carry a `_provenance` field marking them synthetic, in the same
style as `tests/fixtures/synthetic/`. Real captured 1Click/NEAR responses live
in `evidence/raw/` and are never mixed with these.
