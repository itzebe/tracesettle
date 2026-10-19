# Official documentation (vendored copies)

Verbatim copies of the official documentation used in Phase 1, saved so the feasibility report can be
audited offline. Each was fetched from the source noted below on **2026-10-19 (UTC)**.

Docs are served by Mintlify; appending `.md` to any page URL returns the raw markdown. The full page index
is at `https://docs.near-intents.org/llms.txt`.

| File | Source URL |
| --- | --- |
| `HACKATHON.md` | `https://nearhackathon.com/HACKATHON.md` |
| `api-reference_oneclick_check-swap-execution-status.md` | `https://docs.near-intents.org/api-reference/oneclick/check-swap-execution-status.md` |
| `api-reference_oneclick_request-a-swap-quote.md` | `https://docs.near-intents.org/api-reference/oneclick/request-a-swap-quote.md` |
| `api-reference_oneclick_submit-deposit-transaction-hash.md` | `https://docs.near-intents.org/api-reference/oneclick/submit-deposit-transaction-hash.md` |
| `api-reference_oneclick_get-supported-tokens.md` | `https://docs.near-intents.org/api-reference/oneclick/get-supported-tokens.md` |
| `api-reference_get-transactions.md` | `https://docs.near-intents.org/api-reference/get-transactions.md` |
| `integration_distribution-channels_1click-api_about-1click-api.md` | `https://docs.near-intents.org/integration/distribution-channels/1click-api/about-1click-api.md` |
| `integration_distribution-channels_1click-api_quickstart_introduction.md` | `https://docs.near-intents.org/integration/distribution-channels/1click-api/quickstart/introduction.md` |
| `integration_distribution-channels_1click-api_quickstart_making-a-request.md` | `https://docs.near-intents.org/integration/distribution-channels/1click-api/quickstart/making-a-request.md` |
| `integration_verifier-contract_events.md` | `https://docs.near-intents.org/integration/verifier-contract/events.md` |
| `integration_bridging_btc-deposit-refund.md` | `https://docs.near-intents.org/integration/bridging/btc-deposit-refund.md` |
| `integration_devkit_intents-sdk.md` | `https://docs.near-intents.org/integration/devkit/intents-sdk.md` |
| `learn_omni-bridge_how-it-works.md` | `https://docs.near-intents.org/learn/omni-bridge/how-it-works.md` |
| `resources_chain-support.md` | `https://docs.near-intents.org/resources/chain-support.md` |
| `resources_faqs.md` | `https://docs.near-intents.org/resources/faqs.md` |

Refresh with:

```sh
for p in \
  integration/distribution-channels/1click-api/quickstart/making-a-request \
  api-reference/oneclick/check-swap-execution-status \
  resources/chain-support ; do
  f=$(echo "$p" | tr '/' '_')
  curl -s -o "docs/official/$f.md" "https://docs.near-intents.org/$p.md"
done
```
