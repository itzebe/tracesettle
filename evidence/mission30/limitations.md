# Mission 30 — limitations (honest)

1. **A successful live authenticated read was not performed.**
   `NEAR_INTENTS_AGENT_API_KEY` is not present in this runtime (`len == 0`; the
   name is absent from the injected-secret set). The read path is implemented and
   proven to reach the provider (invalid key → `401 invalid_api_key`), but no live
   `200` was obtained. This is an environment/credential limitation, not a code
   limitation. The key was to be supplied via the secure secret input; it is not
   registered.

2. **The provider is mainnet.** `/v1/network` reports `network: mainnet`,
   `contract_id: outlayer.near`. Only **read-only, free** calls were made
   (`/openapi.json`, `/v1/network`, `/v1/whoami`). No write, no swap, no
   withdraw, no transfer, no signing, no paid call.

3. **No agent id was exercised live.** A real policy read needs both a live key
   and an agent id the key can read. Neither was available, so the live policy
   read is untested end-to-end; the parser is tested against the documented shape.

4. **`budget_spent_usd` semantics.** It is the maximum `spent_usd` across the
   provider's daily/weekly/monthly usage windows. The provider does not publish a
   single lifetime "spent" figure, so this is a conservative summary, labelled as
   such; it is never used to *raise* a decision.

5. **Native method arrays are treated as on/off.** The documented
   `sign_message` / `call` / `sign_transaction` arrays name permitted values
   (message prefixes, contract ids, selectors). This module records only whether
   the switch is on; the *contents* are preserved in `raw` but not yet used to
   scope a specific native call. A future change must not treat a non-empty array
   as "any value permitted".

6. **No policy write path.** This module is read-only by design; it never signs a
   policy update, freezes, or unfreezes. Nothing here can change provider state.
