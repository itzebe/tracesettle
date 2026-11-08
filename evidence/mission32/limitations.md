# Mission 32 — limitations and blockers

1. **The credential is not in the runtime.** `NEAR_INTENTS_AGENT_API_KEY` (and all
   aliases, plus 12 candidate names) are absent. The live authenticated steps
   (whoami, agent discovery, policy read) could not be performed. This is the only
   blocker; every other step is complete. Fix: register the key under the secret
   name `NEAR_INTENTS_AGENT_API_KEY`.

2. **No live policy was retrieved, so live enforcement is not demonstrated.** The
   enforcement code and its fail-closed behaviour are unchanged and independently
   verified (Missions 23/25/29); the parser→gate connection is proven with a
   stub transport.

3. **The stub transport is not the live provider.** §4 of `README.md` runs the real
   adapter/parser/gate against a local server that enforces `X-API-Key`. It proves
   the code path, not live provider state.

4. **`list_agents()` surfaces `next_cursor` but does not auto-page.** A partner
   with more agents than one page would need to follow the cursor. Stated, not
   hidden.

5. **Strictly read-only.** No agent or grant creation, no deposit/swap/transfer/
   withdraw/sign, no owner-intent signing, no mainnet transaction, no paid call,
   no cost. Every operation performed was a keyless `GET` or an offline test.

6. **No secret in any artefact.** `provider_probe.json` and
   `authenticated_chain_stub.json` contain only public keyless output and a
   non-secret stub string (`stub-key-not-a-secret`) used against a local server.
