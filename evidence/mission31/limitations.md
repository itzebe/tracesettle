# Mission 31 — limitations

1. **No live API key.** The credential (`NEAR_INTENTS_AGENT_API_KEY`) is absent
   from the runtime; the mission supplied a placeholder, which was not consumed.
   The live authenticated `whoami`, agent list and policy read are therefore
   `ACCESS-BLOCKED`. Every offline and read-only check that does not need the key
   was completed.

2. **The local stub is a transport stand-in, not the live provider.** §2.2 of
   `README.md` drives the real adapter/parser/HTTP client against a local server
   that enforces the `X-API-Key` header and returns the provider's documented
   shapes. It proves the code path, not live provider state.

3. **No live policy was retrieved, so live enforcement was not demonstrated in
   this mission.** The enforcement code and its fail-closed behaviour are
   unchanged and independently verified from Missions 23/25/29.

4. **Agent discovery is paginated but single-page here.** `GET /v1/agents`
   returns `next_cursor`; `list_agents()` surfaces it but does not auto-page. A
   partner with more agents than one page would need to follow the cursor. This
   is stated rather than hidden.

5. **The Agent API is documented as experimental and mainnet-only.** This mission
   is strictly read-only: no deposit, swap, transfer, withdraw, sign, agent or
   grant creation, no owner-intent signing, no mainnet transaction, no cost.

6. **No secret is present in any artefact.** `evidence/mission31/provider_probe.json`
   contains only public, keyless probe output. The key is read only from the
   environment and is never logged, returned, or written.
