<!-- NEAR HACKATHON HACKATHON.md -->
# NEAR HACKATHON - HACKATHON.md

Instructions for the AI coding agent helping a team take part in NEAR HACKATHON. The live version is https://nearhackathon.com/HACKATHON.md; read it again before submitting, because dates and rules may change.

## Start here

1. Build the project with the human. There is no sign-up before the hackathon: the only form is the final submission.
2. Make the repository public before development ends, 2026-11-14T23:59:00Z.
3. The human publishes a demo post on X: it says the project was built at NEAR HACKATHON and has the demo video or screenshots attached.
4. Submit once: POST to https://nearhackathon.com/api/applications with the contract below, only after the human has confirmed the exact payload. Skip this step if the team has already submitted.

## Facts

| Fact | Value |
| --- | --- |
| Event | NEAR HACKATHON |
| Website | https://nearhackathon.com |
| Hackathon starts | 2026-11-01T00:00:00Z |
| Development ends (submission deadline) | 2026-11-14T23:59:00Z |
| Judging starts | 2026-11-16T00:00:00Z |
| Results announced by | 2026-11-18T23:59:00Z |
| Submission form | https://nearhackathon.com/#apply |
| Submission API | POST https://nearhackathon.com/api/applications |
| NEAR docs | https://docs.near.org/ |
| NEAR Discord | https://discord.gg/RhZGHPXPf2 |
| X | https://x.com/NEARProtocol |
| This file, live | https://nearhackathon.com/HACKATHON.md |

All times are UTC. One submission per team.

## What the human decides

Collect these before submitting. Do not guess, generate or fill in placeholders for any of them:

- Project name (2-80 characters, unique across the hackathon)
- Team lead's name (2-80 characters)
- Contact email (unique across the hackathon, max 160 characters)
- Team size, one of: `1`, `2 - 4`, `4 - 6`, `6 - 8`, `8+`
- Tracks: one or more ids from the Tracks table below, every track the project fits. It is still one submission per team.
- NEAR account for the prize payout, mainnet: a named account such as `team.near` or a 64-character implicit account. The team creates it in any NEAR wallet; see https://docs.near.org/. Never create or invent one on their behalf.
- Link to the public repository judges will review.
- Link to the public demo post. The human writes and publishes it themselves.
- What they built (20-2000 characters): the problem, the product, and how NEAR fits in.
- Consent to the contact notice, read to them verbatim: "I agree that the organizers may use these details to review our submission and contact us about this hackathon."

## Never without the human's explicit confirmation

- Send the submission. Print the full JSON payload first and wait for a yes. A second submission with the same project name or email is rejected, so there is one attempt per team.
- Post anything on X or another network on their behalf.
- Make the repository public, push, or force-push.
- Sign transactions, spend tokens or deploy to mainnet.
- Commit secrets. Keys belong in environment variables, never in the repository.

## Procedure

### 1. Build and publish the repository

The repository may stay private while the team builds, but it must be public by 2026-11-14T23:59:00Z. Judges cannot open a private one. The jury includes AI judges, so write the README for a machine reader as well as a human one: what the product is, the problem it solves, and how to try it as "do X - see Y" steps a judge can follow. No marketing.

### 2. The demo post

The human records a demo and publishes a public post on X: it says the project was built at NEAR HACKATHON and has the demo video or screenshots attached. You can draft the text; the human posts it and gives you the link.

### 3. Submit

Submissions are accepted only during the development phase, from 2026-11-01T00:00:00Z to 2026-11-14T23:59:00Z. Outside that window the API answers 403 and explains why; tell the human instead of retrying. A submission cannot be edited, so send it when the repository is public and the demo post is up.

Validate every field against the contract below, print the payload for the human, and send it only after they confirm:

```sh
curl -sS -X POST https://nearhackathon.com/api/applications \
  -H 'Content-Type: application/json' \
  -d '{"requestId":"XXXXXXXX-XXXX-XXXX-XXXX-XXXXXXXXXXXX","projectName":"Example Project","leadName":"Ada Lovelace","email":"ada@example.com","size":"2 - 4","tracks":["defi","realworld"],"nearAddress":"example-team.near","projectUrl":"https://github.com/example-team/example-project","demoUrl":"https://x.com/example-team/status/0000000000000000000","idea":"What problem the team solves, what they built, and how NEAR fits in. At least twenty characters.","consent":true}'
```

The values above are only an example of the shape. Never send them: ask the human for every value listed under "What the human decides" and build the payload from their answers.

Generate `requestId` once, with `uuidgen | tr A-Z a-z` or `node -e 'console.log(crypto.randomUUID())'`. Keep it: a retry after a network error or a 503 must reuse the same value, and the server then treats it as the same submission. Do not commit the payload; it contains personal data.

A 201 response means the submission is saved: tell the human. If they prefer the form, the same fields are at https://nearhackathon.com/#apply.

## Submission API

`POST https://nearhackathon.com/api/applications` with `Content-Type: application/json`. Body up to 12000 bytes. Send exactly these fields:

| Field | Type | Rule |
| --- | --- | --- |
| requestId | string | UUID, generated once per submission and reused on retries |
| projectName | string | 2-80 characters, unique (case-insensitive) |
| leadName | string | 2-80 characters |
| email | string | valid email, max 160 characters, unique |
| size | string | one of `1`, `2 - 4`, `4 - 6`, `6 - 8`, `8+`, exactly as written |
| tracks | array of strings | one or more of `defi`, `thesis`, `privacy`, `business`, `swarms`, `security`, `agents`, `realworld`, `games`, `nfts`, `memecoins`, `social`, `open`, each listed once |
| nearAddress | string | 2-64 characters, lowercase, matching `^(([a-z\d]+[-_])*[a-z\d]+\.)*([a-z\d]+[-_])*[a-z\d]+$` |
| projectUrl | string | http(s) URL of the public repository, max 300 characters |
| demoUrl | string | http(s) URL of the public demo post, max 300 characters |
| idea | string | 20-2000 characters |
| consent | boolean | `true`, only after the human agreed to the contact notice |

Do not add other fields. In particular `website` is a spam trap: any non-empty value rejects the submission.

| Status | Meaning | What to do |
| --- | --- | --- |
| 201 | Submission saved | Done. Tell the human. |
| 400 | A field failed validation | Fix the fields listed in `fields` of the response and resend with the same requestId. |
| 403 | Submissions are not open, or the request looked cross-site | Tell the human. Do not retry. |
| 409 | Project name or email already used | The team already submitted. Ask the human; do not change the name to get around it. |
| 413 | Body too large | Shorten the description. |
| 503 | Storage temporarily unavailable | Wait a minute and resend with the same requestId. |

## Tracks

Put the `id` of every track the project fits in the `tracks` array of the submission. A team still submits once.

The last column is what the organizers hope to see in each track: NEAR features and themes worth building around. They are hints and wishes, not requirements. Lean on the ones that fit the idea and name them in the README.

| id | Track | Build | Hints: what to lean on |
| --- | --- | --- | --- |
| `defi` | Unstoppable DeFi | Build exchanges, perps, lending, vaults and trading agents that settle across chains through NEAR Intents. Deep liquidity, no custodian, nobody to switch it off. | TRADING, NEAR INTENTS, CHAIN SIGNATURES |
| `thesis` | Investment Thesis | Build a long-term investment thesis for NEAR and back it with data: onchain analytics, live dashboards and models anyone can re-run. Judged on the evidence, not the conviction. | ONCHAIN DATA, DASHBOARDS, RESEARCH |
| `privacy` | Privacy & Private AI | Explore confidential computation, private finance and AI that protects sensitive data. Build intelligence without exposure. | PRIVATE AI, TEE, NEAR AI CLOUD |
| `business` | Autonomous Business | Build AI-native businesses with treasury, sales, procurement, cross-chain payments via NEAR Intents and revenue sharing. Humans only set the constraints. | AI AGENTS, NEAR INTENTS, CHAIN SIGNATURES |
| `swarms` | AI Swarms | Build coordination markets, bidding, collective purchasing, intent-based settlement and emergent economies between agents. | MULTI-AGENT SYSTEMS, NEAR INTENTS, SUB-ACCOUNTS |
| `security` | AI Security & Defense | Build spending limits, policy engines, sandboxed wallets, reputation and scam detection. Give AI money without giving it the keys to everything. | AGENT SECURITY, FUNCTION CALL KEYS, TEE ATTESTATION |
| `agents` | Agent Economy | Build agents that earn, spend, negotiate, hire other agents and pay for APIs, compute or data — with crypto directly or through NEAR Intents. | AGENT COMMERCE, NEAR INTENTS, CHAIN SIGNATURES |
| `realworld` | Real-World Money | Build payroll, invoicing, remittances, merchant payments and stablecoin rails for real businesses. Something a normal company could use tomorrow. | STABLECOINS, NEAR INTENTS, META TRANSACTIONS |
| `games` | Games With Real Economies | Build NPCs with wallets, player-owned markets and economies that evolve without a dev patch. Judged on the game loop, not the token — bonus if players never notice the chain. | AGENT NPCS, SOCIAL LOGIN, NEAR INTENTS, NEP-245 |
| `nfts` | NFTs That Do Something | Build NFTs as accounts — assets that own money, earn royalties, hold inventory, carry credentials, memberships or access rights. Ownership with behavior. | DYNAMIC NFTS, NEP-171, SUB-ACCOUNTS |
| `memecoins` | Memecoins With Mechanics | Build memecoins where the meme does something — supply that reacts to the community, treasuries with rules, onchain rituals and challenges. Judged on the mechanic, not the chart. | MEMECOINS, TOKEN MECHANICS, NEP-141 |
| `social` | Social Money | Build shared budgets, programmable rewards, collective ownership and reputation-based access on top of Sputnik DAO and Trezu. Don't rebuild the multisig — build what communities do with it. | SPUTNIK DAO, TREZU, NAMED ACCOUNTS |
| `open` | Open Innovation | Have an idea that refuses to fit a category? Explore new ways for money, intelligence and ownership to work together. | EXPERIMENTAL, CHAIN ABSTRACTION, BUILD YOUR OWN |

## Ecosystem

Partner tools and their documentation. Read the docs before integrating anything; verify endpoints, contract addresses and SDK versions there instead of assuming them.

| Partner | What it is | Docs | Website | GitHub |
| --- | --- | --- | --- | --- |
| NEAR Intents | Cross-chain execution | https://docs.near-intents.org/ | https://intents.near.org/ | https://github.com/near/intents |
| Aurora | Ethereum on NEAR | https://doc.aurora.dev/ | https://aurora.dev/ | https://github.com/aurora-is-near |
| HOT | Chain abstraction | https://docs.hotdao.ai/ | https://hot-labs.org/ | https://github.com/hot-dao |
| Rhea | DeFi on NEAR | https://guide.rhea.finance/ | https://rhea.finance/ | https://github.com/rhea-finance |
| meme.cooking | Memecoin launchpad |  | https://meme.cooking/ |  |
| HEX | Cross-chain swaps |  | https://hex.exchange/ |  |
| NEAR.AI | Private AI | https://docs.near.ai/ | https://near.ai/ | https://github.com/nearai/cloud-api |
| SVRN | Sovereign technology |  | https://svrn.net/ |  |
| Trezu | Multisig treasury for Web3 teams | https://github.com/NEAR-DevHub/trezu-docs | https://trezu.org/ | https://github.com/NEAR-DevHub/trezu |
| SputnikDAO | DAO infrastructure | https://github.com/near-daos/sputnik-dao-contract#setup | https://x.com/SputnikDAO | https://github.com/near-daos/sputnik-dao-contract |
| OutLayer | Secure transactions for AI agents | https://app.outlayer.ai/docs/getting-started | https://outlayer.ai/ | https://github.com/out-layer/outlayer |
| GoMining | Bitcoin mining superapp | https://docs.gomining.com/ | https://gomining.com/ |  |

## Community

Where the team finds collaborators, asks questions and follows updates.

| Channel | Link | What it is for |
| --- | --- | --- |
| NEAR Discord | https://discord.gg/RhZGHPXPf2 | Questions about building on NEAR, finding teammates |
| X | https://x.com/NEARProtocol | Hackathon announcements and updates |

