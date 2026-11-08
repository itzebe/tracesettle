"""Static configuration: sources, timeouts, and the chain/RPC map.

Everything here is a *free, public* endpoint verified in Phase 1. No secrets are
read from or written to this file, and nothing here is exposed to the browser.
"""

from __future__ import annotations

import os
from dataclasses import dataclass

# ---------------------------------------------------------------------------
# Source endpoints
# ---------------------------------------------------------------------------

ONECLICK_BASE = os.environ.get("TRACESETTLE_ONECLICK_BASE", "https://1click.chaindefuser.com")
ONECLICK_STATUS_PATH = "/v0/status"
#: The documented public 1Click endpoints used by the live lifecycle client.
#: Source: the vendored OpenAPI documents (``info.version 0.1.10``) under
#: ``docs/official/api-reference_oneclick_*.md``. No endpoint is invented.
ONECLICK_TOKENS_PATH = "/v0/tokens"
ONECLICK_QUOTE_PATH = "/v0/quote"
ONECLICK_DEPOSIT_SUBMIT_PATH = "/v0/deposit/submit"

SOLVER_RELAY_URL = os.environ.get(
    "TRACESETTLE_SOLVER_RELAY_URL", "https://solver-relay-v2.chaindefuser.com/rpc"
)

BRIDGE_RPC_URL = os.environ.get(
    "TRACESETTLE_BRIDGE_RPC_URL", "https://bridge.chaindefuser.com/rpc"
)

NEAR_RPC_URL = os.environ.get("TRACESETTLE_NEAR_RPC_URL", "https://free.rpc.fastnear.com")

#: Fallback NEAR RPC endpoints, tried in order after ``NEAR_RPC_URL`` when the
#: primary node does not know a transaction.
#:
#: Free NEAR providers are **non-archival**: they answer ``UNKNOWN_TRANSACTION``
#: for any historical transaction outside their pruning window, even though the
#: transaction exists. ``archival-rpc.mainnet.near.org`` is the only free archive
#: endpoint, is marked deprecated, and rate-limits hard (HTTP 429). A historical
#: lookup is therefore best-effort; for production set
#: ``TRACESETTLE_NEAR_RPC_FALLBACK_URL`` to a paid archive node.
NEAR_RPC_FALLBACK_URLS: tuple[str, ...] = tuple(
    url.strip()
    for url in os.environ.get(
        "TRACESETTLE_NEAR_RPC_FALLBACK_URL",
        "https://archival-rpc.mainnet.near.org",
    ).split(",")
    if url.strip()
)

EXPLORER_TX_BASE = "https://explorer.near-intents.org/transactions"

# ---------------------------------------------------------------------------
# Bitcoin data source (free, public, no key)
# ---------------------------------------------------------------------------
#
# Bitcoin has no JSON-RPC ``eth_getTransactionReceipt`` equivalent. The de-facto
# public read API is the Esplora REST API, served by mempool.space and
# blockstream.info. Both were verified live for this project (mainnet) and need
# no key. A fallback host is configured so a single provider outage does not make
# refund verification impossible.
BITCOIN_API_URLS = (
    os.environ.get("TRACESETTLE_BTC_API_URL", "https://mempool.space/api"),
    "https://blockstream.info/api",
)

#: The BTC connector contract that owns the bridge's manual refund flow.
BTC_CONNECTOR_ACCOUNT = "btc-connector.bridge.near"
#: The bridge relayer that signs bridge-side NEAR transactions.
BRIDGE_RELAYER_ACCOUNT = "omni-relayer.bridge.near"

# ---------------------------------------------------------------------------
# HTTP behaviour
# ---------------------------------------------------------------------------

REQUEST_TIMEOUT_SECONDS = float(os.environ.get("TRACESETTLE_HTTP_TIMEOUT", "12"))
MAX_ATTEMPTS = int(os.environ.get("TRACESETTLE_HTTP_ATTEMPTS", "2"))
BACKOFF_BASE_SECONDS = float(os.environ.get("TRACESETTLE_HTTP_BACKOFF", "0.6"))
USER_AGENT = "TraceSettle/0.2 (read-only settlement investigator)"

# ---------------------------------------------------------------------------
# Interface hardening
# ---------------------------------------------------------------------------
#
# Every value below is read from the environment so a deployment can tune it
# without a code change. None of them is a secret; the API key is the only
# sensitive value and it is never logged or echoed back to a client.

#: When set, ``POST /api/investigate`` requires this key. When unset, the
#: endpoint is open — the default for local, loopback-only use. Set it before
#: exposing the server on a shared host.
API_KEY = os.environ.get("TRACESETTLE_API_KEY") or None

#: Whether the read-only public demonstration is served **without** the API key.
#:
#: Off by default: when unset, every guard route and the investigation endpoint
#: keep the API-key requirement exactly as before, so nothing about the existing
#: security posture changes. When enabled it opens a **strict allowlist** of
#: self-contained, read-only GET routes — the agent-payment demonstration, the
#: deterministic attack scenarios, the policy-scope analysis and a *live,
#: read-only* NEAR testnet settlement check — plus the ``/demo`` page that
#: presents them.
#:
#: It never exposes anything that evaluates, signs, broadcasts, or mutates state:
#: ``/api/guard/evaluate``, ``/api/guard/sign``, the wallet and execution routes,
#: the Intents lifecycle, incidents, audit, metrics, the policy document and
#: ``/api/investigate`` all stay key-gated. The demonstration routes are
#: self-contained simulations (the only substitution is the network transport)
#: and the testnet check is a public RPC read of an already-final transaction, so
#: no key, no funds, and no write are involved.
PUBLIC_DEMO_ENABLED = (
    os.environ.get("TRACESETTLE_PUBLIC_DEMO", "").strip().lower()
    in {"1", "true", "yes", "on"}
)

#: Per-connection socket timeout. Bounds how long a slow or idle client can hold
#: a worker thread (slowloris defence).
CLIENT_SOCKET_TIMEOUT_SECONDS = float(os.environ.get("TRACESETTLE_CLIENT_TIMEOUT", "10"))

#: Hard cap on concurrently served connections. Excess connections are rejected
#: immediately with HTTP 503 rather than queued behind a slow client.
MAX_CONCURRENT_REQUESTS = int(os.environ.get("TRACESETTLE_MAX_CONCURRENCY", "16"))

#: Accept backlog. Bounds how many connections the kernel queues before accept.
REQUEST_QUEUE_SIZE = int(os.environ.get("TRACESETTLE_REQUEST_QUEUE", "64"))

#: Per-client-IP request budget for the investigation endpoint.
RATE_LIMIT_PER_MINUTE = int(os.environ.get("TRACESETTLE_RATE_LIMIT_PER_MINUTE", "60"))
RATE_LIMIT_BURST = int(os.environ.get("TRACESETTLE_RATE_LIMIT_BURST", "15"))

#: Per-upstream-host request budget, shared across all investigations, so one
#: abusive client cannot exhaust a free public endpoint's shared rate limit.
HOST_RATE_LIMIT_PER_MINUTE = int(os.environ.get("TRACESETTLE_HOST_RATE_LIMIT_PER_MINUTE", "240"))
HOST_RATE_LIMIT_BURST = int(os.environ.get("TRACESETTLE_HOST_RATE_LIMIT_BURST", "60"))

#: Bounded TTL cache for read-only upstream responses.
UPSTREAM_CACHE_TTL_SECONDS = float(os.environ.get("TRACESETTLE_CACHE_TTL", "45"))
UPSTREAM_CACHE_MAX_ENTRIES = int(os.environ.get("TRACESETTLE_CACHE_MAX_ENTRIES", "512"))


# ---------------------------------------------------------------------------
# Transaction security layer (guard)
# ---------------------------------------------------------------------------
#
# None of these is a secret. The authorization signing key is read separately by
# ``tracesettle.guard.authorization.load_key`` from TRACESETTLE_GUARD_AUTH_KEY and
# is never read here, logged, or returned to a client.

#: Optional JSON policy file. Unset means the built-in default policy.
GUARD_POLICY_PATH = os.environ.get("TRACESETTLE_GUARD_POLICY") or None

#: Optional append-only audit log file. Unset keeps the audit trail in memory,
#: bounded by GUARD_AUDIT_MAX_RECORDS; the hash chain still proves in-place edits.
GUARD_AUDIT_LOG_PATH = os.environ.get("TRACESETTLE_GUARD_AUDIT_LOG") or None
GUARD_AUDIT_MAX_RECORDS = int(os.environ.get("TRACESETTLE_GUARD_AUDIT_MAX_RECORDS", "10000"))

#: Optional SQLite database for durable guard state: spent nonces, revoked
#: authorizations, and the velocity/volume/rejection counters. Unset keeps the
#: in-memory stores (the loopback development default); the console reports the
#: backend honestly. This is durable state for *one* application instance, not
#: shared multi-instance state. A configured path that cannot be opened stops
#: start-up rather than running with a silently degraded control.
GUARD_STATE_DB = os.environ.get("TRACESETTLE_GUARD_STATE_DB") or None
GUARD_STATE_BUSY_TIMEOUT_MS = int(os.environ.get("TRACESETTLE_GUARD_STATE_BUSY_TIMEOUT_MS", "5000"))

#: How long durable counter events and idempotency keys are retained. Events older
#: than this cannot affect any velocity/volume window (the window is a few hours at
#: most), so pruning them keeps the tables bounded and the window read fast. It must
#: stay well above the largest configured window; 24h is a safe default.
GUARD_STATE_RETENTION_SECONDS = float(
    os.environ.get("TRACESETTLE_GUARD_STATE_RETENTION_SECONDS", "86400")
)

#: Which durable backend to use: ``auto`` (default), ``memory``, ``sqlite``, or
#: ``postgresql``. ``auto`` selects PostgreSQL when a DSN is configured, else SQLite
#: when a path is configured, else the in-memory stores (the loopback default).
#: There is no silent fallback: ``sqlite``/``postgresql`` with missing configuration
#: stop start-up rather than degrading.
GUARD_STATE_BACKEND = (os.environ.get("TRACESETTLE_GUARD_STATE_BACKEND") or "auto").strip().lower()

#: PostgreSQL connection string for shared multi-instance guard state. This is a
#: SECRET (it may carry a password); it is never logged, printed, or returned. Set
#: it only when using the PostgreSQL backend.
GUARD_STATE_PG_DSN = os.environ.get("TRACESETTLE_GUARD_STATE_PG_DSN") or None
GUARD_STATE_PG_CONNECT_TIMEOUT_S = int(
    os.environ.get("TRACESETTLE_GUARD_STATE_PG_CONNECT_TIMEOUT_S", "10")
)
GUARD_STATE_PG_STATEMENT_TIMEOUT_MS = int(
    os.environ.get("TRACESETTLE_GUARD_STATE_PG_STATEMENT_TIMEOUT_MS", "5000")
)

#: Production guard: require the PostgreSQL backend. When set, start-up refuses to
#: run with an in-memory or SQLite backend, so a deployment cannot silently lose
#: shared authorization state. There is no override.
GUARD_REQUIRE_POSTGRES = (os.environ.get("TRACESETTLE_GUARD_REQUIRE_POSTGRES") or "").strip().lower() in {
    "1",
    "true",
    "yes",
    "on",
}

#: Optional SQLite database for durable *security safeguards* (the learning loop).
#: When set, a security failure or unverified condition recorded from one decision
#: becomes a persistent restriction applied to later decisions; the lesson and its
#: effect survive a restart. Unset disables the learning loop entirely, so a
#: deployment without this variable behaves exactly as before. A configured path
#: that cannot be opened stops start-up rather than running with learning silently
#: disabled.
GUARD_SAFEGUARD_DB = os.environ.get("TRACESETTLE_GUARD_SAFEGUARD_DB") or None
GUARD_SAFEGUARD_BUSY_TIMEOUT_MS = int(
    os.environ.get("TRACESETTLE_GUARD_SAFEGUARD_BUSY_TIMEOUT_MS", "5000")
)

#: Per-client-IP budget for the guard endpoints. Tighter than the investigation
#: endpoint: these endpoints make no outbound calls, so a high rate is abusive.
GUARD_RATE_LIMIT_PER_MINUTE = int(os.environ.get("TRACESETTLE_GUARD_RATE_LIMIT_PER_MINUTE", "120"))
GUARD_RATE_LIMIT_BURST = int(os.environ.get("TRACESETTLE_GUARD_RATE_LIMIT_BURST", "30"))

#: Body cap for guard requests. A transaction request is small; anything larger
#: is rejected before it is read.
GUARD_MAX_BODY_BYTES = int(os.environ.get("TRACESETTLE_GUARD_MAX_BODY_BYTES", "8192"))

# ---------------------------------------------------------------------------
# Per-service authentication
# ---------------------------------------------------------------------------
#
# The guard trusts a *declared* service_id. To stop one service impersonating
# another, each service can be issued a credential (see ``tracesettle.serviceauth``).
# Credentials are read from a JSON store; the plaintext secret is never stored,
# only its SHA-256 hash. Nothing here is ever logged.

#: Path to a JSON credential store (``{"version":1,"credentials":[...]}``).
#: Each entry has ``credential_id``, ``service_id``, ``secret_hash`` (sha256:…),
#: and optional ``expires_at``/``revoked``.
SERVICE_CREDENTIALS_PATH = os.environ.get("TRACESETTLE_SERVICE_CREDENTIALS") or None

#: Inline JSON credential store, for platforms without a mounted file. Takes
#: precedence over the path when both are set.
SERVICE_CREDENTIALS_JSON = os.environ.get("TRACESETTLE_SERVICE_CREDENTIALS_JSON") or None

#: When set, every guard request must present a valid service credential. When
#: unset, credential authentication applies only if a store is configured. A
#: public binding with this set and no store is refused at startup.
REQUIRE_SERVICE_AUTH = os.environ.get("TRACESETTLE_REQUIRE_SERVICE_AUTH", "").strip().lower() in {
    "1",
    "true",
    "yes",
    "on",
}


def service_auth_configured() -> bool:
    """Whether a service credential store is configured at all."""
    return bool(SERVICE_CREDENTIALS_PATH or SERVICE_CREDENTIALS_JSON)


def load_service_registry():
    """Build a :class:`ServiceRegistry` from configuration, or ``None``.

    A configured store that cannot be read or parsed is a hard error: a security
    control must never silently fall back to "no authentication".
    """
    if not service_auth_configured():
        return None
    from .serviceauth import ServiceRegistry

    if SERVICE_CREDENTIALS_JSON:
        return ServiceRegistry.load(SERVICE_CREDENTIALS_JSON)
    try:
        with open(SERVICE_CREDENTIALS_PATH, encoding="utf-8") as handle:  # type: ignore[arg-type]
            text = handle.read()
    except OSError as exc:
        raise RuntimeError(
            f"cannot read TRACESETTLE_SERVICE_CREDENTIALS ({SERVICE_CREDENTIALS_PATH!r}): {exc}"
        ) from exc
    return ServiceRegistry.load(text)


# ---------------------------------------------------------------------------
# Fail-closed startup
# ---------------------------------------------------------------------------
#
# A public binding with authentication disabled must refuse to start. The check
# itself lives in ``tracesettle.securityconfig``; these are its inputs.

#: True when the guard's authorization signing key is configured. The value is
#: read by ``guard.authorization.load_key``; only its presence is inspected here.
GUARD_AUTH_KEY_CONFIGURED = bool(os.environ.get("TRACESETTLE_GUARD_AUTH_KEY"))

#: Optional key for signing human approvals (see ``tracesettle.near.approval``).
#: Hex (64 chars) or any passphrase (hashed to 32 bytes). Unset mints an
#: ephemeral per-process key, which is safe for a single instance; a multi-process
#: deployment must configure it so an approval minted by one instance validates on
#: another. The value is never logged or returned.
GUARD_APPROVAL_KEY = os.environ.get("TRACESETTLE_GUARD_APPROVAL_KEY") or None

# ---------------------------------------------------------------------------
# NEAR Intents agent API (read-only policy inspection)
# ---------------------------------------------------------------------------
#
# The NEAR integration reads an agent's policy to scope-check a transaction
# before an agent signs. The base URL and key are NEVER invented: with no base
# URL set the adapter reports UNCONFIGURED and the caller must supply a local
# fixture. The key is read only by tracesettle.near.policy.PolicyAdapter and is
# never logged or returned.

#: Base URL of the NEAR Intents Agent API, e.g. https://<host>. Unset disables
#: live policy reads (the loopback default); a local fixture is used instead.
#: The provider's own documented name (``NEAR_INTENTS_AGENT_API_URL``) is also
#: accepted, so an operator can use the names from the provider's docs.
NEAR_AGENT_API_URL = (
    os.environ.get("TRACESETTLE_NEAR_AGENT_API_URL")
    or os.environ.get("NEAR_INTENTS_AGENT_API_URL")
    or None
)

#: Agent API key. Only its presence is inspected here; the value is read by the
#: adapter. Never logged, never returned, never committed. The provider's own
#: documented name (``NEAR_INTENTS_AGENT_API_KEY``) is also accepted.
NEAR_AGENT_API_KEY = (
    os.environ.get("TRACESETTLE_NEAR_AGENT_API_KEY")
    or os.environ.get("NEAR_INTENTS_AGENT_API_KEY")
    or None
)

#: Optional path to a local policy fixture (JSON). When set, the wrapper can be
#: exercised offline with no provider call. Fixtures are clearly labelled.
NEAR_POLICY_FIXTURE = os.environ.get("TRACESETTLE_NEAR_POLICY_FIXTURE") or None

#: Default agent id to read a policy for, when a request does not name one.
NEAR_AGENT_ID = os.environ.get("TRACESETTLE_NEAR_AGENT_ID") or "treasury-agent"

#: Whether live policy reads are configured. Only presence is inspected here.
NEAR_AGENT_API_CONFIGURED = bool(NEAR_AGENT_API_URL)

#: The provider host a live policy read must come from. When set, a read whose
#: base URL host differs is refused (provider identity). Unset means the operator
#: has not pinned a host; the base URL is then trusted as configured.
NEAR_AGENT_API_EXPECTED_HOST = (
    os.environ.get("TRACESETTLE_NEAR_AGENT_API_EXPECTED_HOST", "").strip().lower() or None
)

#: Maximum age (seconds) of a live policy revision. 0 disables the check. When
#: set, a policy whose ``as_of`` is older (or missing) is refused as not current.
NEAR_AGENT_POLICY_MAX_AGE_SECONDS = int(
    os.environ.get("TRACESETTLE_NEAR_AGENT_POLICY_MAX_AGE_SECONDS", "0") or "0"
)

#: Whether a request may name the policy it is evaluated against.
#:
#: Off by default, and that is the security-relevant default: the policy a
#: request is judged against is part of the *enforcement* decision, so a caller
#: must never be able to select it. With this off, ``policy_fixture`` and
#: ``agent_id`` in a request body are ignored and the operator's configuration
#: is used (``TRACESETTLE_NEAR_POLICY_FIXTURE``, then the configured Agent API,
#: then the guard's own policy). Turning it on is a deliberate, loopback-only
#: affordance for exploring alternative policies; it must never be enabled on a
#: public binding.
NEAR_ALLOW_CLIENT_POLICY_SELECTION = (
    os.environ.get("TRACESETTLE_NEAR_ALLOW_CLIENT_POLICY_SELECTION", "").strip().lower()
    in {
        "1",
        "true",
        "yes",
        "on",
    }
)

#: Whether the agent path reads counterparty risk intelligence from the NEAR RPC.
#: Off by default (the loopback default), so a deployment that does not opt in
#: has no counterparty signal. When on, an account that does not exist is
#: blocked, a contract or a brand-new account forces a review, and a signal that
#: cannot be read fails safe. Only public, keyless RPC reads are used.
NEAR_COUNTERPARTY_ENABLED = (
    os.environ.get("TRACESETTLE_NEAR_COUNTERPARTY", "").strip().lower()
    in {"1", "true", "yes", "on"}
)

#: Optional path to an evidence-backed counterparty blocklist (JSON). Every
#: entry must name a source, or loading fails. Unset means no blocklist. The file
#: holds only public identifiers and published evidence, never secrets.
NEAR_BLOCKLIST_PATH = os.environ.get("TRACESETTLE_NEAR_BLOCKLIST") or None

#: The account-age floor, in blocks, below which a counterparty is reviewed as
#: "new". At roughly one block per second, the default (86400) is about a day.
NEAR_COUNTERPARTY_MIN_AGE_BLOCKS = int(
    os.environ.get("TRACESETTLE_NEAR_COUNTERPARTY_MIN_AGE_BLOCKS", "86400") or "86400"
)

#: Whether the agent path can validate a human approval for a REQUIRE_APPROVAL
#: decision. Off by default, so a request that needs approval can never become
#: ALLOW on an unconfigured deployment (the fail-closed default). When on, an
#: approval must be bound to the exact transaction payload, is single-use, and
#: expires. The signing key is generated from ``TRACESETTLE_GUARD_APPROVAL_KEY``
#: when set, otherwise an ephemeral key is used and reported as ephemeral.
NEAR_APPROVAL_ENABLED = (
    os.environ.get("TRACESETTLE_NEAR_APPROVAL", "").strip().lower()
    in {"1", "true", "yes", "on"}
)

#: Seconds an approval remains valid. A short window keeps a stale approval from
#: outliving the transaction it approved.
NEAR_APPROVAL_TTL_SECONDS = int(
    os.environ.get("TRACESETTLE_NEAR_APPROVAL_TTL_SECONDS", "300") or "300"
)

#: Path to the durable NEAR Intents lifecycle database (SQLite). Unset means the
#: lifecycle keeps no durable record, which is the loopback default; a public
#: deployment that offers the lifecycle must set it so investigations survive a
#: restart. The file holds no signing material.
INTENTS_DB = os.environ.get("TRACESETTLE_INTENTS_DB") or None

#: Path to the durable settlement-investigations database (SQLite). Unset means a
#: completed investigation is returned but not stored, which is the loopback
#: default. When set, every investigation is persisted so a report produced
#: before a restart can be retrieved afterward with its evidence intact. The file
#: holds only public on-chain identifiers and published evidence.
INVESTIGATIONS_DB = os.environ.get("TRACESETTLE_INVESTIGATIONS_DB") or None

#: Whether the NEAR Intents lifecycle routes are enabled at all. Off by default:
#: the lifecycle can issue a live quote (a fundable deposit address) and so is an
#: explicit operator decision, not something a public bind turns on silently.
NEAR_LIFECYCLE_ENABLED = (
    os.environ.get("TRACESETTLE_NEAR_LIFECYCLE", "").strip().lower()
    in {"1", "true", "yes", "on"}
)

#: Whether the NEAR execution boundary is enabled. Off by default. When enabled,
#: TraceSettle builds real NEAR transactions, hands them to a caller's wallet to
#: sign, broadcasts the signed bytes, and independently verifies settlement. It
#: never holds a key. Because enabling it exposes a path to a live broadcast, it
#: is an explicit operator decision and never turned on by a public bind.
NEAR_EXECUTION_ENABLED = (
    os.environ.get("TRACESETTLE_NEAR_EXECUTION", "").strip().lower()
    in {"1", "true", "yes", "on"}
)

#: The NEAR network the execution boundary acts on: ``testnet`` (the default) or
#: ``mainnet``. Testnet is the default so a misconfiguration cannot spend real
#: funds. The network is resolved server-side and its genesis hash is checked
#: against the RPC before any transaction is built.
NEAR_EXECUTION_NETWORK = os.environ.get("TRACESETTLE_NEAR_EXECUTION_NETWORK", "testnet").strip() or "testnet"

#: Whether a verified TEE attestation is **required** before the execution
#: boundary will accept a signature. Off by default: the TEE gate is an explicit
#: operator decision. When on, a transaction cannot reach the signer unless a
#: genuine Intel TDX attestation is bound to its exact digest and decision nonce,
#: so an attestation is enforced rather than merely displayed.
NEAR_TEE_REQUIRED = (
    os.environ.get("TRACESETTLE_NEAR_TEE_REQUIRED", "").strip().lower()
    in {"1", "true", "yes", "on"}
)

#: Whether the independent NEAR Intents provider (Agent API) policy must be in
#: force before the execution boundary will authorize an operation. Off by
#: default (the loopback default keeps the operator policy alone); when on, a
#: policy that cannot be read, is stale, is not applied, or is frozen refuses
#: authorization. A required layer with no adapter is a hard refusal, never a
#: silent fallback to the operator policy alone.
NEAR_REQUIRE_PROVIDER_POLICY = (
    os.environ.get("TRACESETTLE_NEAR_REQUIRE_PROVIDER_POLICY", "").strip().lower()
    in {"1", "true", "yes", "on"}
)

#: The TD report measurement fingerprint (``sha256`` of the canonical measurement
#: fields) the TEE gate requires. Empty means the measurement is recorded and
#: reported as ``UNPINNED`` rather than claimed; a non-empty value pins it, and a
#: quote whose measurement differs is refused.
NEAR_TEE_EXPECTED_MEASUREMENT = (
    os.environ.get("TRACESETTLE_NEAR_TEE_EXPECTED_MEASUREMENT", "").strip().lower()
)

#: The durable execution-record database (SQLite). Unset means execution records
#: live in memory only, which is the loopback default; a deployment that relies
#: on the TEE gate should set it so a record survives a restart.
NEAR_EXECUTION_DB = os.environ.get("TRACESETTLE_NEAR_EXECUTION_DB", "").strip() or None

#: The enclave signing endpoint. Unset disables enclave signing: the boundary
#: reports itself unavailable and refuses to sign, so hardware-required
#: execution stays disabled until a genuine endpoint is supplied. It is NOT
#: invented; the operator must configure it.
ENCLAVE_SIGN_URL = os.environ.get("TRACESETTLE_ENCLAVE_SIGN_URL", "").strip() or None

#: The approved enclave measurement, as ``field=hex`` pairs separated by commas
#: (for example ``mr_config_id=01dc14...000``). Every field is checked against the
#: verified quote. Unset means no identity is approved, so provisioning is
#: refused (fail-closed) rather than trusting an unpinned measurement.
ENCLAVE_APPROVED_MEASUREMENT = (
    os.environ.get("TRACESETTLE_ENCLAVE_APPROVED_MEASUREMENT", "").strip() or None
)

#: Whether enclave signing is required for execution. When set, a transaction is
#: never signed by the software signer; it must come from a verified enclave.
ENCLAVE_REQUIRED = (
    os.environ.get("TRACESETTLE_ENCLAVE_REQUIRED", "").strip().lower()
    in {"1", "true", "yes", "on"}
)

#: The durable enclave-key lifecycle database (SQLite). Unset keeps the lifecycle
#: in memory, which is the loopback default; a deployment that revokes keys
#: should set it so a revocation survives a restart.
ENCLAVE_KEY_DB = os.environ.get("TRACESETTLE_ENCLAVE_KEY_DB", "").strip() or None


def parse_approved_measurement(raw: str | None) -> dict[str, str]:
    """Parse ``field=hex,field=hex`` into a mapping, raising on a malformed value.

    A malformed value is a hard error: an operator who tried to pin an identity
    and mistyped it must not end up with a boundary that pins nothing (which,
    fail-closed, refuses everything — but silently, which is worse than a clear
    start-up failure).
    """
    if not raw:
        return {}
    fields: dict[str, str] = {}
    for pair in raw.split(","):
        pair = pair.strip()
        if not pair:
            continue
        if "=" not in pair:
            raise ValueError(
                f"approved measurement entry {pair!r} is not 'field=hex'; refusing to "
                "start with a malformed measurement pin"
            )
        key, value = pair.split("=", 1)
        key, value = key.strip(), value.strip().lower()
        if not key or not value:
            raise ValueError(f"approved measurement entry {pair!r} has an empty field or value")
        fields[key] = value
    return fields


#: The TTL, in seconds, of an execution record. It is the window in which an
#: authorization may be signed; after it the record is EXPIRED and refuses.
NEAR_EXECUTION_TTL_SECONDS = int(
    os.environ.get("TRACESETTLE_NEAR_EXECUTION_TTL_SECONDS", "90") or "90"
)

#: The durable submission-ledger database (SQLite). Every signed/broadcast
#: submission is recorded here before it is sent and updated after, so a
#: submission whose outcome is unknown (a timeout at broadcast) is resolved from
#: the chain on recovery instead of being blindly retried. Unset means records
#: live in memory only; a deployment that broadcasts should set it.
NEAR_LEDGER_DB = os.environ.get("TRACESETTLE_NEAR_LEDGER_DB", "").strip() or None

#: The durable evidence-chain database (SQLite). When set, the pipeline writes one
#: authorization-to-settlement record per submitted transaction, and the reviewer
#: routes can read it back. Unset means chains live in memory only. The chain is
#: what makes a submission independently inspectable: it binds the authorization,
#: the exact signed bytes, the attestation, the broadcast hash and the settlement
#: to one transaction identity.
NEAR_CHAIN_DB = os.environ.get("TRACESETTLE_NEAR_CHAIN_DB", "").strip() or None

#: How many times to poll the chain for a *final* execution status after a
#: broadcast before giving up and reporting the last (possibly non-final) state.
#: A broadcast commonly returns an optimistic status; polling resolves it to a
#: final one without ever inflating a pending state to verified.
NEAR_FINALITY_ATTEMPTS = int(
    os.environ.get("TRACESETTLE_NEAR_FINALITY_ATTEMPTS", "8") or "8"
)

#: The delay, in seconds, between finality polls.
NEAR_FINALITY_DELAY_SECONDS = float(
    os.environ.get("TRACESETTLE_NEAR_FINALITY_DELAY_SECONDS", "1.0") or "1.0"
)

#: The public NEAR AI Cloud gateway attestation endpoint. It returns a genuine,
#: hardware-signed Intel TDX quote; TraceSettle verifies it locally. No key is
#: required and no payment is involved.
TEE_ATTESTATION_URL = os.environ.get(
    "TRACESETTLE_TEE_ATTESTATION_URL",
    "https://cloud-api.near.ai/v1/attestation/report",
)

#: --- OutLayer Agent Custody (TEE-held signing wallet) --------------------
#: OutLayer holds a wallet's signing key inside an Intel TDX enclave and signs on
#: request. Enabling it makes TraceSettle able to *send* an authorized operation
#: to that provider, so it is an explicit operator decision and never a public
#: bind default. The API key is server-side only: it is read here, sent only as a
#: bearer header, and never returned, logged, or echoed in an error.
OUTLAYER_ENABLED = (
    os.environ.get("TRACESETTLE_OUTLAYER_ENABLED", "").strip().lower()
    in {"1", "true", "yes", "on"}
)

#: The OutLayer API key (``wk_...``). Required when OutLayer is enabled; an empty
#: key with the provider enabled is a hard start-up failure, never a fallback.
OUTLAYER_API_KEY = os.environ.get("TRACESETTLE_OUTLAYER_API_KEY", "").strip()

#: The OutLayer network. ``testnet`` (the default) or ``mainnet``. The host is the
#: network selector, so a testnet key can never be used against mainnet.
OUTLAYER_NETWORK = os.environ.get("TRACESETTLE_OUTLAYER_NETWORK", "testnet").strip() or "testnet"

#: The OutLayer wallet id the operator configured, if any. When set, a wallet the
#: API key resolves to that does not match it is refused, so a key swap cannot
#: silently sign for a different wallet.
OUTLAYER_WALLET_ID = os.environ.get("TRACESETTLE_OUTLAYER_WALLET_ID", "").strip()

#: The per-request timeout, in seconds, for OutLayer calls.
OUTLAYER_TIMEOUT_SECONDS = float(
    os.environ.get("TRACESETTLE_OUTLAYER_TIMEOUT_SECONDS", "30") or "30"
)

#: Whether the independent NEAR provider (Agent API) policy must be in force
#: before a custody operation is authorized. On by default: the provider policy
#: is a *second*, independent layer, and OutLayer's wallet policy is not a
#: substitute for it. Set to ``0`` only where the provider policy is known not to
#: apply; the layer then reports itself as not applied rather than passing
#: silently.
OUTLAYER_REQUIRE_PROVIDER_POLICY = (
    os.environ.get("TRACESETTLE_OUTLAYER_REQUIRE_PROVIDER_POLICY", "1").strip().lower()
    not in {"0", "false", "no", "off"}
)

#: The agent id the provider policy is read for on the custody path. Defaults to
#: the shared ``TRACESETTLE_NEAR_AGENT_ID`` so the policy read and the agent
#: authorization refer to the same agent.
OUTLAYER_PROVIDER_POLICY_AGENT_ID = (
    os.environ.get("TRACESETTLE_OUTLAYER_PROVIDER_POLICY_AGENT_ID", "").strip()
    or NEAR_AGENT_ID
)

#: Maximum age (seconds) of a provider policy on the custody path. Defaults to
#: ten minutes, matching the provider's documented policy-change cooldown: a
#: policy older than this (or one that carries no ``as_of`` at all) is refused as
#: not current, so a stale policy cannot authorize a payment. Set to ``0`` to
#: disable the bound.
OUTLAYER_PROVIDER_POLICY_MAX_AGE_SECONDS = int(
    os.environ.get("TRACESETTLE_OUTLAYER_PROVIDER_POLICY_MAX_AGE_SECONDS", "600") or "600"
)

#: Whether the TEE attestation route is enabled. Off by default: it makes an
#: outbound request to the attestation endpoint, so enabling it is an explicit
#: operator decision rather than something a public bind turns on silently.
TEE_ATTESTATION_ENABLED = (
    os.environ.get("TRACESETTLE_TEE_ATTESTATION", "").strip().lower()
    in {"1", "true", "yes", "on"}
)

# ---------------------------------------------------------------------------
# TEE signing boundary (OutLayer Signing Keys — the raw-digest signing route)
# ---------------------------------------------------------------------------

#: Whether the TEE signing boundary is enabled. Off by default. This is the only
#: route that signs the exact NEAR transaction digest inside an Intel TDX enclave
#: (OutLayer's ``outlayer:signing-keys`` WASI-P2 path). It is a **paid** route —
#: OutLayer bills per execution and failed executions are not refunded — so it is
#: an explicit operator decision and is never a public-bind default. With no
#: credential the boundary reports itself unavailable and refuses to sign; it
#: never falls back to a software key.
TEE_SIGNING_ENABLED = (
    os.environ.get("TRACESETTLE_TEE_SIGNING", "").strip().lower()
    in {"1", "true", "yes", "on"}
)

#: The OutLayer project owner and project name that publish the signing guest.
#: Both are required when the boundary is enabled; a missing one is a hard
#: start-up failure, never a silent skip.
TEE_SIGNING_OWNER = os.environ.get("TRACESETTLE_TEE_SIGNING_OWNER", "").strip()
TEE_SIGNING_PROJECT = os.environ.get("TRACESETTLE_TEE_SIGNING_PROJECT", "").strip()

#: The OutLayer payment key (``pk_...``) that pays for the signing calls. Read
#: here, sent only as the ``X-Payment-Key`` header, never returned or logged.
TEE_SIGNING_PAYMENT_KEY = os.environ.get("TRACESETTLE_TEE_SIGNING_PAYMENT_KEY", "").strip()

#: The network the signing project lives on. ``testnet`` (default) or ``mainnet``.
TEE_SIGNING_NETWORK = (
    os.environ.get("TRACESETTLE_TEE_SIGNING_NETWORK", "testnet").strip() or "testnet"
)

#: The approved build identity: the sha256 of the exact signing WASM the operator
#: published. An attestation whose ``wasm_hash`` differs is refused, so a swapped
#: build cannot sign. Required when the boundary is enabled.
TEE_SIGNING_APPROVED_BUILD = (
    os.environ.get("TRACESETTLE_TEE_SIGNING_APPROVED_BUILD", "").strip()
)

#: The approved worker measurement (an ``ApprovedMeasurement`` spec string), so a
#: quote from an unapproved worker is refused. Optional: when unset, the boundary
#: reports the measurement as unpinned rather than claiming it matched.
TEE_SIGNING_APPROVED_MEASUREMENT = (
    os.environ.get("TRACESETTLE_TEE_SIGNING_APPROVED_MEASUREMENT", "").strip() or None
)

#: Whether the signing boundary is *required*: with this on, a NEAR execution that
#: cannot obtain a TEE signature is refused rather than signed in software. Off by
#: default so the software testnet path still works without the paid route.
TEE_SIGNING_REQUIRED = (
    os.environ.get("TRACESETTLE_TEE_SIGNING_REQUIRED", "").strip().lower()
    in {"1", "true", "yes", "on"}
)

# ---------------------------------------------------------------------------
# Serve defaults (env-driven so a container image needs no CLI flags)
# ---------------------------------------------------------------------------
#
# The default host stays loopback: binding a public interface is an explicit
# decision, made either with ``--host`` or by setting TRACESETTLE_HOST. The port
# honours ``PORT`` (the convention used by Render/Fly/Railway/Cloud Run) and
# falls back to ``TRACESETTLE_PORT`` then 8000.

SERVE_HOST = os.environ.get("TRACESETTLE_HOST", "127.0.0.1")
SERVE_PORT = int(os.environ.get("TRACESETTLE_PORT") or os.environ.get("PORT") or "8000")


# ---------------------------------------------------------------------------
# Chain / RPC map
# ---------------------------------------------------------------------------

#: Defuse blockchain ids (as used in asset ids and the 1Click API) -> display name.
CHAIN_DISPLAY_NAMES: dict[str, str] = {
    "near": "NEAR",
    "eth": "Ethereum",
    "arb": "Arbitrum One",
    "base": "Base",
    "op": "OP Mainnet",
    "pol": "Polygon",
    "bsc": "BNB Smart Chain",
    "avax": "Avalanche C-Chain",
    "gnosis": "Gnosis",
    "scroll": "Scroll",
    "bera": "Berachain",
    "xlayer": "X Layer",
    "monad": "Monad",
    "btc": "Bitcoin",
    "sol": "Solana",
    "ton": "TON",
    "tron": "Tron",
    "sui": "Sui",
    "doge": "Dogecoin",
    "xrp": "XRP Ledger",
    "zec": "Zcash",
    "ltc": "Litecoin",
    "dash": "Dash",
    "bch": "Bitcoin Cash",
    "stellar": "Stellar",
    "aptos": "Aptos",
    "cardano": "Cardano",
    "movement": "Movement",
    "starknet": "Starknet",
    "aleo": "Aleo",
    "fogo": "Fogo",
    "adi": "ADI",
    "plasma": "Plasma",
    "hypercore": "Hypercore",
    "hood": "Hood",
    "hlevm": "HLEVM",
}


@dataclass(frozen=True)
class ChainRpc:
    """A public JSON-RPC endpoint for one chain.

    ``url`` is the primary endpoint. ``fallback_urls`` are tried in order when
    the primary does not know a transaction (free public nodes prune history).
    """

    chain: str
    display_name: str
    url: str
    kind: str  # "evm" | "near"
    explorer_tx_url: str
    chain_id: int | None = None  # EVM chain id, verified via eth_chainId
    fallback_urls: tuple[str, ...] = ()

    def endpoints(self) -> tuple[str, ...]:
        """Primary endpoint first, then fallbacks, de-duplicated and ordered."""
        ordered = (self.url, *self.fallback_urls)
        seen: set[str] = set()
        unique: list[str] = []
        for url in ordered:
            if url and url not in seen:
                seen.add(url)
                unique.append(url)
        return tuple(unique)


def _evm(
    chain: str, url: str, explorer: str, chain_id: int, fallbacks: tuple[str, ...] = ()
) -> ChainRpc:
    return ChainRpc(
        chain=chain,
        display_name=CHAIN_DISPLAY_NAMES.get(chain, chain),
        url=url,
        kind="evm",
        explorer_tx_url=explorer,
        chain_id=chain_id,
        fallback_urls=fallbacks,
    )


#: Only chains with a *verified* public RPC are listed. Anything else must be
#: reported as UNAVAILABLE — never as FAILED.
#:
#: Free ``publicnode.com`` endpoints prune history (the primary window is about
#: two days), so an older receipt returns a null result even though the
#: transaction exists. Each chain therefore carries archive-capable fallbacks;
#: a fallback answer is validated by exactly the same checks as the primary.
EVM_RPC_MAP: dict[str, ChainRpc] = {
    "eth": _evm(
        "eth",
        "https://ethereum-rpc.publicnode.com",
        "https://etherscan.io/tx/",
        1,
        ("https://eth.drpc.org", "https://eth-mainnet.public.blastapi.io"),
    ),
    "arb": _evm(
        "arb",
        "https://arbitrum-one-rpc.publicnode.com",
        "https://arbiscan.io/tx/",
        42161,
        ("https://arbitrum.drpc.org",),
    ),
    "base": _evm(
        "base",
        "https://base-rpc.publicnode.com",
        "https://basescan.org/tx/",
        8453,
        ("https://base.drpc.org",),
    ),
    "op": _evm(
        "op",
        "https://optimism-rpc.publicnode.com",
        "https://optimistic.etherscan.io/tx/",
        10,
        ("https://optimism.drpc.org",),
    ),
    "pol": _evm(
        "pol",
        "https://polygon-bor-rpc.publicnode.com",
        "https://polygonscan.com/tx/",
        137,
        ("https://polygon.drpc.org",),
    ),
    "bsc": _evm(
        "bsc",
        "https://bsc-rpc.publicnode.com",
        "https://bscscan.com/tx/",
        56,
        ("https://bsc.drpc.org",),
    ),
    "avax": _evm(
        "avax",
        "https://avalanche-c-chain-rpc.publicnode.com",
        "https://snowtrace.io/tx/",
        43114,
        ("https://avalanche.drpc.org",),
    ),
    "gnosis": _evm(
        "gnosis",
        "https://gnosis-rpc.publicnode.com",
        "https://gnosisscan.io/tx/",
        100,
        ("https://gnosis.drpc.org",),
    ),
    "scroll": _evm(
        "scroll",
        "https://scroll-rpc.publicnode.com",
        "https://scrollscan.com/tx/",
        534352,
        ("https://scroll.drpc.org",),
    ),
}

NEAR_RPC = ChainRpc(
    chain="near",
    display_name="NEAR",
    url=NEAR_RPC_URL,
    kind="near",
    explorer_tx_url="https://nearblocks.io/txns/",
    fallback_urls=NEAR_RPC_FALLBACK_URLS,
)

#: Bitcoin is not an EVM chain and has no JSON-RPC receipt method, so it is kept
#: out of ``EVM_RPC_MAP``. It is listed here only so explorer URLs and display
#: names resolve for a ``btc`` asset id. Its data source is the Esplora REST API
#: in ``BITCOIN_API_URLS``, used by the dedicated bitcoin adapter.
BTC_CHAIN = ChainRpc(
    chain="btc",
    display_name="Bitcoin",
    url=BITCOIN_API_URLS[0],
    kind="bitcoin",
    explorer_tx_url="https://mempool.space/tx/",
)


def rpc_for_chain(chain: str | None) -> ChainRpc | None:
    """Return the RPC config for a chain, or ``None`` when unsupported."""
    if not chain:
        return None
    if chain == "near":
        return NEAR_RPC
    if chain == "btc":
        return BTC_CHAIN
    return EVM_RPC_MAP.get(chain)


def display_name(chain: str | None) -> str:
    if not chain:
        return "unknown chain"
    return CHAIN_DISPLAY_NAMES.get(chain, chain)


def explorer_url_for(chain: str | None, tx_hash: str | None) -> str | None:
    """Build a human-facing explorer URL, or ``None`` when we cannot."""
    if not tx_hash:
        return None
    rpc = rpc_for_chain(chain)
    if rpc is None:
        return None
    return f"{rpc.explorer_tx_url}{tx_hash}"
