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
NEAR_AGENT_API_URL = os.environ.get("TRACESETTLE_NEAR_AGENT_API_URL") or None

#: Agent API key. Only its presence is inspected here; the value is read by the
#: adapter. Never logged, never returned, never committed.
NEAR_AGENT_API_KEY = os.environ.get("TRACESETTLE_NEAR_AGENT_API_KEY") or None

#: Optional path to a local policy fixture (JSON). When set, the wrapper can be
#: exercised offline with no provider call. Fixtures are clearly labelled.
NEAR_POLICY_FIXTURE = os.environ.get("TRACESETTLE_NEAR_POLICY_FIXTURE") or None

#: Default agent id to read a policy for, when a request does not name one.
NEAR_AGENT_ID = os.environ.get("TRACESETTLE_NEAR_AGENT_ID") or "treasury-agent"

#: Whether live policy reads are configured. Only presence is inspected here.
NEAR_AGENT_API_CONFIGURED = bool(NEAR_AGENT_API_URL)

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
