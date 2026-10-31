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
    """A public JSON-RPC endpoint for one chain."""

    chain: str
    display_name: str
    url: str
    kind: str  # "evm" | "near"
    explorer_tx_url: str
    chain_id: int | None = None  # EVM chain id, verified via eth_chainId


def _evm(chain: str, url: str, explorer: str, chain_id: int) -> ChainRpc:
    return ChainRpc(
        chain=chain,
        display_name=CHAIN_DISPLAY_NAMES.get(chain, chain),
        url=url,
        kind="evm",
        explorer_tx_url=explorer,
        chain_id=chain_id,
    )


#: Only chains with a *verified* public RPC are listed. Anything else must be
#: reported as UNAVAILABLE — never as FAILED.
EVM_RPC_MAP: dict[str, ChainRpc] = {
    "eth": _evm("eth", "https://ethereum-rpc.publicnode.com", "https://etherscan.io/tx/", 1),
    "arb": _evm("arb", "https://arbitrum-one-rpc.publicnode.com", "https://arbiscan.io/tx/", 42161),
    "base": _evm("base", "https://base-rpc.publicnode.com", "https://basescan.org/tx/", 8453),
    "op": _evm("op", "https://optimism-rpc.publicnode.com", "https://optimistic.etherscan.io/tx/", 10),
    "pol": _evm("pol", "https://polygon-bor-rpc.publicnode.com", "https://polygonscan.com/tx/", 137),
    "bsc": _evm("bsc", "https://bsc-rpc.publicnode.com", "https://bscscan.com/tx/", 56),
    "avax": _evm("avax", "https://avalanche-c-chain-rpc.publicnode.com", "https://snowtrace.io/tx/", 43114),
    "gnosis": _evm("gnosis", "https://gnosis-rpc.publicnode.com", "https://gnosisscan.io/tx/", 100),
    "scroll": _evm("scroll", "https://scroll-rpc.publicnode.com", "https://scrollscan.com/tx/", 534352),
}

NEAR_RPC = ChainRpc(
    chain="near",
    display_name="NEAR",
    url=NEAR_RPC_URL,
    kind="near",
    explorer_tx_url="https://nearblocks.io/txns/",
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
