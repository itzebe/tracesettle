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
# HTTP behaviour
# ---------------------------------------------------------------------------

REQUEST_TIMEOUT_SECONDS = float(os.environ.get("TRACESETTLE_HTTP_TIMEOUT", "12"))
MAX_ATTEMPTS = int(os.environ.get("TRACESETTLE_HTTP_ATTEMPTS", "2"))
BACKOFF_BASE_SECONDS = float(os.environ.get("TRACESETTLE_HTTP_BACKOFF", "0.6"))
USER_AGENT = "TraceSettle/0.2 (read-only settlement investigator)"

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


def rpc_for_chain(chain: str | None) -> ChainRpc | None:
    """Return the RPC config for a chain, or ``None`` when unsupported."""
    if not chain:
        return None
    if chain == "near":
        return NEAR_RPC
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
