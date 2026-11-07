"""NEAR network configuration, verified server-side.

A NEAR transaction is only valid on the network whose genesis it names. If a
testnet transaction were ever submitted to mainnet (or the reverse) it would be
rejected, but the more dangerous failure is the quiet one: signing a payload for
the *wrong* network, or letting a client pick the network. This module makes the
network an explicit, server-resolved value with a verifiable identity, so the
two can never drift.

The identity of a network is its **genesis hash** and **chain id**, both read
from the RPC. They are checked against the expected constants below before any
transaction is built or submitted. A mismatch is a hard error, never a warning.

Constants are the public, well-known NEAR genesis hashes; they are checked at
runtime against the live RPC rather than trusted blindly.
"""

from __future__ import annotations

import enum
from dataclasses import dataclass

#: Well-known NEAR genesis hashes (public chain identifiers, not secrets).
TESTNET_GENESIS = "FWJ9kR6KFWoyMoNjpLXXGHeuiy7tEY6GmoFeCA5yuc6b"
MAINNET_GENESIS = "EPnLgE7iEq9s7yTkos96M3cWymH5avBAPm3qx3NXqR8H"


class NearNetwork(str, enum.Enum):
    """The two networks TraceSettle supports."""

    TESTNET = "testnet"
    MAINNET = "mainnet"

    @property
    def chain_id(self) -> str:
        return self.value

    @property
    def genesis_hash(self) -> str:
        return TESTNET_GENESIS if self is NearNetwork.TESTNET else MAINNET_GENESIS

    @property
    def is_mainnet(self) -> bool:
        return self is NearNetwork.MAINNET


class NetworkError(ValueError):
    """The network could not be resolved, or its identity did not check out."""


@dataclass(frozen=True)
class NetworkConfig:
    """A resolved, verified network: where to talk, and what it must prove."""

    network: NearNetwork
    rpc_url: str
    #: Fallback RPC endpoints, tried in order after ``rpc_url`` on a definitive
    #: "not found" (never on an outage - see the RPC client's retry rule).
    rpc_fallbacks: tuple[str, ...] = ()
    explorer_tx_base: str = ""

    @property
    def chain_id(self) -> str:
        return self.network.chain_id

    @property
    def genesis_hash(self) -> str:
        return self.network.genesis_hash

    def explorer_url(self, tx_hash: str) -> str:
        return f"{self.explorer_tx_base}{tx_hash}" if self.explorer_tx_base else ""

    def to_dict(self) -> dict[str, object]:
        return {
            "network": self.network.value,
            "chain_id": self.chain_id,
            "genesis_hash": self.genesis_hash,
            "rpc_url": self.rpc_url,
            "explorer_tx_base": self.explorer_tx_base,
            "mainnet": self.network.is_mainnet,
        }


#: Public, keyless RPC endpoints. These are free and were verified reachable.
#: The free nodes prune recent history within about two days, so the archival
#: node is included as a fallback: a pruned transaction is a definitive
#: ``NOT_FOUND`` on the free node, and only the archive can still answer. A
#: ``NOT_FOUND`` is the *only* status that fans out (see ``NearRpc._call``), so
#: an outage never multiplies load across the endpoints.
_TESTNET_RPC = "https://rpc.testnet.near.org"
_TESTNET_RPC_FALLBACKS = (
    "https://rpc.testnet.fastnear.com",
    "https://archival-rpc.testnet.near.org",
)
_MAINNET_RPC = "https://rpc.mainnet.near.org"
_MAINNET_RPC_FALLBACKS = ("https://free.rpc.fastnear.com", "https://rpc.mainnet.fastnear.com")

NETWORKS: dict[NearNetwork, NetworkConfig] = {
    NearNetwork.TESTNET: NetworkConfig(
        network=NearNetwork.TESTNET,
        rpc_url=_TESTNET_RPC,
        rpc_fallbacks=_TESTNET_RPC_FALLBACKS,
        explorer_tx_base="https://testnet.nearblocks.io/txns/",
    ),
    NearNetwork.MAINNET: NetworkConfig(
        network=NearNetwork.MAINNET,
        rpc_url=_MAINNET_RPC,
        rpc_fallbacks=_MAINNET_RPC_FALLBACKS,
        explorer_tx_base="https://nearblocks.io/txns/",
    ),
}

#: The default network. Testnet is the default so a mistake cannot spend real
#: funds; mainnet is opt-in and always explicit.
DEFAULT_NETWORK = NearNetwork.TESTNET


def archive_first_config(network: NearNetwork) -> NetworkConfig:
    """The network's endpoints, reordered so an archive-capable node is first.

    A *historical* read (an already-final transaction) is a definitive
    ``NOT_FOUND`` on a free node that has pruned it, so the archive is the node
    that actually holds the record. Putting it first turns two round trips into
    one. A live submission must keep the free primary first for freshness, so
    this is opt-in and used only by the historical settlement read.
    """
    config = network_config(network)
    urls = (config.rpc_url, *config.rpc_fallbacks)
    archive = [url for url in urls if "archival" in url]
    if not archive:
        return config
    rest = [url for url in urls if "archival" not in url]
    return NetworkConfig(
        network=config.network,
        rpc_url=archive[0],
        rpc_fallbacks=tuple(archive[1:] + rest),
        explorer_tx_base=config.explorer_tx_base,
    )


def parse_network(value: str | NearNetwork | None) -> NearNetwork:
    """Resolve a network name to an enum, refusing anything unrecognised.

    ``None`` resolves to the default (testnet). An unknown string is an error,
    never a silent fallback to a default - a typo must not become mainnet or
    testnet by accident.
    """
    if isinstance(value, NearNetwork):
        return value
    if value is None or value == "":
        return DEFAULT_NETWORK
    try:
        return NearNetwork(str(value).strip().lower())
    except ValueError as exc:
        allowed = ", ".join(n.value for n in NearNetwork)
        raise NetworkError(f"unknown network {value!r}; expected one of: {allowed}") from exc


def network_config(value: str | NearNetwork | None) -> NetworkConfig:
    return NETWORKS[parse_network(value)]


def verify_network_identity(config: NetworkConfig, status_result: dict) -> None:
    """Check a live ``status`` response against the expected identity.

    Raises :class:`NetworkError` if the chain id or genesis hash disagrees. This
    is the single guard that stops a mainnet endpoint being used while the code
    believes it is on testnet (or the reverse).
    """
    chain_id = str(status_result.get("chain_id", ""))
    genesis = str(status_result.get("genesis_hash", ""))
    if chain_id != config.chain_id:
        raise NetworkError(
            f"RPC chain id {chain_id!r} does not match expected {config.chain_id!r}"
        )
    if genesis != config.genesis_hash:
        raise NetworkError(
            "RPC genesis hash does not match the expected hash for "
            f"{config.chain_id}; refusing to proceed"
        )
