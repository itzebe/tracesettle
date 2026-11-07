"""A live, read-only NEAR testnet settlement check for the public demonstration.

The public demonstration needs one honest, *non-simulated* piece of evidence: a
real NEAR testnet transaction, read from a public RPC and checked field by field
against the operation it was supposed to perform. This module does exactly that
and nothing else.

It is strictly read-only and keyless:

* it reads an **already-final** transaction from a public NEAR testnet RPC;
* it never builds, signs, or broadcasts anything;
* it refuses mainnet, so it cannot be pointed at real funds;
* it reports ``UNAVAILABLE`` when the RPC cannot answer, and never upgrades an
  outage into a verdict.

The check reuses :func:`tracesettle.near.verify.verify_intent`, so the same
discipline that governs a wallet submission governs the demonstration: only the
on-chain record establishes the state, and a contradiction is ``DISPUTED``
rather than ``VERIFIED``.

The pinned transaction is a real transfer that the project executed on testnet
during development (see ``docs/NEAR_INTEGRATION.md``); its hash is public chain
data, not a secret.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any

from ..cache import TtlCache
from ..httpclient import HttpClient
from ..model import SourceStatus
from .networks import NearNetwork, archive_first_config
from .rpc import NearRpc
from .txbuild import OP_TRANSFER
from .verify import IntendedOperation, SettlementVerification, verify_intent

#: A real, already-final NEAR **testnet** transfer: 0.01 NEAR from a project
#: probe account to a receiver account. Public chain data.
REFERENCE_TX_HASH = "3wQ7UDmQzCTtqyxnBMaQ35SfxioQJUp3rnLyEPX6nuQd"
REFERENCE_SIGNER = "ts-m6-probe-13285.testnet"
REFERENCE_RECEIVER = "ts-m6-recv-13153.testnet"
#: 0.01 NEAR in yoctoNEAR (1 NEAR = 10^24 yoctoNEAR).
REFERENCE_AMOUNT_YOCTO = 10_000_000_000_000_000_000_000
REFERENCE_EXPLORER = "https://testnet.nearblocks.io/txns/"


@dataclass(frozen=True)
class SettlementCheck:
    """The outcome of a live, read-only settlement check."""

    available: bool
    network: str
    tx_hash: str
    explorer_url: str
    verification: SettlementVerification | None
    note: str

    @property
    def state(self) -> str:
        if not self.available or self.verification is None:
            return "UNAVAILABLE"
        return self.verification.state.value

    @property
    def verified(self) -> bool:
        return self.available and self.verification is not None and self.verification.state.value == "VERIFIED"

    def to_dict(self) -> dict[str, Any]:
        return {
            "available": self.available,
            "network": self.network,
            "mainnet": False,
            "tx_hash": self.tx_hash,
            "explorer_url": self.explorer_url,
            "state": self.state,
            "verified": self.verified,
            "note": self.note,
            "verification": self.verification.to_dict() if self.verification else None,
        }


#: A process-wide cache for the reference settlement read. The pinned
#: transaction is already final, so its record is immutable: re-reading it on
#: every request would add several seconds of free-RPC latency to a keyless
#: public route for no new information. Only a successful, *complete*
#: verification is cached; an outage or a partial read is never stored, so a
#: transient failure cannot be replayed as fresh evidence.
_SETTLEMENT_CACHE = TtlCache(ttl_seconds=300.0, max_entries=16)

#: A tight, bounded client for the public demonstration read. The public free
#: nodes prune recent history, so the archive endpoint is the one that usually
#: answers; the shorter timeout keeps a keyless public route responsive even
#: when a node is slow, and a slow node is reported as an outage, never as a
#: verdict about the transaction.
_LIVE_TIMEOUT_SECONDS = 5.0
#: The read tries at most this many endpoints, so a request from a host with no
#: outbound network fails in bounded time rather than stalling a public route.
_LIVE_MAX_ENDPOINTS = 2


def verify_reference_settlement(
    *,
    tx_hash: str = REFERENCE_TX_HASH,
    signer_id: str = REFERENCE_SIGNER,
    receiver_id: str = REFERENCE_RECEIVER,
    amount_yocto: int = REFERENCE_AMOUNT_YOCTO,
    rpc: NearRpc | None = None,
    cache: TtlCache | None = None,
) -> SettlementCheck:
    """Read one final testnet transaction and verify it against its intent.

    ``rpc`` is injectable so a test can substitute the transport; the default is
    a real public testnet RPC client. The network is fixed to testnet here, so
    the check can never be pointed at mainnet.

    The result is cached (a final transaction cannot change) unless a caller
    supplies its own ``rpc``, so a test always exercises the live path.
    """
    if rpc is not None:
        return _verify_reference_settlement(
            tx_hash=tx_hash,
            signer_id=signer_id,
            receiver_id=receiver_id,
            amount_yocto=amount_yocto,
            rpc=rpc,
        )
    store = cache if cache is not None else _SETTLEMENT_CACHE
    key = f"settlement:{tx_hash}:{signer_id}"
    return store.get_or_load(
        key,
        lambda: _verify_reference_settlement(
            tx_hash=tx_hash,
            signer_id=signer_id,
            receiver_id=receiver_id,
            amount_yocto=amount_yocto,
            rpc=None,
        ),
        cache_if=lambda check: check.verified,
    )


def _verify_reference_settlement(
    *,
    tx_hash: str,
    signer_id: str,
    receiver_id: str,
    amount_yocto: int,
    rpc: NearRpc | None,
) -> SettlementCheck:
    """The uncached read-and-verify; see :func:`verify_reference_settlement`."""
    # The transaction is already final, so read it archive-first: a free node
    # has usually pruned it, and the archive is the node that holds the record.
    config = archive_first_config(NearNetwork.TESTNET)
    client = rpc or NearRpc(
        config,
        client=HttpClient(timeout=_LIVE_TIMEOUT_SECONDS, max_attempts=1),
        max_endpoints=_LIVE_MAX_ENDPOINTS,
    )
    result = client.tx_status(tx_hash, signer_id)

    explorer = f"{REFERENCE_EXPLORER}{tx_hash}"
    if not result.ok:
        return SettlementCheck(
            available=False,
            network=NearNetwork.TESTNET.value,
            tx_hash=tx_hash,
            explorer_url=explorer,
            verification=None,
            note=(
                "The public NEAR testnet RPC could not be reached, so no conclusion is drawn. "
                "This is a limitation of the live read, never a statement about the transaction."
            ),
        )

    intended = IntendedOperation(
        network=NearNetwork.TESTNET,
        signer_id=signer_id,
        operation=OP_TRANSFER,
        receiver_id=receiver_id,
        amount_base=amount_yocto,
        destination=receiver_id,
    )
    verification = verify_intent(
        intended=intended,
        result=result.data,
        source_status=SourceStatus.OK,
    )
    return SettlementCheck(
        available=True,
        network=NearNetwork.TESTNET.value,
        tx_hash=tx_hash,
        explorer_url=explorer,
        verification=verification,
        note=(
            "Read live from a public NEAR testnet RPC and checked against the intended "
            "operation. The transaction was already final before this read: nothing is "
            "signed, broadcast, or moved here."
        ),
    )
