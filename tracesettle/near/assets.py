"""NEAR asset registry with canonical identity and on-chain decimal checks.

An asset is identified by its **canonical** form, never by a display name:

* native NEAR  -> ``near:native``
* NEP-141 token -> ``near:<contract-account>``

A token's identity is scoped to a network: ``near:wrap.testnet`` on testnet is a
different asset from ``near:wrap.near`` on mainnet, and the two must never be
confused. This is the NEAR analogue of the origin-chain derivation rule the
settlement engine already enforces for bridged assets: an Ethereum-origin USDC
is *not* a native NEAR asset, and a display symbol is never used to decide.

Decimals are part of the asset's identity because an amount is meaningless
without them. The registry carries the value that was verified on-chain
(``ft_metadata``), and :func:`verify_decimals` re-checks it against the live
contract before an amount is converted, so a wrong registry entry fails closed
instead of producing an off-by-10^N transfer.

Amounts are ``Decimal`` end to end. A client amount is never parsed with
``float``: a limit of ``0.3`` must admit exactly ``0.3`` and refuse
``0.30000000000000004``.
"""

from __future__ import annotations

from dataclasses import dataclass
from decimal import Decimal, InvalidOperation

from .networks import NearNetwork

#: The reserved identifier for the chain's native asset.
NATIVE_ID = "native"

#: yoctoNEAR: the smallest unit of native NEAR (1 NEAR = 10^24 yoctoNEAR).
YOCTO_NEAR_DECIMALS = 24


class AssetError(ValueError):
    """An asset could not be resolved, or an amount could not be converted."""


@dataclass(frozen=True)
class NearAsset:
    """A resolved NEAR asset: canonical, network-scoped, with verified decimals."""

    network: NearNetwork
    #: ``native`` for NEAR, otherwise the NEP-141 contract account.
    contract: str | None
    symbol: str
    decimals: int
    name: str = ""

    @property
    def is_native(self) -> bool:
        return self.contract is None

    @property
    def identifier(self) -> str:
        """The canonical identifier, e.g. ``near:native`` or ``near:wrap.near``."""
        return f"near:{self.contract or NATIVE_ID}"

    def to_dict(self) -> dict[str, object]:
        return {
            "identifier": self.identifier,
            "network": self.network.value,
            "kind": "native" if self.is_native else "nep141",
            "contract": self.contract,
            "symbol": self.symbol,
            "name": self.name,
            "decimals": self.decimals,
        }


def _native(network: NearNetwork) -> NearAsset:
    return NearAsset(network=network, contract=None, symbol="NEAR", decimals=YOCTO_NEAR_DECIMALS, name="NEAR")


#: The registry. Decimals were read from each contract's ``ft_metadata`` on the
#: live network (see ``evidence/README.md``). Adding a token here is a deliberate
#: act: an unlisted token is *unsupported*, never "assumed to be 18 decimals".
_REGISTRY: dict[NearNetwork, dict[str, NearAsset]] = {
    NearNetwork.TESTNET: {
        "native": _native(NearNetwork.TESTNET),
        "wrap.testnet": NearAsset(NearNetwork.TESTNET, "wrap.testnet", "wNEAR", 24, "Wrapped NEAR"),
        "usdc.fakes.testnet": NearAsset(NearNetwork.TESTNET, "usdc.fakes.testnet", "USDC.e", 6, "Bridged USDC"),
    },
    NearNetwork.MAINNET: {
        "native": _native(NearNetwork.MAINNET),
        "wrap.near": NearAsset(NearNetwork.MAINNET, "wrap.near", "wNEAR", 24, "Wrapped NEAR"),
        "17208628f84f5d6ad33f0da3bbbeb27ffcb398eac501a31bd6ad2011e36133a1": NearAsset(
            NearNetwork.MAINNET,
            "17208628f84f5d6ad33f0da3bbbeb27ffcb398eac501a31bd6ad2011e36133a1",
            "USDC",
            6,
            "USDC",
        ),
        "usdt.tether-token.near": NearAsset(
            NearNetwork.MAINNET, "usdt.tether-token.near", "USDt", 6, "Tether USD"
        ),
    },
}


def supported_assets(network: NearNetwork) -> list[NearAsset]:
    return sorted(_REGISTRY[network].values(), key=lambda a: (not a.is_native, a.symbol))


def _normalise_key(identifier: str) -> str:
    """Accept ``near:native``, ``native``, ``near:wrap.near`` or ``wrap.near``."""
    value = (identifier or "").strip()
    if value.startswith("near:"):
        value = value[len("near:") :]
    return value


def resolve_asset(network: NearNetwork, identifier: str) -> NearAsset:
    """Resolve an identifier to a registered asset, or raise.

    A display name is never consulted: ``USDC`` is not a key, ``usdc.fakes.testnet``
    is. An unknown identifier raises rather than guessing decimals.
    """
    key = _normalise_key(identifier)
    asset = _REGISTRY.get(network, {}).get(key)
    if asset is None:
        raise AssetError(
            f"{identifier!r} is not a supported asset on {network.value}; "
            "supported: " + ", ".join(sorted(_REGISTRY[network]))
        )
    return asset


def is_supported(network: NearNetwork, identifier: str) -> bool:
    try:
        resolve_asset(network, identifier)
        return True
    except AssetError:
        return False


def to_base_units(amount: Decimal | str, asset: NearAsset) -> int:
    """Convert a human amount to the asset's smallest unit, exactly.

    Raises :class:`AssetError` for a non-positive amount, more decimal places
    than the asset supports (which would be silently truncated otherwise), or an
    amount too large to be a valid ``u128``.
    """
    if isinstance(amount, str):
        try:
            value = Decimal(amount.strip())
        except (InvalidOperation, ValueError) as exc:
            raise AssetError(f"amount {amount!r} is not a decimal number") from exc
    else:
        value = amount
    if not value.is_finite():
        raise AssetError("amount must be finite")
    if value <= 0:
        raise AssetError("amount must be greater than zero")
    scaled = value.scaleb(asset.decimals)
    if scaled != scaled.to_integral_value():
        raise AssetError(
            f"amount {value} has more precision than {asset.symbol} supports "
            f"({asset.decimals} decimals)"
        )
    base = int(scaled)
    if base >= 1 << 128:
        raise AssetError("amount is too large for a NEAR u128 transfer")
    return base


def from_base_units(base: int, asset: NearAsset) -> Decimal:
    """Convert smallest units back to a human amount, exactly."""
    return Decimal(base).scaleb(-asset.decimals)


def verify_decimals(metadata: dict, asset: NearAsset) -> None:
    """Check a live ``ft_metadata`` result against the registry entry.

    Raises :class:`AssetError` on any disagreement, so a drifted or malicious
    contract cannot silently change the meaning of an amount.
    """
    live = metadata.get("decimals")
    if live is None:
        raise AssetError(f"{asset.contract} returned no decimals; refusing to assume")
    if int(live) != asset.decimals:
        raise AssetError(
            f"{asset.contract} reports {live} decimals but the registry expects "
            f"{asset.decimals}; refusing to convert an amount with unverified decimals"
        )
