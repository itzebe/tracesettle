"""Defuse asset-id parsing.

Asset ids observed in Phase 1:

* ``nep141:wrap.near``                              -> NEAR-native token
* ``nep141:eth.omft.near``                          -> bridged native asset, chain ``eth``
* ``nep141:eth-0xa0b8...eb48.omft.near``            -> bridged token, chain ``eth``, contract
* ``nep141:sol-5ce3...0186.omft.near``              -> bridged token, chain ``sol``
* ``btc:mainnet:native``                            -> non-nep141 asset id (bridge RPC)

The chain is derived from the id prefix. This is a *documented* correlation
mechanism (the id encodes the origin chain), not an inference from amounts.
"""

from __future__ import annotations

import re
from dataclasses import dataclass

_OMFT_SUFFIX = ".omft.near"
_EVM_CONTRACT_RE = re.compile(r"^0x[0-9a-fA-F]{40}$")


@dataclass(frozen=True)
class AssetInfo:
    asset_id: str
    standard: str | None
    chain: str | None
    contract: str | None
    is_omft: bool
    symbol: str | None = None
    decimals: int | None = None


def parse_asset_id(asset_id: str | None) -> AssetInfo | None:
    """Parse a Defuse asset id into structured form. Never raises."""
    if not asset_id or not isinstance(asset_id, str):
        return None
    raw = asset_id.strip()

    # Non-nep141 forms, e.g. "btc:mainnet:native".
    if ":" in raw and not raw.startswith("nep141:"):
        parts = raw.split(":")
        chain = parts[0] or None
        return AssetInfo(
            asset_id=raw, standard=None, chain=chain, contract=None, is_omft=False
        )

    if raw.startswith("nep141:"):
        standard = "nep141"
        token = raw[len("nep141:") :]
    else:
        standard = None
        token = raw

    if token.endswith(_OMFT_SUFFIX):
        prefix = token[: -len(_OMFT_SUFFIX)]
        # "<chain>-<contract>" for tokens, "<chain>" for native assets.
        if "-" in prefix:
            chain, _, rest = prefix.partition("-")
            contract = rest if _EVM_CONTRACT_RE.match(rest) else rest or None
        else:
            chain, contract = prefix, None
        return AssetInfo(
            asset_id=raw,
            standard=standard,
            chain=chain or None,
            contract=contract,
            is_omft=True,
        )

    # A NEAR-native token (wrap.near, usdt.tether-token.near, nbtc.bridge.near, ...).
    return AssetInfo(
        asset_id=raw, standard=standard, chain="near", contract=token, is_omft=False
    )


def chain_of(asset_id: str | None) -> str | None:
    info = parse_asset_id(asset_id)
    return info.chain if info else None


def contract_of(asset_id: str | None) -> str | None:
    info = parse_asset_id(asset_id)
    return info.contract if info else None


class TokenCatalog:
    """assetId -> {symbol, decimals, blockchain}, built from ``GET /v0/tokens``.

    Optional: used only to render human-friendly symbols and to convert base
    units for display. Absence of a catalog never blocks an investigation.
    """

    def __init__(self, tokens: list[dict]) -> None:
        self._by_id: dict[str, dict] = {}
        for token in tokens or []:
            if not isinstance(token, dict):
                continue
            asset_id = token.get("assetId")
            if isinstance(asset_id, str):
                self._by_id[asset_id] = token

    @classmethod
    def empty(cls) -> "TokenCatalog":
        return cls([])

    def __len__(self) -> int:
        return len(self._by_id)

    def lookup(self, asset_id: str | None) -> AssetInfo | None:
        info = parse_asset_id(asset_id)
        if info is None:
            return None
        token = self._by_id.get(info.asset_id) if info.asset_id else None
        if not token:
            return info
        decimals = token.get("decimals")
        return AssetInfo(
            asset_id=info.asset_id,
            standard=info.standard,
            chain=token.get("blockchain") or info.chain,
            contract=token.get("contractAddress") or info.contract,
            is_omft=info.is_omft,
            symbol=token.get("symbol"),
            decimals=decimals if isinstance(decimals, int) else None,
        )


def format_base_units(value: str | None, decimals: int | None) -> str | None:
    """Render an integer base-unit string as a decimal string. Never guesses."""
    if value is None or decimals is None:
        return None
    try:
        amount = int(str(value))
    except (TypeError, ValueError):
        return None
    sign = "-" if amount < 0 else ""
    amount = abs(amount)
    if decimals == 0:
        return f"{sign}{amount}"
    scale = 10**decimals
    whole, frac = divmod(amount, scale)
    frac_str = str(frac).rjust(decimals, "0").rstrip("0")
    return f"{sign}{whole}.{frac_str}" if frac_str else f"{sign}{whole}"
