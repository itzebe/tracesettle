"""Fixture-backed HTTP transport for the offline demonstration.

This replays the **real** Phase 1 captures from ``evidence/raw/`` through the
real adapter and engine code, so the demonstration can still show a full
investigation when a live source (for example the 1Click status API) is
unavailable.

It substitutes the network transport only. The JSON handed to the adapters is
the verbatim captured response, and every classification is produced by the same
code that runs against the live network. What a replay does **not** prove is
that the live endpoint is answering right now; the demonstration labels a
replayed run as such and never presents it as a live query.
"""

from __future__ import annotations

import json
import pathlib
from typing import Any, Callable

#: Repository root, so ``evidence/raw/`` resolves no matter the working directory.
ROOT = pathlib.Path(__file__).resolve().parents[1]
RAW_DIR = ROOT / "evidence" / "raw"

#: The date the captured responses were fetched (UTC), shown with every replay.
CAPTURE_DATE = "2026-10-19"


class _FakeResponse:
    def __init__(self, payload: bytes, status: int = 200) -> None:
        self._payload = payload
        self.status = status
        self.code = status

    def read(self) -> bytes:
        return self._payload

    def __enter__(self) -> "_FakeResponse":
        return self

    def __exit__(self, *exc: object) -> bool:
        return False


class ReplayOpener:
    """A stand-in for ``urllib.request.urlopen`` backed by captured fixtures.

    Routes are matched in registration order against a URL substring and an
    optional request-body substring. A route registered with ``once=True`` is
    consumed after its first match, which is how two calls to the same NEAR RPC
    URL are answered with different captured transactions.
    """

    def __init__(self) -> None:
        self._routes: list[tuple[str, str, str | None, Callable[[], Any], bool]] = []
        self.calls: list[str] = []

    def json(
        self,
        method: str,
        url_contains: str,
        raw_name: str,
        once: bool = False,
        body_contains: str | None = None,
    ) -> "ReplayOpener":
        """Register a captured ``evidence/raw`` file as the response to a route."""
        payload = json.dumps(json.loads((RAW_DIR / raw_name).read_text())).encode("utf-8")
        self._routes.append(
            (method.upper(), url_contains, body_contains, lambda: _FakeResponse(payload), once)
        )
        return self

    def raw(
        self,
        method: str,
        url_contains: str,
        raw_name: str,
        once: bool = False,
        body_contains: str | None = None,
    ) -> "ReplayOpener":
        """Register a captured non-JSON file (e.g. raw Bitcoin transaction hex)."""
        payload = (RAW_DIR / raw_name).read_bytes()
        self._routes.append(
            (method.upper(), url_contains, body_contains, lambda: _FakeResponse(payload), once)
        )
        return self

    def __call__(self, request: Any, timeout: float | None = None) -> _FakeResponse:
        url = request.full_url if hasattr(request, "full_url") else str(request)
        method = getattr(request, "method", "GET") or "GET"
        raw_body = getattr(request, "data", None)
        body_text = raw_body.decode("utf-8", "replace") if isinstance(raw_body, bytes) else ""
        self.calls.append(f"{method} {url}")
        for index, (route_method, needle, body_needle, responder, once) in enumerate(self._routes):
            if route_method != method.upper() or needle not in url:
                continue
            if body_needle is not None and body_needle not in body_text:
                continue
            if once:
                self._routes.pop(index)
            return responder()
        raise AssertionError(
            f"offline replay has no captured response for {method} {url}; "
            "add the capture to evidence/raw/ and register it here"
        )


def verified_settlement_opener() -> ReplayOpener:
    """Routes for the real, verified ETH -> USDC swap (deposit address keyed)."""
    opener = ReplayOpener()
    opener.json("GET", "/v0/status", "oneclick_status_SUCCESS.json")
    opener.json("POST", "ethereum-rpc", "evm_receipt_origin.json", once=True)
    opener.json("POST", "ethereum-rpc", "evm_receipt_destination.json")
    opener.json("POST", "solver-relay", "solver_relay_get_status_SETTLED.json")
    # The NEAR RPC is called once per reported near-tx hash. Match each capture to
    # the hash in the request body: the status lists the bridge mint tx first, so
    # serving by call order would answer the wrong request with the wrong record.
    opener.json(
        "POST", "rpc.fastnear", "near_rpc_tx_omft.json",
        body_contains="FbrSoTHbQdwD6HxabhaozvQQVBA4kF2Qn2c3W2otp284",
    )
    opener.json(
        "POST", "rpc.fastnear", "near_rpc_tx.json",
        body_contains="5E3GdbhwUYj9RFXhkk3rMyPwom4xvMYjtCFj7i2uypFb",
    )
    return opener


def intent_hash_opener() -> ReplayOpener:
    """Routes for the intent-hash-only lookup (solver relay settlement check)."""
    opener = ReplayOpener()
    opener.json("POST", "solver-relay", "solver_relay_get_status_SETTLED.json")
    return opener


def refunded_swap_opener() -> ReplayOpener:
    """Routes for the real refunded BTC -> TRON swap (deposit address keyed).

    The provider now names the refund transaction in ``originChainTxHashes``, so
    the refund is validated from that explicit anchor; the Bitcoin origin and
    bridge captures supply the remaining stages.
    """
    opener = ReplayOpener()
    opener.json("GET", "/v0/status", "oneclick_status_btc_REFUNDED.json")
    opener.json("POST", "solver-relay", "solver_relay_get_status_BTC_REFUNDED.json")
    # NEAR RPC is called once per reported near-tx hash; match by the hash in the
    # request body so the right capture answers the right request.
    opener.json(
        "POST", "rpc.fastnear", "near_rpc_tx_btc_deposit.json",
        body_contains="5G5fbpGz6EJryTD245spudvhQqpx4FC3UcmYRBCjgL7T",
    )
    opener.json(
        "POST", "rpc.fastnear", "near_rpc_tx_btc_settlement.json",
        body_contains="83tjFcjTXfVxRVnBTeYyWmcww7CUWwEpcVmkGeHAjxL1",
    )
    # Origin-chain transactions: the refund tx and the deposit tx, both validated
    # from raw bytes (identity + script checks). The ``/hex`` routes are registered
    # first because ``/tx/{id}`` is a prefix of ``/tx/{id}/hex`` and routes match in
    # registration order.
    opener.raw("GET", "/tx/377b55cbc30363d991838b4803c8c83b231d0193e4b31f8e527728520469721f/hex", "btc_tx_refund.hex")
    opener.json("GET", "/tx/377b55cbc30363d991838b4803c8c83b231d0193e4b31f8e527728520469721f", "btc_tx_refund.json")
    opener.raw("GET", "/tx/9a80de61146553e809f2e57a7b789ae5e64de7aa67fa06009881eac638051226/hex", "btc_tx_deposit.hex")
    opener.json("GET", "/tx/9a80de61146553e809f2e57a7b789ae5e64de7aa67fa06009881eac638051226", "btc_tx_deposit.json")
    # Refund-address history: the ``/txs`` page route is registered before the bare
    # address route because it is a longer match on the same prefix.
    opener.json("GET", "/address/bc1q77w5l5fhkrsq7m05eykug59ks7r8tf6ptmdrgw/txs", "btc_address_history.json")
    opener.json("GET", "/address/bc1q77w5l5fhkrsq7m05eykug59ks7r8tf6ptmdrgw", "btc_address_stats_refund.json")
    return opener
