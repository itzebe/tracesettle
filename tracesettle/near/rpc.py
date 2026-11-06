"""NEAR JSON-RPC client.

A thin, honest wrapper over the public NEAR RPC. It speaks only the documented
JSON-RPC methods and never invents an endpoint or a field. Every call is
classified into the same :class:`~tracesettle.model.SourceStatus` vocabulary the
rest of the product uses, so "the node said not found" and "the node was down"
stay distinct everywhere.

Failure rule (shared with the settlement adapters): a *definitive* ``NOT_FOUND``
tries the next endpoint, because a different node may hold the archive. An
**outage** (timeout, network error, rate limit, server error) does **not** fan
out - with the source down we cannot tell "absent" from "unknown", and fanning
out only adds load. An outage is reported as an outage.

Submission is idempotent by construction: a NEAR transaction's hash covers its
nonce, so resubmitting the *same* signed bytes can only ever be applied once by
the network. Retrying an identical payload is therefore safe; retrying a
*different* payload is never done here.
"""

from __future__ import annotations

import json
from dataclasses import dataclass
from typing import Any

from ..httpclient import HttpClient
from ..model import SourceStatus
from .networks import NetworkConfig

#: RPC methods used. Kept as constants so a typo is a NameError, not a silent
#: 400 from the node.
METHOD_STATUS = "status"
METHOD_BLOCK = "block"
METHOD_QUERY = "query"
METHOD_GAS_PRICE = "gas_price"
METHOD_SEND_TX = "broadcast_tx_commit"
METHOD_TX = "tx"
METHOD_EXPERIMENTAL_TX_STATUS = "EXPERIMENTAL_tx_status"


@dataclass(frozen=True)
class RpcResult:
    """The outcome of one RPC call, with the failure kept distinct from data."""

    status: SourceStatus
    data: Any = None
    error: str | None = None
    endpoint: str = ""

    @property
    def ok(self) -> bool:
        return self.status is SourceStatus.OK


class NearRpc:
    """A NEAR RPC client bound to one resolved, identity-checked network."""

    def __init__(self, config: NetworkConfig, client: HttpClient | None = None) -> None:
        self.config = config
        self.client = client or HttpClient()

    # -- low level ---------------------------------------------------------

    def _endpoints(self) -> list[str]:
        seen: list[str] = []
        for url in (self.config.rpc_url, *self.config.rpc_fallbacks):
            if url and url not in seen:
                seen.append(url)
        return seen

    def _call(self, method: str, params: Any) -> RpcResult:
        """Call one method, trying fallbacks only on a definitive NOT_FOUND."""
        payload = {"jsonrpc": "2.0", "id": "tracesettle", "method": method, "params": params}
        last = RpcResult(SourceStatus.NETWORK_ERROR, error="no endpoint tried")
        for url in self._endpoints():
            result = self.client.post_json(url, payload)
            if result.status is SourceStatus.OK:
                body = result.data
                if not isinstance(body, dict):
                    return RpcResult(SourceStatus.MALFORMED, error="RPC body was not an object", endpoint=url)
                if "error" in body:
                    return self._classify_rpc_error(body["error"], url)
                if "result" not in body:
                    return RpcResult(SourceStatus.MALFORMED, error="RPC body had no result", endpoint=url)
                return RpcResult(SourceStatus.OK, data=body["result"], endpoint=url)
            last = RpcResult(result.status, error=result.message or str(result.status), endpoint=url)
            # Only a definitive miss is worth another endpoint.
            if result.status is not SourceStatus.NOT_FOUND:
                return last
        return last

    @staticmethod
    def _classify_rpc_error(error: Any, url: str) -> RpcResult:
        """Map a JSON-RPC error object to a status, keeping "absent" vs "down"."""
        name = ""
        message = ""
        if isinstance(error, dict):
            name = str(error.get("name") or "")
            message = str(error.get("message") or "")
            cause = error.get("cause")
            if isinstance(cause, dict) and cause.get("name"):
                name = name or str(cause["name"])
        blob = f"{name} {message}".lower()
        if "unknown_transaction" in blob or "does not exist" in blob or "unknown_block" in blob:
            return RpcResult(SourceStatus.NOT_FOUND, error=name or message, endpoint=url)
        if "unknown_account" in blob or "account" in blob and "does not exist" in blob:
            return RpcResult(SourceStatus.NOT_FOUND, error=name or message, endpoint=url)
        if "timeout" in blob or "time out" in blob:
            return RpcResult(SourceStatus.TIMEOUT, error=name or message, endpoint=url)
        if "rate" in blob and "limit" in blob:
            return RpcResult(SourceStatus.RATE_LIMITED, error=name or message, endpoint=url)
        # Any other structured error is a malformed/unexpected response: never
        # treated as success, and never as "absent" either.
        return RpcResult(SourceStatus.MALFORMED, error=name or message or "rpc error", endpoint=url)

    # -- typed helpers -----------------------------------------------------

    def status(self) -> RpcResult:
        return self._call(METHOD_STATUS, [])

    def block_hash(self, *, finality: str = "final") -> RpcResult:
        result = self._call(METHOD_BLOCK, {"finality": finality})
        if not result.ok or not isinstance(result.data, dict):
            return result
        header = result.data.get("header", {})
        h = header.get("hash")
        if not isinstance(h, str):
            return RpcResult(SourceStatus.MALFORMED, error="block had no hash", endpoint=result.endpoint)
        return RpcResult(SourceStatus.OK, data={"hash": h, "height": header.get("height")}, endpoint=result.endpoint)

    def gas_price(self) -> RpcResult:
        result = self._call(METHOD_GAS_PRICE, [None])
        if not result.ok or not isinstance(result.data, dict):
            return result
        price = result.data.get("gas_price")
        if not isinstance(price, str):
            return RpcResult(SourceStatus.MALFORMED, error="no gas_price", endpoint=result.endpoint)
        return RpcResult(SourceStatus.OK, data=int(price), endpoint=result.endpoint)

    def view_access_key(self, account_id: str, public_key: str) -> RpcResult:
        """Fetch an account's access key (nonce + permission).

        ``public_key`` is the ``ed25519:<b58>`` form. A missing key is
        ``NOT_FOUND`` (the key does not exist), which is a real answer, not an
        error.
        """
        params = {
            "request_type": "view_access_key",
            "finality": "final",
            "account_id": account_id,
            "public_key": public_key,
        }
        return self._call(METHOD_QUERY, params)

    def view_account(self, account_id: str) -> RpcResult:
        params = {
            "request_type": "view_account",
            "finality": "final",
            "account_id": account_id,
        }
        return self._call(METHOD_QUERY, params)

    def call_function(
        self, account_id: str, method_name: str, args: dict | None = None, *, finality: str = "final"
    ) -> RpcResult:
        """Call a view method and decode its JSON result.

        The node returns the result as a byte array; it is decoded here so
        callers get the object the contract returned.
        """
        import base64

        raw_args = json.dumps(args or {}).encode()
        params = {
            "request_type": "call_function",
            "finality": finality,
            "account_id": account_id,
            "method_name": method_name,
            "args_base64": base64.b64encode(raw_args).decode(),
        }
        result = self._call(METHOD_QUERY, params)
        if not result.ok or not isinstance(result.data, dict):
            return result
        if "error" in result.data:
            return RpcResult(SourceStatus.MALFORMED, error=str(result.data["error"]), endpoint=result.endpoint)
        raw = result.data.get("result")
        if raw is None:
            return RpcResult(SourceStatus.MALFORMED, error="call_function returned no result", endpoint=result.endpoint)
        try:
            decoded = json.loads(bytes(raw).decode("utf-8"))
        except (ValueError, TypeError, UnicodeDecodeError):
            return RpcResult(SourceStatus.MALFORMED, error="contract result was not JSON", endpoint=result.endpoint)
        return RpcResult(SourceStatus.OK, data=decoded, endpoint=result.endpoint)

    def send_tx(self, signed_transaction_b64: str, *, wait_until: str = "INCLUDED_FINAL") -> RpcResult:
        """Broadcast a signed transaction and wait for a result.

        The payload is the base64 of the borsh-encoded ``SignedTransaction``.
        Retrying identical bytes is safe (the hash includes the nonce); this
        client never retries a different payload.
        """
        params = [signed_transaction_b64]
        result = self._call(METHOD_SEND_TX, params)
        return result

    def tx_status(self, tx_hash: str, sender_account_id: str) -> RpcResult:
        """Fetch a transaction's full result. ``sender_account_id`` is required."""
        params = {
            "tx_hash": tx_hash,
            "sender_account_id": sender_account_id,
            "wait_until": "NONE",
        }
        return self._call(METHOD_TX, params)

    def experimental_tx_status(self, tx_hash: str, sender_account_id: str) -> RpcResult:
        params = {
            "tx_hash": tx_hash,
            "sender_account_id": sender_account_id,
            "wait_until": "NONE",
        }
        return self._call(METHOD_EXPERIMENTAL_TX_STATUS, params)
