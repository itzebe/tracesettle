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

    def __init__(
        self,
        config: NetworkConfig,
        client: HttpClient | None = None,
        *,
        max_endpoints: int | None = None,
    ) -> None:
        self.config = config
        self.client = client or HttpClient()
        #: Optional bound on how many endpoints a single call may try. ``None``
        #: means "all of them". A caller that must answer a public request in
        #: bounded time sets this so an outage cannot stall the route.
        self.max_endpoints = max_endpoints

    # -- low level ---------------------------------------------------------

    def _endpoints(self) -> list[str]:
        seen: list[str] = []
        for url in (self.config.rpc_url, *self.config.rpc_fallbacks):
            if url and url not in seen:
                seen.append(url)
        if self.max_endpoints is not None:
            return seen[: self.max_endpoints]
        return seen

    def _call(self, method: str, params: Any) -> RpcResult:
        """Call one method, trying fallbacks only on a definitive NOT_FOUND.

        A node may report a definitive miss either as a transport status
        (``NOT_FOUND``) or inside an HTTP 200 as a JSON-RPC error object whose
        classification is ``NOT_FOUND`` (a pruned transaction). Both paths must
        continue to the next endpoint, because a different node may still hold
        the archive. An outage (timeout, rate limit, malformed, server error)
        stops the fan-out: with the source down we cannot tell "absent" from
        "unknown", and hammering the other endpoints only adds load.
        """
        payload = {"jsonrpc": "2.0", "id": "tracesettle", "method": method, "params": params}
        last = RpcResult(SourceStatus.NETWORK_ERROR, error="no endpoint tried")
        for url in self._endpoints():
            result = self.client.post_json(url, payload)
            if result.status is SourceStatus.OK:
                body = result.data
                if not isinstance(body, dict):
                    return RpcResult(SourceStatus.MALFORMED, error="RPC body was not an object", endpoint=url)
                if "error" in body:
                    classified = self._classify_rpc_error(body["error"], url)
                    if classified.status is not SourceStatus.NOT_FOUND:
                        return classified
                    last = classified
                    continue
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
        """Map a JSON-RPC error object to a status, keeping "absent" vs "down".

        The public nodes wrap a definitive miss in a generic envelope: a pruned
        transaction returns ``{"name": "HANDLER_ERROR", "cause": {"name":
        "UNKNOWN_TRANSACTION"}, "data": "Transaction … doesn't exist"}``. The
        outer ``name`` is always ``HANDLER_ERROR``, so the tokens that carry the
        real meaning live in the *cause*, the *data* string and the cause's
        ``info`` values. Every one of those is folded into the search blob; if
        only the outer name were read, a pruned transaction would be classified
        ``MALFORMED`` and the fallback endpoints would never be tried.
        """
        name = ""
        parts: list[str] = []
        if isinstance(error, dict):
            name = str(error.get("name") or "")
            parts.append(name)
            parts.append(str(error.get("message") or ""))
            parts.append(str(error.get("data") or ""))
            cause = error.get("cause")
            if isinstance(cause, dict):
                parts.append(str(cause.get("name") or ""))
                info = cause.get("info")
                if isinstance(info, dict):
                    parts.extend(str(value) for value in info.values())
        blob = " ".join(parts).lower()
        if (
            "unknown_transaction" in blob
            or "does not exist" in blob
            or "doesn't exist" in blob
            or "unknown_block" in blob
        ):
            return RpcResult(SourceStatus.NOT_FOUND, error=name or blob.strip(), endpoint=url)
        if "unknown_account" in blob:
            return RpcResult(SourceStatus.NOT_FOUND, error=name or blob.strip(), endpoint=url)
        if "timeout" in blob or "time out" in blob:
            return RpcResult(SourceStatus.TIMEOUT, error=name or blob.strip(), endpoint=url)
        if "rate" in blob and "limit" in blob:
            return RpcResult(SourceStatus.RATE_LIMITED, error=name or blob.strip(), endpoint=url)
        # Any other structured error is a malformed/unexpected response: never
        # treated as success, and never as "absent" either.
        return RpcResult(SourceStatus.MALFORMED, error=name or blob.strip() or "rpc error", endpoint=url)

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
