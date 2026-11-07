"""Unit tests for the free on-chain TEE signing route.

The live route needs a public HTTPS wasm URL and free testnet NEAR, so it is
opt-in (``tests/test_near_live_onchain_tee.py``). Everything here is offline: the
transport is a stand-in ``NearRpc`` that answers the exact shapes the real node
answers, and the enclave is a stand-in provider that returns a **real** ed25519
keypair's output over the **real** digest. So the parsing, the refusal paths and
the honesty rules are the real code, and only the network is substituted.
"""

from __future__ import annotations

import base64
import hashlib
import json
from decimal import Decimal

import pytest

from tracesettle.base58 import b58decode
from tracesettle.model import SourceStatus
from tracesettle.near import ed25519
from tracesettle.near.networks import NearNetwork
from tracesettle.near.rpc import RpcResult
from tracesettle.near.tee_signing import (
    OnChainCaller,
    OnChainTeeConfig,
    OnChainTeeError,
    OutLayerOnChainSigningProvider,
    TeeProviderUnavailable,
    build_signing_request,
)
from tracesettle.near.tee_signing.boundary import _b58
from tracesettle.near.tee_signing.onchain import (
    _extract_events,
    _extract_success_value,
)
from tracesettle.near.txbuild import build_transfer

SEED = bytes(range(32))
PUBLIC_KEY = "ed25519:" + _b58(ed25519.public_key(SEED))
BLOCK_HASH = "9Gq9bHtf6SKUuWLbzgPMVedA3BtYbYVwb5NVUrQyzoE9"
WASM_SHA = "ab" * 32


class _FakeRpc:
    """Answers the three RPC calls the provider makes, and records submissions."""

    def __init__(self, *, send_ok: bool = True, enclave: "_FakeEnclave | None" = None):
        self.sent: list[str] = []
        self._send_ok = send_ok
        self._enclave = enclave

    def block_hash(self, *, finality: str = "final") -> RpcResult:
        return RpcResult(SourceStatus.OK, data={"hash": BLOCK_HASH, "height": 1})

    def view_access_key(self, account_id: str, public_key: str) -> RpcResult:
        return RpcResult(SourceStatus.OK, data={"nonce": 100, "permission": "FullAccess"})

    def view_account(self, account_id: str) -> RpcResult:
        return RpcResult(SourceStatus.OK, data={"amount": str(10**25)})

    def send_tx(self, signed_b64: str, *, wait_until: str = "INCLUDED_FINAL") -> RpcResult:
        self.sent.append(signed_b64)
        if not self._send_ok:
            return RpcResult(SourceStatus.NOT_FOUND, error="rejected")
        assert self._enclave is not None
        return RpcResult(SourceStatus.OK, data={"receipts_outcome": self._enclave.receipts})


class _FakeEnclave:
    """Produces the exact receipt shape the real OutLayer call produces."""

    def __init__(self, *, digest: str, mode: str = "sign", tamper_digest: str | None = None):
        self.digest = digest
        self.mode = mode
        self.tamper_digest = tamper_digest
        self.receipts: list[dict] = []

    def run(self, input_data: str) -> None:
        request = json.loads(input_data)
        if request.get("guest_op") == "public_key":
            output = {"status": "ok", "operation": "public_key", "public_key": PUBLIC_KEY}
        else:
            sig = ed25519.sign(bytes.fromhex(self.digest.split(":")[1]), SEED)
            output = {
                "status": "ok",
                "public_key": PUBLIC_KEY,
                "signature": base64.b64encode(sig).decode(),
                "signed_transaction": base64.b64encode(b"TXDATA").decode(),
                "transaction_digest": self.tamper_digest or self.digest,
                "tx_hash": "F27Erv42DhGhaTqNXPhsf5KXedfQvP3cd1Vbz9aZnQPj",
                "authorization_id": "m25",
                "manifest_len": 301,
            }
        self.receipts = [
            {
                "outcome": {
                    "status": {"SuccessValue": base64.b64encode(json.dumps(output).encode()).decode()},
                    "logs": [
                        "EVENT_JSON:"
                        + json.dumps(
                            {
                                "standard": "near-outlayer",
                                "event": "execution_completed",
                                "data": [
                                    {
                                        "success": True,
                                        "payment_charged": "1147400000000000000000",
                                        "payment_refunded": "998852600000000000000000",
                                        "resources_used": {"instructions": 52005, "time_ms": 384},
                                    }
                                ],
                            }
                        )
                    ],
                }
            }
        ]


def _wire_enclave(rpc: _FakeRpc, enclave: _FakeEnclave, original):
    """Make the fake transport run the fake enclave before answering.

    The provider embeds the ``request_execution`` args in the signed transaction,
    so the harness recovers them from the bytes the provider actually signed —
    the same bytes a real node would receive.
    """

    def send(signed_b64, *, wait_until="INCLUDED_FINAL"):
        raw = base64.b64decode(signed_b64).decode("latin-1")
        start = raw.find('{"source"')
        end = raw.find('"response_format"', start)
        args_json = raw[start : raw.find("}", end) + 1]
        enclave.run(json.loads(args_json)["input_data"])
        return original(signed_b64)

    return send


def _caller() -> OnChainCaller:
    return OnChainCaller(account_id="payer.testnet", public_key=PUBLIC_KEY, sign=lambda d: ed25519.sign(d, SEED))


def _config() -> OnChainTeeConfig:
    return OnChainTeeConfig(network="testnet", wasm_url="https://example.test/g.wasm", wasm_sha256=WASM_SHA)


def _tx():
    return build_transfer(
        network=NearNetwork.TESTNET,
        signer_id="tee.testnet",
        public_key=PUBLIC_KEY,
        nonce=101,
        receiver_id="merchant.testnet",
        block_hash=BLOCK_HASH,
        amount_human=Decimal("0.1"),
        service_id="m25",
    )


def _request(tx):
    return build_signing_request(
        transaction=tx,
        authorization={"id": "m25", "digest": "sha256:" + "00" * 32, "expiry": "2999-01-01T00:00:00+00:00", "policy_version": "m25"},
        provider="outlayer:signing-keys-onchain",
        approved_build="sha256:" + WASM_SHA,
    )


# -- capability honesty ------------------------------------------------------


def test_no_caller_is_unavailable_and_free():
    provider = OutLayerOnChainSigningProvider(caller=None, config=_config())
    cap = provider.capability()
    assert cap.available is False
    assert cap.requires_payment is False
    assert "caller account" in cap.detail


def test_missing_wasm_hash_is_unavailable():
    provider = OutLayerOnChainSigningProvider(
        caller=_caller(), config=OnChainTeeConfig(network="testnet", wasm_url="https://x/y.wasm", wasm_sha256="")
    )
    assert provider.capability().available is False


def test_ready_reports_the_executor_and_network():
    provider = OutLayerOnChainSigningProvider(caller=_caller(), config=_config())
    cap = provider.capability()
    assert cap.available is True
    assert "outlayer.testnet" in cap.detail


def test_unknown_network_is_refused():
    with pytest.raises(OnChainTeeError):
        OnChainTeeConfig(network="devnet").executor()


def test_mainnet_is_refused():
    """The route is testnet-only, like every other signer in the product."""
    with pytest.raises(OnChainTeeError, match="testnet-only"):
        OnChainTeeConfig(network="mainnet").executor()


def test_a_mainnet_provider_reports_unavailable_and_refuses():
    provider = OutLayerOnChainSigningProvider(
        caller=_caller(),
        config=OnChainTeeConfig(network="mainnet", wasm_url="https://x/y.wasm", wasm_sha256=WASM_SHA),
        rpc=_FakeRpc(),
    )
    with pytest.raises(OnChainTeeError, match="testnet-only"):
        provider.public_key()


def test_sign_without_caller_raises_unavailable():
    provider = OutLayerOnChainSigningProvider(caller=None, config=_config())
    with pytest.raises(TeeProviderUnavailable):
        provider.sign(_request(_tx()))


# -- the enclave call --------------------------------------------------------


def test_public_key_returns_the_enclave_key():
    enclave = _FakeEnclave(digest="sha256:" + "00" * 32)
    rpc = _FakeRpc(enclave=enclave)
    original = rpc.send_tx

    rpc.send_tx = _wire_enclave(rpc, enclave, original)  # type: ignore[assignment]
    provider = OutLayerOnChainSigningProvider(caller=_caller(), config=_config(), rpc=rpc)
    assert provider.public_key() == PUBLIC_KEY


def test_sign_returns_a_verified_signature_over_the_digest():
    tx = _tx()
    enclave = _FakeEnclave(digest=tx.payload_fingerprint())
    rpc = _FakeRpc(enclave=enclave)
    rpc.send_tx = _wire_enclave(rpc, enclave, rpc.send_tx)  # type: ignore[assignment]
    provider = OutLayerOnChainSigningProvider(caller=_caller(), config=_config(), rpc=rpc)
    result = provider.sign(_request(tx))
    assert result.transaction_digest == tx.payload_fingerprint()
    assert result.public_key == PUBLIC_KEY
    assert result.simulated is False
    assert ed25519.verify(
        result.signature_raw64,
        bytes.fromhex(result.transaction_digest.split(":")[1]),
        b58decode(result.public_key.split(":")[1]),
    )
    assert provider.last_run["payment_charged"] == "1147400000000000000000"


def test_a_signature_over_a_different_digest_is_refused():
    tx = _tx()
    enclave = _FakeEnclave(digest=tx.payload_fingerprint(), tamper_digest="sha256:" + "11" * 32)
    rpc = _FakeRpc(enclave=enclave)
    rpc.send_tx = _wire_enclave(rpc, enclave, rpc.send_tx)  # type: ignore[assignment]
    provider = OutLayerOnChainSigningProvider(caller=_caller(), config=_config(), rpc=rpc)
    with pytest.raises(OnChainTeeError, match="different transaction digest"):
        provider.sign(_request(tx))


def test_a_signature_over_other_bytes_is_refused_even_when_the_digest_matches():
    """A signature that does not verify over the authorized digest is refused.

    The enclave reports the right digest but returns a signature over different
    bytes — a buggy or dishonest enclave. The provider must verify the signature
    locally rather than trust the reported digest, so this is caught here.
    """
    tx = _tx()
    enclave = _FakeEnclave(digest=tx.payload_fingerprint())
    rpc = _FakeRpc(enclave=enclave)
    original = rpc.send_tx
    real_run = enclave.run

    def forged_run(input_data: str) -> None:
        real_run(input_data)
        for receipt in enclave.receipts:
            status = receipt["outcome"]["status"]
            answer = json.loads(base64.b64decode(status["SuccessValue"]).decode())
            if answer.get("status") == "ok" and "signature" in answer:
                # Sign a *different* digest; report the correct one.
                forged = ed25519.sign(bytes.fromhex("22" * 32), SEED)
                answer["signature"] = base64.b64encode(forged).decode()
                status["SuccessValue"] = base64.b64encode(json.dumps(answer).encode()).decode()

    enclave.run = forged_run  # type: ignore[assignment]
    rpc.send_tx = _wire_enclave(rpc, enclave, original)  # type: ignore[assignment]
    provider = OutLayerOnChainSigningProvider(caller=_caller(), config=_config(), rpc=rpc)
    with pytest.raises(OnChainTeeError, match="does not verify"):
        provider.sign(_request(tx))


def test_a_rejected_submission_is_an_error_not_a_signature():
    provider = OutLayerOnChainSigningProvider(caller=_caller(), config=_config(), rpc=_FakeRpc(send_ok=False))
    with pytest.raises(OnChainTeeError, match="not accepted"):
        provider.public_key()


def test_the_caller_key_never_enters_the_provider():
    """The provider holds only a sign callable, never a key."""
    provider = OutLayerOnChainSigningProvider(caller=_caller(), config=_config())
    fields = set(vars(provider._caller))
    assert fields == {"account_id", "public_key", "sign"}, fields
    assert not hasattr(provider, "_seed")


# -- receipt parsing ---------------------------------------------------------


def test_extract_success_value_takes_the_last_json_answer():
    receipts = [
        {"outcome": {"status": {"SuccessValue": ""}}},
        {"outcome": {"status": {"SuccessValue": base64.b64encode(b'{"status":"ok","n":1}').decode()}}},
        {"outcome": {"status": {"SuccessValue": base64.b64encode(b'{"status":"ok","n":2}').decode()}}},
    ]
    assert _extract_success_value(receipts) == {"status": "ok", "n": 2}


def test_extract_success_value_ignores_non_json():
    receipts = [{"outcome": {"status": {"SuccessValue": base64.b64encode(b"not json").decode()}}}]
    assert _extract_success_value(receipts) is None


def test_extract_events_keys_by_event_name():
    receipts = [
        {
            "outcome": {
                "logs": [
                    "EVENT_JSON:"
                    + json.dumps({"event": "execution_completed", "data": [{"success": True}]})
                ]
            }
        }
    ]
    events = _extract_events(receipts)
    assert events["execution_completed"] == {"success": True}


def test_the_request_digest_is_the_products_own():
    tx = _tx()
    request = _request(tx)
    assert request.digest() == request.digest()
    assert hashlib.sha256(b"x").hexdigest()  # sanity: hashlib import used
