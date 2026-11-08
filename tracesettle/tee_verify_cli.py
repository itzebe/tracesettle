"""Reviewer commands: verify the TEE trust chain without trusting the product.

Everything here is read-only and reproducible from public data. A reviewer can
run these against a recorded run, or against the live chain, and reach the same
verdict the product does — or refute it. Nothing needs a private key, a paid
service, or an account.

Commands
--------

``guest verify``
    Recompute the build-input digest and compare it to the recorded identity, and
    (when the artifact is present) its sha256. Run ``build.sh`` first to
    reproduce the bytes.

``attestation verify``
    Fetch the attestation for an execution transaction from OutLayer's free API
    and verify every claim: the Intel quote, the Task-Hash commitment, the worker
    measurement against the quote and against the on-chain register contract, the
    approved build, the execution binding, and the input/output payload hashes.

``signature verify``
    Verify the enclave's ed25519 signature over the transaction digest recomputed
    from the signed transaction bytes.

``chain verify``
    Check that every stage of an evidence chain names the same transaction.

Each command prints a human report by default and ``--json`` for a machine. The
exit code is 0 only when the check passed.
"""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path
from typing import Any

from . import base58
from .near import ed25519
from .near import borsh
from .near.tee_signing.build_verify import GUEST_DIR, ReproducibleBuildError, verify_build
from .near.tee_signing.evidence_chain import (
    EvidenceChain,
    verify_chain_bindings,
)
from .near.tee_signing.outlayer_attestation import (
    OutLayerAttestationError,
    fetch_attestation,
    verify_outlayer_attestation,
)

_MARK = {True: "PASS", False: "FAIL"}


def _emit(payload: dict[str, Any], *, as_json: bool, title: str, ok: bool) -> int:
    if as_json:
        print(json.dumps(payload, indent=2, sort_keys=True))
    else:
        print(f"== {title} ==")
        _print_human(payload)
        print()
        print(f"RESULT: {_MARK[ok]}")
    return 0 if ok else 1


def _print_human(node: Any, indent: int = 0) -> None:
    pad = "  " * indent
    if isinstance(node, dict):
        for key, value in node.items():
            if isinstance(value, (dict, list)):
                print(f"{pad}{key}:")
                _print_human(value, indent + 1)
            else:
                print(f"{pad}{key}: {value}")
    elif isinstance(node, list):
        for item in node:
            if isinstance(item, dict) and "name" in item:
                mark = "OK " if item.get("holds") else "FAIL"
                detail = f" - {item['detail']}" if item.get("detail") else ""
                print(f"{pad}[{mark}] {item['name']}{detail}")
            elif isinstance(item, (dict, list)):
                _print_human(item, indent + 1)
            else:
                print(f"{pad}- {item}")
    else:
        print(f"{pad}{node}")


# -- guest build -------------------------------------------------------------


def cmd_guest_verify(args: argparse.Namespace) -> int:
    try:
        verdict = verify_build(
            guest_dir=Path(args.guest_dir) if args.guest_dir else None,
            artifact=Path(args.artifact) if args.artifact else None,
            variant=args.variant,
        )
    except ReproducibleBuildError as exc:
        print(f"cannot verify the build: {exc}", file=sys.stderr)
        return 2
    payload = verdict.to_dict()
    payload["artifact_present"] = verdict.artifact_present
    if not verdict.artifact_present and not args.json:
        print(
            "NOTE: the artifact is not built here. The input-identity check ran; "
            "run guest/signing-module/build.sh to reproduce the bytes, then re-run.",
            file=sys.stderr,
        )
    return _emit(payload, as_json=args.json, title="guest build identity", ok=verdict.holds)


# -- attestation -------------------------------------------------------------


def cmd_attestation_verify(args: argparse.Namespace) -> int:
    record: dict[str, Any] | None = None
    tx_result: dict[str, Any] | None = None
    recorded_approval: dict[str, Any] | None = None
    if args.record:
        record = json.loads(Path(args.record).read_text(encoding="utf-8"))
        if "attestation" in record:  # a fixture that wraps the record
            tx_result = record.get("tx_result")
            recorded_approval = record.get("worker_approval")
            args.tx_hash = args.tx_hash or record.get("execution_tx_hash", "")
            args.approved_build = args.approved_build or record.get("approved_wasm_sha256", "")
            record = record["attestation"]
    if record is None:
        if not args.tx_hash:
            print("provide a --tx-hash or a --record", file=sys.stderr)
            return 2
        try:
            record = fetch_attestation(args.tx_hash, network=args.network)
        except OutLayerAttestationError as exc:
            print(f"cannot fetch the attestation: {exc}", file=sys.stderr)
            return 2

    if tx_result is None and args.tx_result:
        tx_result = json.loads(Path(args.tx_result).read_text(encoding="utf-8"))
        tx_result = tx_result.get("result", tx_result)

    # The worker-approval read is the only on-chain call. Prefer the recorded
    # answer so the command is reproducible offline; ``--live-worker-approval``
    # re-reads it from the register contract instead.
    rpc = None
    if not args.no_worker_approval and not args.live_worker_approval and recorded_approval:
        from .near.tee_signing.outlayer_attestation import RecordedApprovalRpc

        rpc = RecordedApprovalRpc(recorded_approval)

    try:
        verdict = verify_outlayer_attestation(
            record,
            expected_transaction_hash=args.tx_hash or "",
            expected_wasm_sha256=args.approved_build or "",
            network=args.network,
            rpc=rpc,
            tx_result=tx_result,
            check_worker_approval=not args.no_worker_approval,
        )
    except OutLayerAttestationError as exc:
        print(f"cannot verify the attestation: {exc}", file=sys.stderr)
        return 2
    payload = verdict.to_dict()
    payload["execution_tx_hash"] = args.tx_hash or verdict.transaction_hash
    payload["worker_approval_source"] = (
        "live" if args.live_worker_approval else ("recorded" if rpc is not None else "none")
    )
    return _emit(payload, as_json=args.json, title="OutLayer execution attestation", ok=verdict.verified)


# -- signature ---------------------------------------------------------------


def cmd_signature_verify(args: argparse.Namespace) -> int:
    import base64
    import hashlib

    data = json.loads(Path(args.record).read_text(encoding="utf-8"))
    signing = data.get("signing", data.get("sign_transaction", {}).get("output", data))
    public_key = str(signing.get("public_key", ""))
    signature_b64 = str(signing.get("signature", signing.get("signature_b64", "")))
    signed_b64 = str(signing.get("signed_transaction", signing.get("signed_b64", "")))
    if not (public_key and signature_b64 and signed_b64):
        print("the record must carry public_key, signature and signed_transaction", file=sys.stderr)
        return 2

    signed_bytes = base64.b64decode(signed_b64)
    signature = base64.b64decode(signature_b64)
    # NEAR's ``SignedTransaction`` is the Borsh ``Transaction`` followed by a Borsh
    # ``Signature``: a one-byte algorithm tag then the 64 signature bytes. The
    # enclave signs ``sha256(transaction)`` — the message NEAR itself verifies — so
    # the signed region is everything except that trailer. The length is the shared
    # constant, so this CLI cannot disagree with the product's own serializer.
    from .near.txbuild import SIGNATURE_TRAILER_LEN

    if len(signed_bytes) <= SIGNATURE_TRAILER_LEN:
        print("the signed transaction is too short to carry a signature", file=sys.stderr)
        return 2
    unsigned = signed_bytes[:-SIGNATURE_TRAILER_LEN]
    digest = hashlib.sha256(unsigned).digest()
    raw_key = base58.b58decode(public_key.split(":")[-1]) or b""

    signature_ok = len(signature) == 64 and ed25519.verify(signature, digest, raw_key)
    claimed = str(signing.get("transaction_digest", "")).replace("sha256:", "").lower()
    digest_matches_claim = (digest.hex() == claimed) if claimed else None
    tx_hash_bytes = borsh.transaction_hash(unsigned)

    # If the record also carries the structured request, rebuild the bytes from it
    # and check they are the same bytes — so the signature is over the transaction
    # the product *meant* to sign, not merely over an opaque blob.
    structured = _structured_from_record(data)
    structured_matches = None
    if structured is not None:
        structured_matches = structured == unsigned

    payload = {
        "public_key": public_key,
        "signature_verified_over_the_digest": signature_ok,
        "signed_bytes_len": len(signed_bytes),
        "recomputed_transaction_digest": digest.hex(),
        "claimed_transaction_digest": claimed or "(not stated)",
        "recomputed_digest_matches_claim": digest_matches_claim,
        "recomputed_tx_hash": base58.b58encode(tx_hash_bytes),
        "claimed_tx_hash": signing.get("tx_hash", "(not stated)"),
        "rebuilt_from_structured_request_matches": structured_matches,
    }
    ok = (
        signature_ok
        and digest_matches_claim is not False
        and structured_matches is not False
    )
    return _emit(payload, as_json=args.json, title="enclave signature", ok=ok)


def _structured_from_record(data: dict[str, Any]) -> bytes | None:
    """Rebuild the NEAR ``Transaction`` bytes from a structured record, if present.

    Accepts either the product's request shape (``signer_account``/``public_key``/
    ``nonce``/``receiver_account``/``block_hash``/``actions``) or the RPC's
    transaction shape (``signer_id``/``receiver_id``/``actions``), when a
    ``block_hash`` is available. Returns ``None`` when the bytes cannot be rebuilt
    from what was recorded — never a partial guess.
    """
    request = None
    for key in ("request", "signing_request", "input"):
        value = data.get(key)
        if isinstance(value, dict):
            request = value
            break
    if request is None:
        return None
    try:
        signer = str(request.get("signer_account", request.get("signer_id", "")))
        receiver = str(request.get("receiver_account", request.get("receiver_id", "")))
        public_key = str(request["public_key"])
        block_hash = request.get("block_hash")
        if not (signer and receiver and public_key and block_hash):
            return None
        return borsh.transaction(
            signer,
            base58.b58decode(public_key.split(":")[-1]),
            int(request["nonce"]),
            receiver,
            base58.b58decode(block_hash),
            tuple(_action_bytes(a) for a in request["actions"]),
        )
    except Exception:  # noqa: BLE001 - an unrebuildable record is simply not rebuilt
        return None


def _action_bytes(action: dict[str, Any]) -> bytes:
    """One action's Borsh bytes, accepting the RPC's ``{"Transfer": {...}}`` shape."""
    if "Transfer" in action and isinstance(action["Transfer"], dict):
        return borsh.action_transfer(int(action["Transfer"]["deposit"]))
    kind = str(action.get("type", ""))
    if kind == "Transfer":
        return borsh.action_transfer(int(action["deposit"]))
    if kind == "FunctionCall":
        encoded = json.dumps(action.get("args"), separators=(",", ":")).encode("utf-8")
        return borsh.action_function_call(
            str(action["method_name"]), encoded, int(action.get("gas", 0)), int(action.get("deposit", "1"))
        )
    raise ValueError(f"unsupported action type {kind!r}")


# -- evidence chain ----------------------------------------------------------


def cmd_chain_verify(args: argparse.Namespace) -> int:
    data = json.loads(Path(args.record).read_text(encoding="utf-8"))
    chain = EvidenceChain.from_dict(data)
    binding = verify_chain_bindings(chain)
    payload = {
        "transaction_digest": chain.transaction_digest,
        "tx_hash": chain.tx_hash,
        "network": chain.network,
        "stages_present": [s for s in chain.stages],
        "chain_digest": chain.digest(),
        "bound": binding.bound,
        "checks": binding.checks,
        "failures": binding.failures,
    }
    return _emit(payload, as_json=args.json, title="evidence chain", ok=binding.bound)


def add_reviewer_subcommands(sub: argparse._SubParsersAction) -> None:  # type: ignore[type-arg]
    """Attach the reviewer commands to the main CLI's subparser group."""
    guest = sub.add_parser("guest", help="reproducible-build commands for the TEE signing guest")
    guest_sub = guest.add_subparsers(dest="guest_command", required=True)
    gv = guest_sub.add_parser("verify", help="verify the build identity and (if built) the artifact")
    gv.add_argument("--guest-dir", default="", help="the guest crate directory")
    gv.add_argument("--artifact", default="", help="an artifact to hash instead of the recorded path")
    gv.add_argument("--variant", default="wasm", choices=["wasm", "project"])
    gv.add_argument("--json", action="store_true")
    gv.set_defaults(func=cmd_guest_verify)

    att = sub.add_parser("attestation", help="verify an OutLayer execution attestation")
    att_sub = att.add_subparsers(dest="attestation_command", required=True)
    av = att_sub.add_parser("verify", help="fetch and verify the attestation for an execution")
    av.add_argument("--tx-hash", default="", help="the execution transaction hash")
    av.add_argument("--record", default="", help="a recorded attestation JSON instead of fetching")
    av.add_argument("--tx-result", default="", help="a NEAR RPC tx result, to bind input/output hashes")
    av.add_argument("--approved-build", default="", help="the pinned approved wasm sha256")
    av.add_argument("--network", default="testnet", choices=["testnet", "mainnet"])
    av.add_argument("--no-worker-approval", action="store_true", help="skip the on-chain register read")
    av.add_argument(
        "--live-worker-approval",
        action="store_true",
        help="read worker approval from the register contract instead of the recorded answer",
    )
    av.add_argument("--json", action="store_true")
    av.set_defaults(func=cmd_attestation_verify)

    sig = sub.add_parser("signature", help="verify an enclave signature over a recorded transaction")
    sig_sub = sig.add_subparsers(dest="signature_command", required=True)
    sv = sig_sub.add_parser("verify", help="verify the ed25519 signature and recompute the digest")
    sv.add_argument("record", help="a JSON record carrying public_key/signature/signed_transaction")
    sv.add_argument("--json", action="store_true")
    sv.set_defaults(func=cmd_signature_verify)

    chain = sub.add_parser("chain", help="verify an evidence chain")
    chain_sub = chain.add_subparsers(dest="chain_command", required=True)
    cv = chain_sub.add_parser("verify", help="check that every stage names the same transaction")
    cv.add_argument("record", help="a JSON evidence-chain record")
    cv.add_argument("--json", action="store_true")
    cv.set_defaults(func=cmd_chain_verify)


__all__ = [
    "GUEST_DIR",
    "add_reviewer_subcommands",
    "cmd_attestation_verify",
    "cmd_chain_verify",
    "cmd_guest_verify",
    "cmd_signature_verify",
]
