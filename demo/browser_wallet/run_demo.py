#!/usr/bin/env python3
"""Live browser-wallet journey on NEAR testnet (demonstration harness).

This drives the **real** TraceSettle console in a **real** Chromium browser with
a browser-wallet emulator that holds the key and signs, so the full journey is
exercised end to end:

    connect -> authorize (the real guard) -> the wallet signs and sends ->
    independent settlement verification

The web page never sees a private key. The emulator plays the role of a wallet
*extension*: it keeps the key in the Node process, builds the NEAR transaction
with the same Borsh layout as ``tracesettle/near/borsh.py`` (byte-identical,
pinned by ``tests/test_browser_wallet_borsh.py``), signs ed25519, and broadcasts
to NEAR testnet. The page receives only a signed-and-broadcast transaction hash,
exactly as a real wallet returns.

Four scenarios are run:

  happy    an approved transfer: authorization ALLOW, the wallet signs, and
           independent verification reaches VERIFIED.
  blocked  a recipient outside the operator policy: authorization BLOCK, and the
           wallet is never asked to sign.
  tamper   the wallet signs a different amount than the one authorized: the
           transfer succeeds on-chain but settlement is DISPUTED, because the
           on-chain record contradicts the authorized intent.
  reject   the user rejects the signature request: nothing is broadcast.

This script never installs anything. It refuses to run without the prerequisites
(a Chromium binary, a ``puppeteer-core`` install, and a *testnet* key) and never
points at mainnet. The key is used only to sign the demonstration transactions.

Prerequisites (see ``demo/browser_wallet/README.md``):

    cd demo/browser_wallet && npm install   # puppeteer-core, pinned
    export TSW_SEED=<64-hex-ed25519-secret>   # a funded *.testnet account key
    export TSW_ACCOUNT=<your-account.testnet>
    export TSW_RECEIVER=<recipient.testnet>   # an existing *.testnet account

Usage:
    python demo/browser_wallet/run_demo.py [--outdir DIR] [--amount 0.02]
"""

from __future__ import annotations

import argparse
import json
import os
import pathlib
import secrets
import shutil
import socket
import subprocess
import sys
import tempfile
import time
import urllib.error
import urllib.request

HERE = pathlib.Path(__file__).resolve().parent
REPO = HERE.parents[1]
sys.path.insert(0, str(REPO))

from tracesettle.near import ed25519  # noqa: E402

B58 = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz"
EXPECTED = {
    "happy": "VERIFIED",
    "blocked": "BLOCK",
    "tamper": "DISPUTED",
    "reject": "did not send",
}


def _b58encode(raw: bytes) -> str:
    n = int.from_bytes(raw, "big")
    out = ""
    while n:
        n, r = divmod(n, 58)
        out = B58[r] + out
    pad = len(raw) - len(raw.lstrip(b"\x00"))
    return "1" * pad + (out or "")


def _free_port() -> int:
    with socket.socket() as s:
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]


def _policy(receiver: str) -> dict:
    return {
        "policy_id": "near-testnet-browser-demo",
        "name": "NEAR testnet browser-wallet demonstration policy",
        "version": "1",
        "approved_destinations": [receiver],
        "blocked_destinations": [],
        "services": [
            {
                "service_id": "treasury-agent",
                "enabled": True,
                "allowed_operations": ["WITHDRAWAL", "SETTLEMENT"],
                "allowed_chains": ["near-testnet"],
                "allowed_assets": ["NEAR:NATIVE"],
                "max_amount_per_transaction": "5",
                "max_amount_per_window": "50",
                "approval_threshold": "100",
            }
        ],
        "per_transaction_limit": "5",
        "window_seconds": 3600,
        "max_requests_per_window": 30,
        "max_blocked_per_window": 5,
        "approval_threshold": "100",
        "min_approvals": 1,
        "max_rejected_authorizations": 3,
        "authorization_ttl_seconds": 90,
        "allow_unlisted_destinations": False,
    }


def _prereqs() -> list[str]:
    problems: list[str] = []
    if not os.environ.get("TSW_SEED"):
        problems.append("TSW_SEED is not set (a 64-hex ed25519 secret for a *.testnet account)")
    if not os.environ.get("TSW_ACCOUNT", "").endswith(".testnet"):
        problems.append("TSW_ACCOUNT must be a *.testnet account")
    if not os.environ.get("TSW_RECEIVER", "").endswith(".testnet"):
        problems.append("TSW_RECEIVER must be a *.testnet account")
    if shutil.which("node") is None:
        problems.append("node is not on PATH")
    chromium = os.environ.get("PUPPETEER_EXECUTABLE_PATH") or shutil.which("chromium") or shutil.which(
        "chromium-browser"
    ) or shutil.which("google-chrome")
    if not chromium:
        problems.append("no Chromium/Chrome binary found (set PUPPETEER_EXECUTABLE_PATH)")
    if not (HERE / "node_modules" / "puppeteer-core").exists():
        problems.append("puppeteer-core is not installed; run `npm install` in demo/browser_wallet")
    return problems


def _wait_health(base: str, timeout: float = 20.0) -> bool:
    deadline = time.time() + timeout
    while time.time() < deadline:
        try:
            with urllib.request.urlopen(base + "/api/health", timeout=2) as r:
                if r.status == 200:
                    return True
        except (urllib.error.URLError, OSError):
            time.sleep(0.4)
    return False


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Live browser-wallet journey on NEAR testnet")
    parser.add_argument("--outdir", default=None, help="where to write screenshots + JSON evidence")
    parser.add_argument("--amount", default="0.02", help="NEAR to transfer (default 0.02)")
    args = parser.parse_args(argv)

    outdir = pathlib.Path(args.outdir) if args.outdir else pathlib.Path(tempfile.mkdtemp(prefix="ts-wallet-"))
    outdir.mkdir(parents=True, exist_ok=True)

    print("=" * 78)
    print("TRACESETTLE x NEAR - browser-wallet journey (live testnet demonstration)")
    print("=" * 78)

    problems = _prereqs()
    if problems:
        print("This demonstration cannot run here. Missing prerequisites:")
        for p in problems:
            print("  - " + p)
        print()
        print("It never installs anything. See demo/browser_wallet/README.md.")
        return 0

    seed = bytes.fromhex(os.environ["TSW_SEED"].removeprefix("ed25519:"))
    if len(seed) != 32:
        print("TSW_SEED must decode to exactly 32 bytes.")
        return 2
    account = os.environ["TSW_ACCOUNT"]
    receiver = os.environ["TSW_RECEIVER"]
    pubkey = "ed25519:" + _b58encode(ed25519.public_key(seed))

    port = _free_port()
    base = f"http://127.0.0.1:{port}"
    api_key = secrets.token_hex(24)
    guard_key = secrets.token_hex(32)
    policy_path = outdir / "policy.json"
    policy_path.write_text(json.dumps(_policy(receiver), indent=2), encoding="utf-8")

    env = dict(os.environ)
    env.update(
        {
            "TRACESETTLE_NEAR_EXECUTION": "1",
            "TRACESETTLE_NEAR_EXECUTION_NETWORK": "testnet",
            "TRACESETTLE_GUARD_POLICY": str(policy_path),
            "TRACESETTLE_API_KEY": api_key,
            "TRACESETTLE_GUARD_AUTH_KEY": guard_key,
            "TRACESETTLE_GUARD_RATE_LIMIT_PER_MINUTE": "1200",
            "TRACESETTLE_GUARD_RATE_LIMIT_BURST": "300",
            "TSW_SEED": seed.hex(),
            "TSW_ACCOUNT": account,
            "TSW_RECEIVER": receiver,
            "TSW_PUBKEY": pubkey,
            "TSW_API_KEY": api_key,
            "TSW_CONSOLE": base + "/console",
            "TS_OUTDIR": str(outdir),
        }
    )

    print("network   : testnet")
    print(f"account   : {account}")
    print(f"receiver  : {receiver}  (approved destination)")
    print(f"amount    : {args.amount} NEAR")
    print(f"evidence  : {outdir}")
    print()

    server = subprocess.Popen(
        [sys.executable, "-m", "tracesettle", "serve", "--host", "127.0.0.1", "--port", str(port)],
        cwd=str(REPO),
        env=env,
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
    )
    try:
        if not _wait_health(base):
            print("the local server did not become healthy; aborting.")
            return 1
        print("local console is up with the NEAR execution boundary enabled.")
        print("(the server holds no key; the emulated wallet signs and sends)")
        print()

        failures = 0
        for scenario in ("happy", "blocked", "tamper", "reject"):
            print("-" * 78)
            print(f"scenario: {scenario}  (expected: {EXPECTED[scenario]})")
            proc = subprocess.run(
                ["node", "harness.mjs", scenario],
                cwd=str(HERE),
                env=env,
                capture_output=True,
                text=True,
                timeout=180,
            )
            try:
                result = json.loads(proc.stdout)
            except json.JSONDecodeError:
                print(proc.stdout[-2000:])
                print(proc.stderr[-2000:])
                failures += 1
                continue
            output = result.get("output", "")
            ok = EXPECTED[scenario] in output
            print(f"  wallet asked to sign : {result.get('walletAsked')}")
            broadcast = result.get("broadcast")
            if broadcast:
                print(f"  on-chain tx          : {broadcast.get('onchainHash')}")
            head = output.strip().splitlines()
            print("  console result       : " + (head[1] if len(head) > 1 else head[0] if head else ""))
            print(f"  matches expectation  : {'YES' if ok else 'NO'}")
            if not ok:
                failures += 1

        print("-" * 78)
        if failures:
            print(f"{failures} scenario(s) did not match the expected outcome.")
            return 1
        print("All four scenarios matched their expected outcome.")
        print("Evidence written to: " + str(outdir))
        return 0
    finally:
        server.terminate()
        try:
            server.wait(timeout=10)
        except subprocess.TimeoutExpired:
            server.kill()


if __name__ == "__main__":
    raise SystemExit(main())
