"""Command-line entry point.

    python -m tracesettle investigate <identifier> [--json|--markdown]
    python -m tracesettle serve [--host 127.0.0.1] [--port 8000]

Read-only for settlements. The guard layer evaluates transaction requests before
execution and issues a transaction-bound authorization; it never signs, submits,
or moves anything.
"""

from __future__ import annotations

import argparse
import sys
from datetime import datetime, timezone

from . import __version__, config
from .httpclient import HttpClient
from .investigation import build_result, investigate
from .report import build_report


def _created_at() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def _cmd_investigate(args: argparse.Namespace) -> int:
    client = HttpClient(timeout=args.timeout, max_attempts=args.attempts)
    inv = investigate(args.identifier, client)
    report = build_report(inv, build_result(inv), _created_at())
    if args.json:
        print(report.to_json())
    else:
        print(report.to_markdown())
    return 0


def _cmd_serve(args: argparse.Namespace) -> int:
    from .ui import serve

    serve(host=args.host, port=args.port, timeout_seconds=args.timeout, max_attempts=args.attempts)
    return 0


def _load_registry(store_path: str | None):
    """Load a credential store, or start an empty one.

    The stored form contains only one-way hashes, so loading it never reveals a
    secret. A malformed store is a hard error: a security control must not be
    silently discarded.
    """
    import os

    from .serviceauth import ServiceRegistry

    if store_path and os.path.exists(store_path):
        with open(store_path, encoding="utf-8") as handle:
            return ServiceRegistry.load(handle.read())
    return ServiceRegistry()


def _store_lock(store_path: str | None):
    """An exclusive advisory lock over a credential store, for read-modify-write.

    Without it, two concurrent ``credentials`` commands could each read the same
    snapshot, mutate, and write back, so the later write would silently undo the
    earlier one — including restoring a credential the other command had just
    revoked. The lock serialises the whole read-modify-write so a revoke cannot
    be lost. It is a no-op when no store path is configured, and degrades to no
    locking on platforms without ``fcntl`` (the tool's supported platforms have
    it).
    """
    import contextlib
    import os

    if not store_path:
        return contextlib.nullcontext()

    try:
        import fcntl
    except ImportError:  # pragma: no cover - non-POSIX; documented limitation
        return contextlib.nullcontext()

    lock_path = os.path.abspath(store_path) + ".lock"

    @contextlib.contextmanager
    def _locked():
        directory = os.path.dirname(lock_path) or "."
        os.makedirs(directory, exist_ok=True)
        fd = os.open(lock_path, os.O_CREAT | os.O_RDWR, 0o600)
        try:
            fcntl.flock(fd, fcntl.LOCK_EX)
            yield
        finally:
            try:
                fcntl.flock(fd, fcntl.LOCK_UN)
            finally:
                os.close(fd)

    return _locked()


def _mutate_registry(store_path: str | None, mutate):
    """Read-modify-write the store under the store lock.

    The lock is taken *before* the read, so a mutation always observes the
    latest committed state and no concurrent mutation is lost. ``mutate``
    returns ``(result, changed)``; the store is written only when something
    changed, so a no-op revoke does not create or rewrite the file.
    """
    with _store_lock(store_path):
        registry = _load_registry(store_path)
        result, changed = mutate(registry)
        if store_path and changed:
            _write_registry(registry, store_path)
        return result


def _write_registry(registry, store_path: str) -> None:
    """Persist the store with owner-only permissions.

    The store holds hashes, not secrets, but it is still access-controlled:
    knowing which credentials exist is information an attacker should not have.
    """
    import json
    import os
    import tempfile

    directory = os.path.dirname(os.path.abspath(store_path)) or "."
    fd, tmp = tempfile.mkstemp(dir=directory, prefix=".creds-", suffix=".json")
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as handle:
            json.dump(registry.to_store(), handle, indent=2, sort_keys=True)
            handle.write("\n")
        os.chmod(tmp, 0o600)
        os.replace(tmp, store_path)
    except BaseException:
        try:
            os.unlink(tmp)
        except OSError:
            pass
        raise


def _cmd_credentials_mint(args: argparse.Namespace) -> int:
    import json

    def mutate(registry):
        credential, secret = registry.mint(args.service_id)
        return (credential, secret), True

    credential, secret = _mutate_registry(args.store, mutate)
    written = args.store if args.store else None
    result = {
        "service_id": credential.service_id,
        "credential_id": credential.credential_id,
        "secret": secret,
        "store_written": written,
        "notice": (
            "The secret is shown once and is not recoverable. Store it in the "
            "service's own secret manager and present it in the "
            "X-Service-Credential header. Only its hash is persisted."
        ),
    }
    print(json.dumps(result, indent=2))
    return 0


def _cmd_credentials_list(args: argparse.Namespace) -> int:
    import json

    registry = _load_registry(args.store)
    print(
        json.dumps(
            {
                "credentials": [c.to_dict() for c in registry.credentials()],
                "active_service_ids": list(registry.active_service_ids()),
            },
            indent=2,
        )
    )
    return 0


def _cmd_credentials_revoke(args: argparse.Namespace) -> int:
    import json

    def mutate(registry):
        revoked = registry.revoke(args.credential_id)
        return revoked, revoked

    revoked = _mutate_registry(args.store, mutate)
    print(json.dumps({"credential_id": args.credential_id, "revoked": revoked}, indent=2))
    return 0


def _cmd_judge(args: argparse.Namespace) -> int:
    """Run the independent evaluation scenarios and print the report."""
    import json

    from .judge import to_report

    report = to_report()
    summary = report["summary"]
    if args.json:
        print(json.dumps(report, indent=2))
    else:
        # A live check that could not run (no outbound network) is an honest
        # environmental limitation, not a defect, so it is marked "SKIP" rather
        # than "FAIL". Only a real contradiction is a failure. The `skipped`
        # flag is computed once in judge.py so the CLI and the web page agree.
        print("TRACESETTLE — independent evaluation scenarios")
        print("=" * 64)
        for s in report["scenarios"]:
            mark = "PASS" if s["passed"] else ("SKIP" if s["skipped"] else "FAIL")
            kind = "real" if s["real"] else "sim"
            print(f"[{mark}] {s['id']:32} {kind:4} decision={s['decision']:16} "
                  f"signer_calls={s['signer_calls']}")
            print(f"        expected: {s['expected']}")
            print(f"        observed: {s['observed']}")
        print("-" * 64)
        print(f"passed {summary['passed']}/{summary['total']} "
              f"(enforcement {summary['enforcement_passed']}/{summary['enforcement_total']}, "
              f"live {summary['live_passed']}/{summary['live_total']})")
        if summary["live_passed"] < summary["live_total"]:
            print("note: the live settlement check could not run here (no outbound network); "
                  "it is reported UNAVAILABLE, never assumed.")
        print(f"anything broadcast: {summary['broadcast_occurred']}")
        print()
        print(report["disclaimer"])
    # Exit non-zero only for a real defect: an enforcement scenario that did not
    # behave as specified, or a live check that found a contradiction. A live
    # check that is merely UNAVAILABLE (no network from this host) is an honest
    # environmental limitation, not a failure of the product.
    enforcement_ok = summary["enforcement_passed"] == summary["enforcement_total"]
    live_states = {
        s["decision"] for s in report["scenarios"] if s["real"]
    }
    live_contradiction = bool(live_states & {"DISPUTED", "FAILED", "CONTRADICTORY"})
    return 0 if enforcement_ok and not live_contradiction else 1


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="tracesettle",
        description="Read-only NEAR Intents settlement investigator. Never signs or moves funds.",
    )
    parser.add_argument("--version", action="version", version=f"TRACESETTLE {__version__}")
    sub = parser.add_subparsers(dest="command", required=True)

    inv = sub.add_parser("investigate", help="run a read-only investigation")
    inv.add_argument("identifier", help="deposit address, intent hash, or NEAR transaction hash")
    inv.add_argument("--json", action="store_true", help="emit JSON instead of Markdown")
    inv.add_argument("--timeout", type=float, default=15.0, help="per-request timeout in seconds")
    inv.add_argument("--attempts", type=int, default=3, help="max attempts per request")
    inv.set_defaults(func=_cmd_investigate)

    srv = sub.add_parser("serve", help="run the local read-only web interface")
    srv.add_argument("--host", default=config.SERVE_HOST)
    srv.add_argument("--port", type=int, default=config.SERVE_PORT)
    srv.add_argument("--timeout", type=float, default=15.0)
    srv.add_argument("--attempts", type=int, default=3)
    srv.set_defaults(func=_cmd_serve)

    judge = sub.add_parser(
        "judge", help="run the independent evaluation scenarios (offline, no key needed)"
    )
    judge.add_argument("--json", action="store_true", help="emit the full report as JSON")
    judge.set_defaults(func=_cmd_judge)

    creds = sub.add_parser(
        "credentials",
        help="manage per-service credentials for the guard (hashes only, never secrets)",
    )
    creds_sub = creds.add_subparsers(dest="credentials_command", required=True)

    def _add_store(parser: argparse.ArgumentParser) -> None:
        parser.add_argument(
            "--store",
            default=config.SERVICE_CREDENTIALS_PATH,
            help="path to the credential store JSON (default: TRACESETTLE_SERVICE_CREDENTIALS)",
        )

    mint = creds_sub.add_parser("mint", help="issue a credential for a service (prints the secret once)")
    mint.add_argument("service_id", help="the service identity this credential authenticates")
    _add_store(mint)
    mint.set_defaults(func=_cmd_credentials_mint)

    listing = creds_sub.add_parser("list", help="list credentials (never prints a secret)")
    _add_store(listing)
    listing.set_defaults(func=_cmd_credentials_list)

    revoke = creds_sub.add_parser("revoke", help="revoke a credential by id")
    revoke.add_argument("credential_id", help="the credential id to revoke")
    _add_store(revoke)
    revoke.set_defaults(func=_cmd_credentials_revoke)

    from .tee_verify_cli import add_reviewer_subcommands

    add_reviewer_subcommands(sub)

    return parser


def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    return args.func(args)


if __name__ == "__main__":
    sys.exit(main())
