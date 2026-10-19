"""Command-line entry point.

    python -m tracesettle investigate <identifier> [--json|--markdown]
    python -m tracesettle serve [--host 127.0.0.1] [--port 8000]

Read-only. No command signs, submits, or moves anything.
"""

from __future__ import annotations

import argparse
import sys
from datetime import datetime, timezone

from . import __version__
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
    srv.add_argument("--host", default="127.0.0.1")
    srv.add_argument("--port", type=int, default=8000)
    srv.add_argument("--timeout", type=float, default=15.0)
    srv.add_argument("--attempts", type=int, default=3)
    srv.set_defaults(func=_cmd_serve)

    return parser


def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    return args.func(args)


if __name__ == "__main__":
    sys.exit(main())
