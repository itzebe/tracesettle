#!/usr/bin/env python3
"""Validate deploy/production/.env.production.example against the real config.

Checks:
  1. Every KEY= line names a variable tracesettle/config.py actually reads.
  2. No value looks like a real secret (placeholders only).
  3. Mandatory production variables are present in the template.

Read-only; exits non-zero on any problem.
"""
from __future__ import annotations

import re
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
CONFIG = ROOT / "tracesettle" / "config.py"
TEMPLATE = ROOT / "deploy" / "production" / ".env.production.example"

MANDATORY = [
    "TRACESETTLE_API_KEY",
    "TRACESETTLE_GUARD_AUTH_KEY",
    "TRACESETTLE_GUARD_STATE_BACKEND",
    "TRACESETTLE_GUARD_STATE_PG_DSN",
    "TRACESETTLE_GUARD_REQUIRE_POSTGRES",
    "TRACESETTLE_NEAR_RPC_URL",
    "TRACESETTLE_NEAR_RPC_FALLBACK_URL",
]

# A real secret would be a long hex/base64/url-with-password token. Placeholders
# are <ANGLE_BRACKETS>, plain words, or empty.
SECRET_SHAPE = re.compile(
    r"^(?:[0-9a-fA-F]{32,}|[A-Za-z0-9+/]{40,}={0,2}|postgres(?:ql)?://[^<]*:[^<]*@)"
)


def known_vars() -> set[str]:
    text = CONFIG.read_text(encoding="utf-8")
    # Match any quoted TRACESETTLE_* literal and the bare PORT name, so multi-line
    # os.environ.get(...) calls are covered.
    return set(re.findall(r'"(TRACESETTLE_[A-Z_]+)"', text)) | {"PORT"}


def parse_template(text: str) -> list[tuple[str, str, int]]:
    out: list[tuple[str, str, int]] = []
    for i, line in enumerate(text.splitlines(), 1):
        stripped = line.strip()
        if not stripped or stripped.startswith("#") or "=" not in stripped:
            continue
        key, _, value = stripped.partition("=")
        out.append((key.strip(), value.strip(), i))
    return out


def main() -> int:
    known = known_vars()
    entries = parse_template(TEMPLATE.read_text(encoding="utf-8"))
    problems: list[str] = []

    seen = {k for k, _, _ in entries}
    for key, value, line in entries:
        if key not in known:
            problems.append(f"line {line}: unknown variable {key!r} (not read by config.py)")
        if SECRET_SHAPE.match(value):
            problems.append(f"line {line}: {key} looks like a REAL secret, not a placeholder")

    for mandatory in MANDATORY:
        if mandatory not in seen:
            problems.append(f"missing mandatory production variable {mandatory!r}")

    print(f"template variables: {len(entries)}  known in config: {len(known)}")
    if problems:
        print("FAIL:")
        for p in problems:
            print("  -", p)
        return 1
    print("OK: every variable exists in config.py and every value is a placeholder")
    return 0


if __name__ == "__main__":
    sys.exit(main())
