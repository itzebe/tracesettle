"""CLI and environment-driven serve defaults.

The container image runs ``python -m tracesettle serve`` with no flags, so the
host and port must be settable through the environment (``TRACESETTLE_HOST``,
``PORT``/``TRACESETTLE_PORT``). These tests exercise the real parser and config.

The environment cases run in a fresh interpreter so that reloading the config
module cannot leak state into other tests in the same process.
"""

from __future__ import annotations

import os
import pathlib
import subprocess
import sys

from tracesettle import config
from tracesettle.__main__ import build_parser

ROOT = pathlib.Path(__file__).resolve().parents[1]


def _config_value_in_subprocess(env: dict[str, str], expression: str) -> str:
    """Import the real config module in a clean interpreter and print a value."""
    child_env = {
        k: v for k, v in os.environ.items() if not k.startswith(("PORT", "TRACESETTLE_"))
    }
    child_env.update(env)
    proc = subprocess.run(
        [sys.executable, "-c", f"from tracesettle import config; print({expression})"],
        cwd=ROOT,
        env=child_env,
        capture_output=True,
        text=True,
        check=True,
    )
    return proc.stdout.strip()


def test_serve_defaults_match_config():
    args = build_parser().parse_args(["serve"])
    assert args.host == config.SERVE_HOST
    assert args.port == config.SERVE_PORT


def test_serve_default_host_is_loopback():
    """Binding a public interface must stay an explicit decision."""
    assert config.SERVE_HOST == "127.0.0.1"


def test_explicit_flags_override_env_defaults():
    args = build_parser().parse_args(["serve", "--host", "0.0.0.0", "--port", "9000"])
    assert args.host == "0.0.0.0"
    assert args.port == 9000


def test_port_env_is_honoured():
    assert _config_value_in_subprocess({"PORT": "12345"}, "config.SERVE_PORT") == "12345"


def test_tracesettle_port_env_is_honoured():
    assert _config_value_in_subprocess({"TRACESETTLE_PORT": "23456"}, "config.SERVE_PORT") == "23456"


def test_tracesettle_port_takes_precedence_over_port():
    value = _config_value_in_subprocess(
        {"PORT": "11111", "TRACESETTLE_PORT": "22222"}, "config.SERVE_PORT"
    )
    assert value == "22222"


def test_host_env_is_honoured():
    assert (
        _config_value_in_subprocess({"TRACESETTLE_HOST": "0.0.0.0"}, "config.SERVE_HOST")
        == "0.0.0.0"
    )


def test_near_fallback_env_is_honoured():
    value = _config_value_in_subprocess(
        {"TRACESETTLE_NEAR_RPC_FALLBACK_URL": "https://a.example,https://b.example"},
        "config.NEAR_RPC.fallback_urls",
    )
    assert value == "('https://a.example', 'https://b.example')"
