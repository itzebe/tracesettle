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


def _wait_for_health(port: int, timeout: float = 10.0) -> bool:
    import time
    import urllib.request

    deadline = time.time() + timeout
    while time.time() < deadline:
        try:
            with urllib.request.urlopen(
                f"http://127.0.0.1:{port}/api/health", timeout=1
            ) as resp:
                if resp.status == 200:
                    return True
        except Exception:
            time.sleep(0.1)
    return False


def test_serve_exits_cleanly_on_sigterm():
    """SIGTERM must stop the server with exit code 0 (PID-1 container semantics).

    A process that is PID 1 inside a container gets no default action for SIGTERM,
    so ``docker stop`` would hang until the runtime SIGKILLs it unless the server
    installs its own handler. This runs the real entry point in a subprocess.
    """
    import signal
    import socket
    import time

    with socket.socket() as probe:
        probe.bind(("127.0.0.1", 0))
        port = probe.getsockname()[1]

    env = dict(os.environ)
    env["TRACESETTLE_HOST"] = "127.0.0.1"
    env["TRACESETTLE_PORT"] = str(port)
    proc = subprocess.Popen(
        [sys.executable, "-m", "tracesettle", "serve"],
        cwd=ROOT,
        env=env,
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
    )
    try:
        assert _wait_for_health(port), "server never became healthy"
        start = time.time()
        proc.send_signal(signal.SIGTERM)
        code = proc.wait(timeout=10)
        elapsed = time.time() - start
        assert code == 0, f"expected clean exit 0, got {code}"
        assert elapsed < 8, f"SIGTERM took too long ({elapsed:.1f}s); handler likely missing"
    finally:
        if proc.poll() is None:
            proc.kill()
            proc.wait(timeout=5)
