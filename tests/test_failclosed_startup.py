"""Fail-closed startup, exercised through the real entry point.

The unit tests in ``test_securityconfig.py`` cover the decision logic. These run
``python -m tracesettle serve`` in a subprocess and assert the process actually
refuses to start (non-zero exit, no listener) for an insecure public binding,
and starts cleanly for the loopback development workflow.
"""

from __future__ import annotations

import os
import pathlib
import socket
import subprocess
import sys
import time

ROOT = pathlib.Path(__file__).resolve().parents[1]


def _free_port() -> int:
    with socket.socket() as probe:
        probe.bind(("127.0.0.1", 0))
        return probe.getsockname()[1]


def _clean_env(**overrides: str) -> dict[str, str]:
    env = {k: v for k, v in os.environ.items() if not k.startswith(("PORT", "TRACESETTLE_"))}
    env.update(overrides)
    return env


def _port_is_listening(port: int, timeout: float = 1.0) -> bool:
    deadline = time.time() + timeout
    while time.time() < deadline:
        try:
            with socket.create_connection(("127.0.0.1", port), timeout=0.5):
                return True
        except OSError:
            time.sleep(0.05)
    return False


def _run_serve(env: dict[str, str], port: int, wait: float = 3.0) -> tuple[int, str, bool, bool]:
    """Start the real server; return (exit_code, output, still_running, listening).

    If the process is still running after ``wait`` seconds it started
    successfully; the listening state is probed *before* it is terminated, and
    the reported exit code is -1 (terminated by this helper).
    """
    proc = subprocess.Popen(
        [sys.executable, "-m", "tracesettle", "serve", "--host", env["_HOST"], "--port", str(port)],
        cwd=ROOT,
        env={k: v for k, v in env.items() if not k.startswith("_")},
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
    )
    try:
        try:
            output = proc.communicate(timeout=wait)[0].decode("utf-8", "replace")
            return proc.returncode, output, False, False
        except subprocess.TimeoutExpired:
            listening = _port_is_listening(port)
            return -1, "", True, listening
    finally:
        if proc.poll() is None:
            proc.terminate()
            try:
                proc.wait(timeout=5)
            except subprocess.TimeoutExpired:
                proc.kill()
                proc.wait(timeout=5)


def test_public_binding_without_credentials_refuses_to_start():
    port = _free_port()
    env = _clean_env(_HOST="0.0.0.0")
    code, output, running, listening = _run_serve(env, port)
    assert not running, "server started on a public interface without credentials"
    assert code == 2, f"expected exit 2 (refused), got {code}"
    assert "refusing to start" in output
    assert "TRACESETTLE_API_KEY" in output
    assert not _port_is_listening(port)


def test_public_binding_with_only_api_key_still_refuses():
    port = _free_port()
    env = _clean_env(_HOST="0.0.0.0", TRACESETTLE_API_KEY="a-key")
    code, output, running, listening = _run_serve(env, port)
    assert not running
    assert code == 2
    assert "TRACESETTLE_GUARD_AUTH_KEY" in output


def test_public_binding_with_all_credentials_starts():
    port = _free_port()
    env = _clean_env(
        _HOST="0.0.0.0",
        TRACESETTLE_API_KEY="a-key",
        TRACESETTLE_GUARD_AUTH_KEY="00" * 32,
    )
    code, output, running, listening = _run_serve(env, port)
    try:
        assert running, f"server failed to start with credentials; output:\n{output}"
        assert listening
    finally:
        pass


def test_loopback_binding_starts_with_no_credentials():
    port = _free_port()
    env = _clean_env(_HOST="127.0.0.1")
    code, output, running, listening = _run_serve(env, port)
    assert running, f"loopback development server failed to start; output:\n{output}"


def test_require_service_auth_without_a_store_refuses_to_start():
    port = _free_port()
    env = _clean_env(_HOST="127.0.0.1", TRACESETTLE_REQUIRE_SERVICE_AUTH="1")
    code, output, running, listening = _run_serve(env, port)
    assert not running
    assert code == 2
    assert "TRACESETTLE_REQUIRE_SERVICE_AUTH" in output


def test_no_override_allows_a_public_start_without_credentials():
    """The legacy override variable must NOT permit an unauthenticated public start.

    Regression: ``TRACESETTLE_ALLOW_INSECURE_PUBLIC=1`` previously let the server
    bind 0.0.0.0 with no credentials and serve the guard endpoints — including
    minting real transaction authorizations — to any network caller. It is now
    inert; the process refuses to start.
    """
    port = _free_port()
    env = _clean_env(_HOST="0.0.0.0", TRACESETTLE_ALLOW_INSECURE_PUBLIC="1")
    code, output, running, listening = _run_serve(env, port)
    assert not running, f"override still allowed a public start; output:\n{output}"
    assert not listening
    assert code == 2
    assert "refusing to start" in output


def test_unreadable_credential_store_refuses_to_start():
    port = _free_port()
    env = _clean_env(
        _HOST="127.0.0.1",
        TRACESETTLE_SERVICE_CREDENTIALS="/nonexistent/path/credentials.json",
    )
    code, output, running, _ = _run_serve(env, port)
    assert not running, "server started despite an unreadable credential store"
    assert code == 2
    assert "refusing to start" in output


def test_malformed_credential_store_refuses_to_start(tmp_path):
    port = _free_port()
    store = tmp_path / "creds.json"
    store.write_text("{not valid json")
    env = _clean_env(_HOST="127.0.0.1", TRACESETTLE_SERVICE_CREDENTIALS=str(store))
    code, output, running, _ = _run_serve(env, port)
    assert not running, "server started with a malformed credential store"
    assert code == 2
    assert "refusing to start" in output
