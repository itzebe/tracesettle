"""Shared test infrastructure.

Tests exercise the **real** adapter and engine code paths. The only thing
substituted is the network transport, via :class:`FakeOpener`, which mimics
``urllib.request.urlopen``. That keeps the tests deterministic and offline while
still testing our parsing, classification, and reconciliation logic rather than
mocks of it.

Fixture provenance is preserved:

* real captured responses are loaded from ``evidence/raw/`` (never copied);
* synthetic responses live in ``tests/fixtures/synthetic/`` with a manifest.
"""

from __future__ import annotations

import io
import json
import pathlib
import urllib.error
from typing import Any, Callable

import pytest

from tracesettle.httpclient import HttpClient
from tracesettle.model import EventType, EvidenceItem, Provenance, Stage, Verification

ROOT = pathlib.Path(__file__).resolve().parents[1]
RAW_DIR = ROOT / "evidence" / "raw"
SYNTHETIC_DIR = pathlib.Path(__file__).resolve().parent / "fixtures" / "synthetic"

# Real identifiers captured in Phase 1.
REAL_DEPOSIT_ADDRESS = "0xB741c00f6D63b6dEd0cCADA1a82bCBADc38A572B"
REAL_INTENT_HASH = "7ypUiXpjHmDoFFzo8nRWvY4BMfcKR5YkF5Cez28N94dG"
REAL_NEAR_TX = "5E3GdbhwUYj9RFXhkk3rMyPwom4xvMYjtCFj7i2uypFb"
REAL_NEAR_TX_BRIDGE = "FbrSoTHbQdwD6HxabhaozvQQVBA4kF2Qn2c3W2otp284"
REAL_ORIGIN_TX = "0xfca11aa01bce5fc20a6cbeb4ca30e8af994cda47de9bd5fa53a9ca4295ba01d2"
REAL_DESTINATION_TX = "0x91cd1ede3f49313787d6c21c633aee5a1417c46a6dfd33904dc407498c9af3f3"
REAL_RECIPIENT = "0x4e6d3A556e485188E9C9a528bc72c88BD92BD735"


def load_raw(name: str) -> Any:
    """Load a real captured response from evidence/raw."""
    return json.loads((RAW_DIR / name).read_text())


def load_synthetic(name: str) -> Any:
    """Load a clearly-labelled synthetic response."""
    return json.loads((SYNTHETIC_DIR / name).read_text())


class FakeResponse:
    def __init__(self, payload: bytes, status: int = 200) -> None:
        self._payload = payload
        self.status = status
        self.code = status

    def read(self) -> bytes:
        return self._payload

    def __enter__(self) -> "FakeResponse":
        return self

    def __exit__(self, *exc: object) -> bool:
        return False


class FakeOpener:
    """Maps (method, url-substring) to canned responses or raised errors.

    Routes are matched in registration order. A route registered with
    ``once=True`` is consumed after its first match, which lets tests express
    "fail once, then succeed" retry sequences.
    """

    def __init__(self) -> None:
        self._routes: list[tuple[str, str, Callable[[], Any], bool]] = []
        self.calls: list[str] = []

    def json(
        self, method: str, url_contains: str, payload: Any, status: int = 200, once: bool = False
    ) -> "FakeOpener":
        body = json.dumps(payload).encode("utf-8")
        return self.raw(method, url_contains, body, status, once=once)

    def raw(
        self,
        method: str,
        url_contains: str,
        body: bytes,
        status: int = 200,
        once: bool = False,
    ) -> "FakeOpener":
        self._routes.append((method.upper(), url_contains, lambda: FakeResponse(body, status), once))
        return self

    def http_error(
        self, method: str, url_contains: str, code: int, body: bytes = b"", once: bool = False
    ) -> "FakeOpener":
        def raise_it() -> Any:
            raise urllib.error.HTTPError(
                url_contains, code, f"HTTP {code}", {}, io.BytesIO(body)
            )

        self._routes.append((method.upper(), url_contains, raise_it, once))
        return self

    def network_error(
        self, method: str, url_contains: str, reason: str = "connection reset", once: bool = False
    ) -> "FakeOpener":
        def raise_it() -> Any:
            raise urllib.error.URLError(reason)

        self._routes.append((method.upper(), url_contains, raise_it, once))
        return self

    def timeout(self, method: str, url_contains: str, once: bool = False) -> "FakeOpener":
        def raise_it() -> Any:
            raise TimeoutError("timed out")

        self._routes.append((method.upper(), url_contains, raise_it, once))
        return self

    def __call__(self, request: Any, timeout: float | None = None) -> FakeResponse:
        url = request.full_url if hasattr(request, "full_url") else str(request)
        method = getattr(request, "method", "GET") or "GET"
        self.calls.append(f"{method} {url}")
        for index, (route_method, needle, responder, once) in enumerate(self._routes):
            if route_method == method.upper() and needle in url:
                if once:
                    self._routes.pop(index)
                return responder()
        raise AssertionError(f"no fake route for {method} {url}")


def client_for(opener: FakeOpener, attempts: int = 1) -> HttpClient:
    return HttpClient(
        opener=opener, max_attempts=attempts, timeout=1.0, backoff_base=0.0, sleeper=lambda _: None
    )


# ---------------------------------------------------------------------------
# Evidence helpers (for engine-only unit tests)
# ---------------------------------------------------------------------------


def ev(
    id: str,
    stage: Stage,
    event_type: EventType,
    verification: Verification,
    *,
    source: str = "test",
    provenance: Provenance = Provenance.REAL,
    reported_status: str | None = None,
    tx_hash: str | None = None,
    chain: str | None = None,
    details: dict[str, Any] | None = None,
    limitations: tuple[str, ...] = (),
) -> EvidenceItem:
    return EvidenceItem(
        id=id,
        stage=stage,
        event_type=event_type,
        source=source,
        verification=verification,
        provenance=provenance,
        reported_status=reported_status,
        tx_hash=tx_hash,
        chain=chain,
        details=details or {},
        limitations=limitations,
    )


@pytest.fixture
def opener() -> FakeOpener:
    return FakeOpener()
