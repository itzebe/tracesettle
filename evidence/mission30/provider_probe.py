"""Mission 30 — probe the NEAR Intents Agent API, read-only and free.

Run: python3 evidence/mission30/provider_probe.py > evidence/mission30/provider_probe.json

Two read-only calls, no credential required to demonstrate the boundary:

* ``GET /v1/network``  — documented as unauthenticated; returns the network,
  contract id and live component status.
* ``GET /v1/whoami``   — documented as requiring ``X-API-Key``; with no key the
  provider answers ``401 invalid_api_key``, which is the exact auth boundary the
  adapter models.

No API key is read, sent, logged, or written. Nothing here is invented: the
endpoints come from the provider's live OpenAPI document
(``https://api.agentsonintents.com/openapi.json``).
"""

from __future__ import annotations

import json
import urllib.request

BASE = "https://api.agentsonintents.com"


def _get(path: str, headers: dict[str, str] | None = None) -> dict:
    req = urllib.request.Request(BASE + path, headers=headers or {})
    try:
        with urllib.request.urlopen(req, timeout=15) as resp:
            body = resp.read().decode("utf-8", "replace")
            return {"path": path, "http_status": resp.status, "body": _maybe_json(body)}
    except urllib.error.HTTPError as exc:
        body = exc.read().decode("utf-8", "replace")
        return {"path": path, "http_status": exc.code, "body": _maybe_json(body)}
    except Exception as exc:  # noqa: BLE001
        return {"path": path, "http_status": None, "error": f"{type(exc).__name__}: {exc}"}


def _maybe_json(text: str):
    try:
        return json.loads(text)
    except ValueError:
        return text


def main() -> None:
    openapi = _get("/openapi.json")
    doc = openapi.get("body") if isinstance(openapi.get("body"), dict) else {}
    paths = sorted(p for p in (doc.get("paths") or {}) if p.startswith("/v1/"))
    security_schemes = sorted((doc.get("components", {}).get("securitySchemes") or {}).keys())
    evidence = {
        "base_url": BASE,
        "openapi": {
            "http_status": openapi.get("http_status"),
            "title": (doc.get("info") or {}).get("title"),
            "version": (doc.get("info") or {}).get("version"),
            "security_schemes": security_schemes,
            "v1_paths": paths,
        },
        "network": _get("/v1/network"),
        "whoami_without_key": _get("/v1/whoami"),
        "note": (
            "No API key was supplied. /v1/whoami answering 401 with "
            "'invalid_api_key' is the documented auth boundary, not an outage. "
            "A successful read requires a live key in the X-API-Key header."
        ),
    }
    print(json.dumps(evidence, indent=2, sort_keys=True))


if __name__ == "__main__":
    main()
