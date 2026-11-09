#!/usr/bin/env python3
"""Mission 33T — collect live, redacted provider-authentication evidence.

Read-only. It never prints, logs, hashes, encodes or persists the value of
``NEAR_INTENTS_AGENT_API_KEY``; only its presence, length and non-secret JWT
claims are recorded. The provider calls are free and read-only (the key is sent
in the ``X-API-Key`` header exactly as the provider's OpenAPI documents it).

Outputs JSON files next to this script. Run from the repository root:

    python3 evidence/mission33t/collect_evidence.py
"""

from __future__ import annotations

import base64
import json
import os
import subprocess
import sys
from datetime import datetime, timezone
from pathlib import Path

BASE_URL = "https://api.agentsonintents.com"
EXPLORER_URL = "https://explorer.near-intents.org/api/v0/transactions"
KEY_NAME = "NEAR_INTENTS_AGENT_API_KEY"
HERE = Path(__file__).resolve().parent
ROOT = HERE.parent.parent


def _now() -> str:
    return datetime.now(timezone.utc).isoformat()


def _jwt_claims_no_values(token: str) -> dict:
    """Non-secret structural facts about a JWT, never the value itself."""
    parts = token.split(".")
    out: dict = {"segments": len(parts)}
    if len(parts) != 3:
        out["is_jwt"] = False
        return out
    out["is_jwt"] = True

    def _b64d(seg: str) -> bytes:
        return base64.urlsafe_b64decode(seg + "=" * (-len(seg) % 4))

    try:
        header = json.loads(_b64d(parts[0]))
        out["alg"] = header.get("alg")
        out["typ"] = header.get("typ")
    except Exception:  # noqa: BLE001 - a malformed header is a fact, not a crash
        out["alg"] = None
    try:
        payload = json.loads(_b64d(parts[1]))
        out["claim_names"] = sorted(payload.keys())
        out["key_type"] = payload.get("key_type")
        out["version"] = payload.get("v")
        out["has_partner_id"] = "partner_id" in payload
        out["partner_id_length"] = len(str(payload.get("partner_id", "")))
        if "iat" in payload and "exp" in payload:
            iat, exp = int(payload["iat"]), int(payload["exp"])
            out["issued_at"] = datetime.fromtimestamp(iat, timezone.utc).isoformat()
            out["expires_at"] = datetime.fromtimestamp(exp, timezone.utc).isoformat()
            out["lifetime_days"] = round((exp - iat) / 86400, 2)
            out["expired"] = int(datetime.now(timezone.utc).timestamp()) > exp
    except Exception:  # noqa: BLE001
        out["claim_names"] = []
    return out


def _run_cli(*args: str) -> dict:
    proc = subprocess.run(
        [sys.executable, "-m", "tracesettle", *args],
        cwd=str(ROOT),
        capture_output=True,
        text=True,
    )
    stdout = proc.stdout.strip()
    try:
        parsed = json.loads(stdout)
    except Exception:  # noqa: BLE001 - keep the raw text if it is not JSON
        parsed = {"raw_stdout": stdout}
    return {
        "command": " ".join(["python3", "-m", "tracesettle", *args]),
        "exit": proc.returncode,
        "output": parsed,
    }


def _http_get(url: str, headers: dict | None = None) -> dict:
    import urllib.error
    import urllib.request

    req = urllib.request.Request(url, headers=headers or {})
    try:
        with urllib.request.urlopen(req, timeout=20) as resp:  # noqa: S310 - fixed provider URL
            body = resp.read().decode("utf-8", "replace")
            return {"http_status": resp.status, "body": body}
    except urllib.error.HTTPError as exc:
        return {"http_status": exc.code, "body": exc.read().decode("utf-8", "replace")}
    except Exception as exc:  # noqa: BLE001
        return {"http_status": None, "error": type(exc).__name__}


def main() -> int:
    if str(ROOT) not in sys.path:
        sys.path.insert(0, str(ROOT))
    key = os.environ.get(KEY_NAME)
    present = bool(key)
    nonempty = bool(key and key.strip())

    # 1. Credential presence (never the value).
    presence = {
        "credential": {
            "name": KEY_NAME,
            "present": present,
            "nonempty": nonempty,
            "value": "<never recorded>",
        },
        "length": len(key) if key else 0,
        "whitespace_free": (key == key.strip() and not any(c.isspace() for c in key)) if key else None,
        "provider": {"base_url": BASE_URL},
        "generated_at": _now(),
    }
    if key:
        presence["jwt_claims_no_values"] = _jwt_claims_no_values(key)
    (HERE / "credential_presence.json").write_text(json.dumps(presence, indent=2, sort_keys=True) + "\n")

    # 1b. Owner-side confirmation that the runtime holds a *replaced* value:
    # compare the non-secret claims against the Mission 33S capture. Only
    # structural, non-secret facts are compared; never the value.
    prior_path = ROOT / "evidence" / "mission33s" / "credential_presence.json"
    change: dict = {"generated_at": _now(), "compared_with": str(prior_path.relative_to(ROOT))}
    if key and prior_path.exists():
        prior = json.loads(prior_path.read_text())
        cur = presence.get("jwt_claims_no_values", {})
        old = prior.get("jwt_claims_no_values", {})
        change["previous_issued_at"] = old.get("issued_at")
        change["current_issued_at"] = cur.get("issued_at")
        change["previous_expires_at"] = old.get("expires_at")
        change["current_expires_at"] = cur.get("expires_at")
        change["issued_at_changed"] = old.get("issued_at") != cur.get("issued_at")
        change["value_replaced"] = bool(
            old.get("issued_at") != cur.get("issued_at")
            or prior.get("length") != presence.get("length")
        )
        change["previous_key_type"] = old.get("key_type")
        change["current_key_type"] = cur.get("key_type")
        change["key_type_unchanged"] = old.get("key_type") == cur.get("key_type")
    (HERE / "runtime_credential_change.json").write_text(json.dumps(change, indent=2, sort_keys=True) + "\n")

    # 2. Provider reachability (unauthenticated) — is the provider serving?
    openapi = _http_get(f"{BASE_URL}/openapi.json")
    network = _http_get(f"{BASE_URL}/v1/network")
    tokens = _http_get(f"{BASE_URL}/v1/tokens")
    noauth = _http_get(f"{BASE_URL}/v1/agents")
    reachability = {
        "base_url": BASE_URL,
        "openapi_http_status": openapi.get("http_status"),
        "network_http_status": network.get("http_status"),
        "tokens_http_status": tokens.get("http_status"),
        "unauthenticated_agents_http_status": noauth.get("http_status"),
        "unauthenticated_agents_body": noauth.get("body", "")[:400],
        "generated_at": _now(),
    }
    try:
        spec = json.loads(openapi["body"])
        reachability["openapi_title"] = spec.get("info", {}).get("title")
        reachability["openapi_version"] = spec.get("info", {}).get("version")
        reachability["v1_path_count"] = len([p for p in spec.get("paths", {}) if p.startswith("/v1")])
        schemes = spec.get("components", {}).get("securitySchemes", {})
        reachability["api_key_scheme"] = schemes.get("ApiKey", {}).get("name")
    except Exception:  # noqa: BLE001
        pass
    (HERE / "provider_reachability.json").write_text(json.dumps(reachability, indent=2, sort_keys=True) + "\n")

    if not present:
        print(f"{KEY_NAME} is ABSENT — runtime injection problem; stopping.")
        return 2

    # 3. Live CLI outcomes (the exact commands the mission names).
    cli = [
        _run_cli("provider", "auth", "--base-url", BASE_URL, "--json"),
        _run_cli("provider", "agents", "--base-url", BASE_URL, "--json"),
        # No agent id was discoverable, so the documented placeholder is used. It
        # is never treated as a real agent; the read must fail closed.
        _run_cli(
            "provider", "policy",
            "0000000000000000000000000000000000000000000000000000000000000000",
            "--base-url", BASE_URL, "--json",
        ),
    ]
    lines = ["# Mission 33T — live CLI outcomes (read-only, key present)", "", f"Base URL: {BASE_URL}", ""]
    for entry in cli:
        lines.append(f"## {entry['command']}")
        lines.append("```json")
        lines.append(json.dumps(entry["output"], indent=2, sort_keys=True))
        lines.append("```")
        lines.append(f"exit={entry['exit']}")
        lines.append("")
    (HERE / "cli_outcomes.md").write_text("\n".join(lines))
    (HERE / "cli_outcomes.json").write_text(json.dumps(cli, indent=2, sort_keys=True) + "\n")

    # 4. Key scope: where does the provider accept this key? The Agent API must
    #    accept it as X-API-Key; the Explorer API is a different surface/header.
    agent_api = _http_get(f"{BASE_URL}/v1/whoami", headers={"X-API-Key": key})
    explorer = _http_get(EXPLORER_URL, headers={"Authorization": f"Bearer {key}"})
    scope = {
        "generated_at": _now(),
        "jwt_key_type": presence.get("jwt_claims_no_values", {}).get("key_type"),
        "agent_api": {
            "endpoint": f"{BASE_URL}/v1/whoami",
            "auth_header": "X-API-Key",
            "http_status": agent_api.get("http_status"),
            "body": agent_api.get("body", "")[:400],
            "accepted": agent_api.get("http_status") == 200,
        },
        "explorer_api": {
            "endpoint": EXPLORER_URL,
            "auth_header": "Authorization: Bearer",
            "http_status": explorer.get("http_status"),
            "accepted": explorer.get("http_status") == 200,
        },
    }
    (HERE / "key_scope.json").write_text(json.dumps(scope, indent=2, sort_keys=True) + "\n")

    # 5. The product's own adapter read (what the enforcement layer consumes).
    from tracesettle.httpclient import HttpClient
    from tracesettle.near.policy import PolicyAdapter

    adapter = PolicyAdapter(
        base_url=BASE_URL,
        api_key=key,
        http_client=HttpClient(timeout=20, max_attempts=2),
    )
    auth = adapter.authenticate()
    agents = adapter.list_agents()
    adapter_read = {
        "generated_at": _now(),
        "authenticate": auth.to_dict(),
        "list_agents": agents.to_dict(),
    }
    (HERE / "live_adapter_read.json").write_text(json.dumps(adapter_read, indent=2, sort_keys=True) + "\n")

    print(
        "wrote credential_presence.json, provider_reachability.json, "
        "cli_outcomes.md/json, key_scope.json, live_adapter_read.json"
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
