#!/usr/bin/env python3
"""Mission 33T — prove the provider-policy layer stays fail-closed.

Read-only. The *real* guard, the *real* NEAR execution boundary and the *real*
``combine_provider_policy`` run for every scenario; the same transaction is
prepared each time and only the provider-policy read changes. The only
substitutions are network boundaries: the NEAR RPC (a ``FakeNearRpc``) and, for
the non-live scenarios, the provider transport (an adapter returning a controlled
:class:`PolicyRead`). The ``UNAUTHENTICATED`` scenario uses the *live* Agent API
with the key from the environment, so the credential that this mission is about
drives one row of the matrix for real.

The property under test: a missing, disabled, stale, malformed, unauthorized or
unavailable policy must never produce an authorization. An explicit provider
denial is ``BLOCK``; a failure to *establish* the policy is ``HOLD``; both mean
``authorized: False``.

    python3 evidence/mission33t/failure_modes.py
"""

from __future__ import annotations

import json
import os
import sys
from pathlib import Path

HERE = Path(__file__).resolve().parent
ROOT = HERE.parent.parent
sys.path.insert(0, str(ROOT))
sys.path.insert(0, str(ROOT / "tests"))

BASE_URL = "https://api.agentsonintents.com"
AGENT = "treasury-agent"


def _policy_body(**overrides):
    body = {
        "agent_id": AGENT,
        "revision": 5,
        "status": "APPLIED",
        "provider_policy_synced": True,
        "frozen": False,
        "native": {"near": {"transfer": True, "call": False, "sign_message": False}},
    }
    body.update(overrides)
    return body


class _FakeResult:
    def __init__(self, *, ok: bool, http_status: int | None, data=None, status: str = "SourceStatus.OK"):
        self.ok = ok
        self.http_status = http_status
        self.data = data
        self.status = status


class _FakeHttp:
    """A provider transport stand-in returning a controlled result or raising."""

    def __init__(self, *, result=None, exc: Exception | None = None):
        self._result = result
        self._exc = exc

    def get_json(self, url, params=None, headers=None):  # noqa: ANN001
        if self._exc is not None:
            raise self._exc
        return self._result


class _Availability:
    """A minimal availability value carrier (the gate reads ``.value``)."""

    def __init__(self, value: str):
        self.value = value


class _StaleRead:
    """A read the adapter marks ``STALE`` in the gate's own vocabulary."""

    availability = _Availability("STALE")
    ok = False
    policy = None
    local_fixture = False
    endpoint = "https://provider.invalid/v1/agents/treasury-agent/policy"
    detail = "the policy revision is older than the configured maximum age"


class _StandInAdapter:
    """Returns one fixed, already-constructed ``PolicyRead`` (a transport stand-in)."""

    def __init__(self, read):
        self._read = read
        self.base_url = None  # reported as "fixture" provenance, never "live"

    def read_policy(self, agent_id):  # noqa: ANN001
        return self._read


def _real_adapter(*, result=None, exc=None, base_url="https://provider.invalid", expected_agent_id=AGENT):
    from tracesettle.near.policy import PolicyAdapter

    return PolicyAdapter(
        base_url=base_url,
        api_key="k",
        http_client=_FakeHttp(result=result, exc=exc),
        expected_host="provider.invalid",
        expected_agent_id=expected_agent_id,
    )


def _live_adapter():
    from tracesettle.httpclient import HttpClient
    from tracesettle.near.policy import PolicyAdapter

    return PolicyAdapter(
        base_url=BASE_URL,
        api_key=os.environ.get("NEAR_INTENTS_AGENT_API_KEY"),
        http_client=HttpClient(timeout=20, max_attempts=2),
    )


def _run(adapter, *, require=True, install_gate=True):
    """Prepare the same transaction with the given provider-policy adapter."""
    from near_helpers import RECIPIENT, make_boundary, public_key_for_test
    from tracesettle.near.execution import ExecutionError
    from tracesettle.near.provider_policy_gate import ProviderPolicyGate

    pk = public_key_for_test()
    tx_kwargs = dict(
        service_id=AGENT,
        account_id="agent.testnet",
        public_key=pk,
        receiver_id=RECIPIENT,
        asset_identifier="near:native",
        amount_human="1",
    )

    boundary, _ = make_boundary()
    if install_gate:
        boundary._policy_adapter = adapter
        boundary._provider_policy_agent_id = AGENT
        boundary._require_provider_policy = require
        boundary._policy_gate = ProviderPolicyGate(
            adapter, agent_id=AGENT, require=require, native_chain="near"
        )
    else:
        # Required layer, but no adapter/agent id constructed: must refuse outright.
        boundary._policy_adapter = None
        boundary._provider_policy_agent_id = ""
        boundary._require_provider_policy = True
        boundary._policy_gate = None

    try:
        prepared = boundary.prepare(**tx_kwargs)
    except ExecutionError as exc:
        return {"outcome": "EXECUTION_ERROR", "detail": str(exc), "decision": None, "authorized": False}

    pp = prepared.provider_policy
    return {
        "outcome": pp.outcome.value if pp is not None else "NO_GATE",
        "provider_decision": pp.decision.value if pp is not None else None,
        "decision": prepared.decision.decision.value,
        "authorized": bool(prepared.authorized),
        "authorization_id": prepared.authorization_id,
        "detail": pp.detail if pp is not None else None,
    }


def main() -> int:
    in_force = _policy_body()
    not_in_force = _policy_body(status="REQUESTED", provider_policy_synced=False)
    frozen = _policy_body(frozen=True)
    native_off = _policy_body(native={"near": {"transfer": False, "call": False, "sign_message": False}})
    other_agent = _policy_body(agent_id="some-other-agent")

    scenarios = []

    # Control: an in-force policy must still authorize (the layer is not a blanket refusal).
    scenarios.append((
        "IN_FORCE",
        "the provider policy is applied, synced and enables native.near.transfer",
        _real_adapter(result=_FakeResult(ok=True, http_status=200, data=in_force)),
        True,
    ))
    scenarios.append((
        "NOT_IN_FORCE",
        "a policy update that is not APPLIED / not provider-synced is never active",
        _real_adapter(result=_FakeResult(ok=True, http_status=200, data=not_in_force)),
        True,
    ))
    scenarios.append((
        "FROZEN",
        "the provider froze the agent's wallet (explicit denial)",
        _real_adapter(result=_FakeResult(ok=True, http_status=200, data=frozen)),
        True,
    ))
    scenarios.append((
        "NATIVE_TRANSFER_DISABLED",
        "the policy does not enable native.near.transfer (explicit denial)",
        _real_adapter(result=_FakeResult(ok=True, http_status=200, data=native_off)),
        True,
    ))
    scenarios.append((
        "AGENT_MISMATCH",
        "the provider returned a policy for a different agent (the gate's own AGENT_MISMATCH)",
        _real_adapter(
            result=_FakeResult(ok=True, http_status=200, data=other_agent),
            expected_agent_id="",
        ),
        True,
    ))
    scenarios.append((
        "UNAUTHENTICATED",
        "the provider refused the read (401) - LIVE Agent API with the injected key",
        _live_adapter(),
        True,
    ))
    scenarios.append((
        "NOT_FOUND",
        "no policy exists for this agent (404)",
        _real_adapter(result=_FakeResult(ok=False, http_status=404, data=None)),
        True,
    ))
    scenarios.append((
        "MALFORMED",
        "the provider returned a body that cannot be interpreted",
        _real_adapter(result=_FakeResult(ok=True, http_status=200, data="not-a-policy-object")),
        True,
    ))
    scenarios.append((
        "UNAVAILABLE",
        "the policy read raised a transport error",
        _real_adapter(exc=TimeoutError("simulated transport timeout")),
        True,
    ))
    scenarios.append((
        "UNCONFIGURED",
        "no Agent API base URL is configured",
        _real_adapter(result=None, base_url=""),
        True,
    ))
    scenarios.append((
        "STALE",
        "the adapter reports a stale revision (the gate's own STALE vocabulary)",
        _StandInAdapter(_StaleRead()),
        True,
    ))

    results = []
    for name, description, adapter, require in scenarios:
        row = _run(adapter, require=require)
        row.update({"scenario": name, "description": description})
        results.append(row)

    # Required layer with no adapter must refuse outright, never fall back.
    no_adapter = _run(None, require=True, install_gate=False)
    no_adapter.update({
        "scenario": "REQUIRED_NO_ADAPTER",
        "description": "the layer is required but no adapter is configured; must refuse outright",
    })
    results.append(no_adapter)

    # Assertions: nothing but the control authorizes, and the control does.
    by_name = {r["scenario"]: r for r in results}
    assert by_name["IN_FORCE"]["decision"] == "ALLOW", "the in-force control must authorize"
    assert by_name["IN_FORCE"]["authorized"] is True, "the in-force control must authorize"
    for name in (
        "NOT_IN_FORCE", "FROZEN", "NATIVE_TRANSFER_DISABLED", "AGENT_MISMATCH",
        "UNAUTHENTICATED", "NOT_FOUND", "MALFORMED", "UNAVAILABLE", "UNCONFIGURED",
        "STALE", "REQUIRED_NO_ADAPTER",
    ):
        assert by_name[name]["authorized"] is False, f"{name} must not authorize"
        assert by_name[name]["decision"] != "ALLOW", f"{name} must not be ALLOW"

    record = {
        "provider": {"base_url": BASE_URL, "layer": "near provider policy (NEAR Intents Agent API)"},
        "live_key_configured": bool(os.environ.get("NEAR_INTENTS_AGENT_API_KEY")),
        "note": (
            "The same transaction is prepared for every row; only the provider-policy read changes. "
            "The guard, the boundary and combine_provider_policy are the real product code."
        ),
        "results": results,
        "all_non_control_refused": True,
        "control_authorized": True,
    }
    (HERE / "failure_modes.json").write_text(json.dumps(record, indent=2, sort_keys=True) + "\n")

    print(json.dumps({r["scenario"]: r["decision"] for r in results}, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
