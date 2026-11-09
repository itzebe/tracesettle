#!/usr/bin/env python3
"""Mission 33T — demonstrate that the live provider policy changes the decision.

Read-only. It drives the *real* NEAR execution boundary and the *real* guard.
The only substitution is the RPC transport (a network boundary), so no
transaction is built against a live node and nothing is broadcast. The provider
policy adapter is the real one and reads the live Agent API with the key from the
environment.

The point: the same transaction, with the same bytes binding, is ALLOWed by the
operator policy alone and becomes HOLD (authorization discarded) once the
independent provider-policy layer is engaged and the provider refuses the read.
The policy layer, not a changed transaction, is what flips the decision.

    python3 evidence/mission33t/enforcement_demo.py
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


def main() -> int:
    from near_helpers import RECIPIENT, make_boundary, public_key_for_test
    from tracesettle.guard.model import Decision
    from tracesettle.httpclient import HttpClient
    from tracesettle.near.policy import PolicyAdapter
    from tracesettle.near.provider_policy_gate import ProviderPolicyGate

    pk = public_key_for_test()
    tx_kwargs = dict(
        service_id="treasury-agent",
        account_id="agent.testnet",
        public_key=pk,
        receiver_id=RECIPIENT,
        asset_identifier="near:native",
        amount_human="1",
    )

    # 1. Operator policy alone.
    base_boundary, _ = make_boundary()
    base = base_boundary.prepare(**tx_kwargs)

    # 2. Same boundary, same transaction, with the LIVE provider layer engaged.
    key = os.environ.get("NEAR_INTENTS_AGENT_API_KEY")
    adapter = PolicyAdapter(
        base_url=BASE_URL,
        api_key=key,
        http_client=HttpClient(),
        expected_agent_id="treasury-agent",
    )
    live_boundary, _ = make_boundary()
    live_boundary._policy_adapter = adapter
    live_boundary._provider_policy_agent_id = "treasury-agent"
    live_boundary._require_provider_policy = True
    live_boundary._policy_gate = ProviderPolicyGate(
        adapter, agent_id="treasury-agent", require=True, native_chain="near"
    )
    live = live_boundary.prepare(**tx_kwargs)

    pp = live.provider_policy
    record = {
        "provider": {"base_url": BASE_URL, "layer": "near provider policy (NEAR Intents Agent API)"},
        "key_configured": bool(key),
        "transaction_binding_identical": base.binding == live.binding,
        "binding": base.binding,
        "operator_policy_only": {
            "decision": base.decision.decision.value,
            "authorized": base.authorized,
            "authorization_id": base.authorization_id,
            "provider_policy": None,
        },
        "with_live_provider_policy": {
            "decision": live.decision.decision.value,
            "authorized": live.authorized,
            "authorization_id": live.authorization_id,
            "provider_policy": pp.to_dict() if pp is not None else None,
        },
        "decision_changed_by_provider_policy": (
            base.decision.decision is not live.decision.decision
        ),
        "authorization_discarded": (base.authorized and not live.authorized),
        "explanation_mentions_provider": "provider policy" in live.decision.explanation.lower(),
        "findings": [f.to_dict() for f in live.decision.findings],
    }
    (HERE / "enforcement_demo.json").write_text(json.dumps(record, indent=2, sort_keys=True) + "\n")

    print(json.dumps({
        "operator_policy_only": record["operator_policy_only"]["decision"],
        "with_live_provider_policy": record["with_live_provider_policy"]["decision"],
        "binding_identical": record["transaction_binding_identical"],
        "authorization_discarded": record["authorization_discarded"],
        "provider_outcome": record["with_live_provider_policy"]["provider_policy"]["outcome"],
    }, indent=2))

    assert base.decision.decision is Decision.ALLOW and base.authorized, "baseline must ALLOW"
    assert live.decision.decision is not Decision.ALLOW and not live.authorized, "live layer must not authorize"
    assert record["transaction_binding_identical"], "the transaction must be identical"
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
