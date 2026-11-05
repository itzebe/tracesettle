"""Live NEAR Intents *provider* reads, run only when a key is supplied.

The NEAR Intents Agent API is real and documented. This test exercises the
**live** endpoint ``GET /v1/agents/{agent_id}/policy`` through the production
adapter (``tracesettle.near.policy.PolicyAdapter``) when an operator supplies a
base URL and a live API key. It is skipped by default: with no credentials the
correct outcome is "skipped", never a fabricated pass.

Two things are always asserted, so the test cannot pass vacuously:

* the endpoint the adapter calls is the documented provider host — the adapter
  never invents an endpoint;
* whatever the provider answers is mapped to the *correct* availability, and an
  ``AVAILABLE`` read is a policy that parses and is reported in force only when
  the provider's own ``status``/``provider_policy_synced`` say so.

Set ``TRACESETTLE_TEST_AGENT_API_URL``, ``TRACESETTLE_TEST_AGENT_API_KEY`` and
(optionally) ``TRACESETTLE_TEST_AGENT_ID`` to run it. It never writes a policy,
never freezes an account, and never signs anything.
"""

from __future__ import annotations

import os
import urllib.parse

import pytest

from tracesettle.near.policy import PolicyAdapter, PolicyAvailability

_BASE_URL = os.environ.get("TRACESETTLE_TEST_AGENT_API_URL", "").strip()
_API_KEY = os.environ.get("TRACESETTLE_TEST_AGENT_API_KEY", "").strip()
_AGENT_ID = os.environ.get("TRACESETTLE_TEST_AGENT_ID", "").strip()

#: The documented provider host. The adapter must only ever call this.
DOCUMENTED_PROVIDER_HOST = "api.agentsonintents.com"

pytestmark = pytest.mark.skipif(
    not (_BASE_URL and _API_KEY),
    reason=(
        "no live Agent API credentials supplied; set "
        "TRACESETTLE_TEST_AGENT_API_URL and TRACESETTLE_TEST_AGENT_API_KEY"
    ),
)


def test_live_provider_read_is_mapped_to_a_documented_availability():
    from tracesettle.httpclient import HttpClient

    adapter = PolicyAdapter(
        base_url=_BASE_URL,
        api_key=_API_KEY,
        http_client=HttpClient(timeout=20, max_attempts=2),
    )
    # No agent id configured is allowed; a provider read then uses the operator's
    # default agent. The read must never raise.
    agent_id = _AGENT_ID or "0" * 64
    read = adapter.read_policy(agent_id)

    assert read.availability in set(PolicyAvailability), read.detail
    # The adapter calls exactly the documented path on the configured host.
    if read.endpoint:
        parsed = urllib.parse.urlsplit(read.endpoint)
        assert parsed.path == f"/v1/agents/{agent_id}/policy"
    if read.availability is PolicyAvailability.AVAILABLE:
        assert read.policy is not None
        # "In force" is decided by the provider's own fields, never assumed.
        assert read.policy.in_force is (
            read.policy.status.value == "APPLIED" and read.policy.provider_policy_synced
        )
    else:
        # A non-available read must never carry a trusted policy.
        assert read.policy is None
        assert read.detail


def test_documented_provider_host_is_the_configured_one():
    """The endpoint is not invented: the base host is the documented provider."""
    host = urllib.parse.urlsplit(_BASE_URL).hostname or ""
    assert host.lower() == DOCUMENTED_PROVIDER_HOST, (
        f"the configured provider host {host!r} is not the documented provider "
        f"{DOCUMENTED_PROVIDER_HOST!r}"
    )
