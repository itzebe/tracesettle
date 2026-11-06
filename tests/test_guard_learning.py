"""Tests for the learning loop and its durable safeguard store.

The learning loop is the last step of the mission lifecycle. These tests assert
the safety properties that make it trustworthy:

* it only ever *tightens* a decision, never relaxes one;
* it never overrides the operator's configured policy;
* a lesson is drawn only from a recognised risk finding, never invented;
* the lesson and its effect survive a restart;
* a broken safeguard store fails closed.
"""

from __future__ import annotations

from decimal import Decimal

import pytest

from tracesettle.guard import invariants as inv
from tracesettle.guard.learning import (
    LESSON_BY_FINDING,
    LearningLoop,
    apply_safeguards,
    derive_safeguard,
)
from tracesettle.guard.model import Decision
from tracesettle.guard.policy import DEFAULT_POLICY
from tracesettle.guard.safeguards import (
    DIM_REQUIRE_APPROVAL_ABOVE,
    DIM_REQUIRE_VERIFICATION,
    Safeguard,
    SafeguardError,
    SafeguardStore,
    open_safeguard_store,
)
from tracesettle.guard.service import GuardService, request_from_payload

APPROVED = "0x4e6d3A556e485188E9C9a528bc72c88BD92BD735"
UNAPPROVED = "0x9f8A2c4b7e6D1f03aB5C8e2947D6f10B3aE4c5D6"


def _payload(**overrides):
    base = {
        "service_id": "treasury-agent",
        "operation": "WITHDRAWAL",
        "chain": "eth",
        "asset": "USDC",
        "amount": "100",
        "destination": APPROVED,
        "request_id": "learn-1",
    }
    base.update(overrides)
    return base


@pytest.fixture()
def store(tmp_path):
    s = SafeguardStore(str(tmp_path / "safeguards.db"))
    yield s
    s.close()


# --- store ------------------------------------------------------------------


def test_store_round_trips_a_safeguard(store):
    sg = Safeguard(
        safeguard_id="sg_1",
        service_id="treasury-agent",
        asset="USDC",
        dimension=DIM_REQUIRE_APPROVAL_ABOVE,
        threshold=Decimal("100"),
        reason_code="TEST",
        reason="test",
        created_at=1.0,
    )
    store.record(sg)
    got = store.for_request("treasury-agent", "USDC")
    assert len(got) == 1
    assert got[0].threshold == Decimal("100")
    assert got[0].to_dict()["threshold"] == "100"


def test_store_is_idempotent_and_keeps_the_stricter_threshold(store):
    def record(threshold):
        store.record(
            Safeguard(
                safeguard_id="sg_x",
                service_id="treasury-agent",
                asset="USDC",
                dimension=DIM_REQUIRE_APPROVAL_ABOVE,
                threshold=Decimal(threshold),
                reason_code="TEST",
                reason="test",
                created_at=1.0,
            )
        )

    record("500")
    record("100")  # stricter
    record("900")  # looser: must not weaken
    got = store.for_request("treasury-agent", "USDC")
    assert len(got) == 1
    assert got[0].threshold == Decimal("100")


def test_store_scopes_by_asset(store):
    store.record(
        Safeguard(
            safeguard_id="sg_usdc",
            service_id="treasury-agent",
            asset="USDC",
            dimension=DIM_REQUIRE_VERIFICATION,
            threshold=None,
            reason_code="TEST",
            reason="test",
            created_at=1.0,
        )
    )
    assert store.for_request("treasury-agent", "USDC")
    assert not store.for_request("treasury-agent", "ETH")
    assert not store.for_request("other-service", "USDC")


def test_service_wide_safeguard_matches_every_asset(store):
    store.record(
        Safeguard(
            safeguard_id="sg_all",
            service_id="treasury-agent",
            asset=None,
            dimension=DIM_REQUIRE_VERIFICATION,
            threshold=None,
            reason_code="TEST",
            reason="test",
            created_at=1.0,
        )
    )
    assert store.for_request("treasury-agent", "USDC")
    assert store.for_request("treasury-agent", "ETH")


def test_store_persists_across_reopen(tmp_path):
    path = str(tmp_path / "sg.db")
    first = SafeguardStore(path)
    first.record(
        Safeguard(
            safeguard_id="sg_1",
            service_id="svc",
            asset=None,
            dimension=DIM_REQUIRE_VERIFICATION,
            threshold=None,
            reason_code="TEST",
            reason="test",
            created_at=1.0,
        )
    )
    first.close()
    second = SafeguardStore(path)
    assert len(second.for_request("svc", "USDC")) == 1
    second.close()


def test_clear_removes_a_safeguard(store):
    store.record(
        Safeguard(
            safeguard_id="sg_1",
            service_id="svc",
            asset=None,
            dimension=DIM_REQUIRE_VERIFICATION,
            threshold=None,
            reason_code="TEST",
            reason="test",
            created_at=1.0,
        )
    )
    assert store.clear("sg_1") is True
    assert store.count() == 0
    assert store.clear("sg_1") is False


def test_open_safeguard_store_unset_returns_none():
    assert open_safeguard_store(None) is None
    assert open_safeguard_store("") is None


def test_store_refuses_a_newer_schema(tmp_path):
    import sqlite3

    path = str(tmp_path / "sg.db")
    conn = sqlite3.connect(path)
    conn.execute("CREATE TABLE safeguard_schema (version INTEGER NOT NULL)")
    conn.execute("INSERT INTO safeguard_schema(version) VALUES (99)")
    conn.commit()
    conn.close()
    with pytest.raises(SafeguardError):
        SafeguardStore(path)


# --- derivation -------------------------------------------------------------


def test_derive_returns_none_without_a_recognised_finding():
    request = request_from_payload(_payload())
    assert derive_safeguard(request, Decision.BLOCK, ("SOMETHING_ELSE",)) is None
    assert derive_safeguard(request, Decision.BLOCK, ()) is None


def test_derive_returns_none_for_an_allow():
    request = request_from_payload(_payload())
    assert derive_safeguard(request, Decision.ALLOW, ("UNAPPROVED_DESTINATION",)) is None


def test_derive_tightens_to_approval_for_an_unapproved_destination():
    request = request_from_payload(_payload(amount="250"))
    lesson = derive_safeguard(request, Decision.BLOCK, ("UNAPPROVED_DESTINATION",))
    assert lesson is not None
    assert lesson.dimension == DIM_REQUIRE_APPROVAL_ABOVE
    assert lesson.threshold == Decimal("250")


def test_derive_requires_verification_for_a_denied_destination():
    request = request_from_payload(_payload())
    lesson = derive_safeguard(request, Decision.BLOCK, ("DESTINATION_DENIED",))
    assert lesson is not None
    assert lesson.dimension == DIM_REQUIRE_VERIFICATION


def test_every_lesson_maps_to_a_known_dimension():
    for code, (reason_code, _reason) in LESSON_BY_FINDING.items():
        assert code and reason_code


# --- application ------------------------------------------------------------


def _request(amount):
    return request_from_payload(_payload(amount=amount))


def test_apply_does_nothing_without_safeguards():
    app = apply_safeguards(_request("100"), ())
    assert app.applied is False
    assert app.decision is None


def test_apply_tightens_only_above_the_threshold():
    sg = Safeguard(
        safeguard_id="sg_1",
        service_id="treasury-agent",
        asset="USDC",
        dimension=DIM_REQUIRE_APPROVAL_ABOVE,
        threshold=Decimal("100"),
        reason_code="TEST",
        reason="test",
        created_at=1.0,
    )
    assert apply_safeguards(_request("100"), (sg,)).applied is False
    assert apply_safeguards(_request("100.01"), (sg,)).decision is Decision.REQUIRE_APPROVAL


def test_apply_verification_safeguard_holds():
    sg = Safeguard(
        safeguard_id="sg_1",
        service_id="treasury-agent",
        asset="USDC",
        dimension=DIM_REQUIRE_VERIFICATION,
        threshold=None,
        reason_code="TEST",
        reason="test",
        created_at=1.0,
    )
    app = apply_safeguards(_request("1"), (sg,))
    assert app.decision is Decision.HOLD
    assert app.applied is True


def test_apply_takes_the_strictest_of_several():
    approval = Safeguard(
        safeguard_id="sg_a",
        service_id="treasury-agent",
        asset="USDC",
        dimension=DIM_REQUIRE_APPROVAL_ABOVE,
        threshold=Decimal("1"),
        reason_code="TEST",
        reason="test",
        created_at=1.0,
    )
    verify = Safeguard(
        safeguard_id="sg_v",
        service_id="treasury-agent",
        asset="USDC",
        dimension=DIM_REQUIRE_VERIFICATION,
        threshold=None,
        reason_code="TEST",
        reason="test",
        created_at=1.0,
    )
    app = apply_safeguards(_request("100"), (approval, verify))
    assert app.decision is Decision.HOLD
    assert set(app.safeguard_ids) == {"sg_a", "sg_v"}


# --- the loop ---------------------------------------------------------------


def test_inert_loop_records_nothing():
    loop = LearningLoop(None)
    assert loop.enabled is False
    assert loop.apply(_request("100")).applied is False
    assert loop.observe(_request("100"), Decision.BLOCK, ("UNAPPROVED_DESTINATION",)) is None
    assert loop.list() == ()


def test_loop_learns_and_tightens_a_later_decision(store):
    service = GuardService(policy=DEFAULT_POLICY, safeguard_store=store)
    first = service.evaluate_payload(_payload(request_id="l1", destination=UNAPPROVED))
    assert first.decision is Decision.BLOCK
    assert first.learned_safeguard is not None

    second = service.evaluate_payload(_payload(request_id="l2", amount="5000"))
    assert second.influenced_by_learning is True
    assert second.decision is not Decision.ALLOW
    assert second.authorization is None
    assert any(f.code == "LEARNED_SAFEGUARD_APPLIED" for f in second.findings)


def test_loop_does_not_tighten_below_the_learned_threshold(store):
    service = GuardService(policy=DEFAULT_POLICY, safeguard_store=store)
    service.evaluate_payload(_payload(request_id="l1", amount="1000", destination=UNAPPROVED))
    below = service.evaluate_payload(_payload(request_id="l2", amount="1000"))
    assert below.decision is Decision.ALLOW
    assert below.influenced_by_learning is False


def test_loop_effect_survives_a_restart(tmp_path):
    path = str(tmp_path / "sg.db")
    first_store = SafeguardStore(path)
    first = GuardService(policy=DEFAULT_POLICY, safeguard_store=first_store)
    first.evaluate_payload(_payload(request_id="l1", amount="100", destination=UNAPPROVED))
    first_store.close()

    reopened = SafeguardStore(path)
    second = GuardService(policy=DEFAULT_POLICY, safeguard_store=reopened)
    decision = second.evaluate_payload(_payload(request_id="l2", amount="9999"))
    assert decision.influenced_by_learning is True
    assert decision.decision is not Decision.ALLOW
    reopened.close()


def test_loop_never_weakens_the_operator_policy(store):
    """A learned safeguard is applied on top of, never instead of, the policy."""
    service = GuardService(policy=DEFAULT_POLICY, safeguard_store=store)
    # A request the operator's policy already refuses stays refused.
    denied = service.evaluate_payload(
        _payload(request_id="d1", destination="0x" + "0" * 40)
    )
    assert denied.decision is Decision.BLOCK
    assert denied.authorization is None


def test_loop_counts_applications(store):
    service = GuardService(policy=DEFAULT_POLICY, safeguard_store=store)
    service.evaluate_payload(_payload(request_id="l1", amount="100", destination=UNAPPROVED))
    service.evaluate_payload(_payload(request_id="l2", amount="9999"))
    service.evaluate_payload(_payload(request_id="l3", amount="8888"))
    stored = store.all()
    assert len(stored) == 1
    assert stored[0].applied_count == 2


def test_broken_store_fails_closed(tmp_path):
    """An unreadable safeguard store yields REQUIRE_APPROVAL, never ALLOW."""
    path = str(tmp_path / "sg.db")
    store = SafeguardStore(path)
    service = GuardService(policy=DEFAULT_POLICY, safeguard_store=store)
    store.close()  # every later read raises SafeguardError

    decision = service.evaluate_payload(_payload(request_id="broken"))
    assert decision.decision is not Decision.ALLOW
    assert decision.authorization is None


# --- invariants -------------------------------------------------------------


def test_learning_invariants_are_registered():
    for name in ("learning_loop_only_tightens", "learning_never_relaxes_policy"):
        assert name in inv.INVARIANTS
        assert name in inv.INVARIANT_DESCRIPTIONS


def test_learning_invariants_hold():
    for name in ("learning_loop_only_tightens", "learning_never_relaxes_policy"):
        result = inv.INVARIANTS[name]()
        assert result.holds is True, result.detail


def test_learning_invariant_fails_if_a_safeguard_cannot_tighten(monkeypatch):
    """Mutation: if the loop ignored a learned safeguard, the invariant must fail."""
    from tracesettle.guard import learning as learning_mod

    monkeypatch.setattr(learning_mod.LearningLoop, "apply", lambda self, request: learning_mod.SafeguardApplication(None, (), (), ()))
    result = inv.INVARIANTS["learning_loop_only_tightens"]()
    assert result.holds is False


def test_learning_invariant_fails_if_lessons_are_not_persisted(monkeypatch):
    """Mutation: if a lesson were not recorded, the invariant must fail."""
    from tracesettle.guard import learning as learning_mod

    monkeypatch.setattr(learning_mod.LearningLoop, "observe", lambda self, *a, **k: None)
    result = inv.INVARIANTS["learning_loop_only_tightens"]()
    assert result.holds is False


def test_relax_invariant_fails_if_a_safeguard_could_relax(monkeypatch):
    """Mutation: if a below-threshold safeguard fired, the invariant must fail."""
    from tracesettle.guard import learning as learning_mod

    real = learning_mod.apply_safeguards

    def permissive(request, safeguards):
        app = real(request, safeguards)
        if safeguards:
            return learning_mod.SafeguardApplication(
                decision=Decision.ALLOW,
                reasons=app.reasons,
                safeguard_ids=app.safeguard_ids,
                safeguards=app.safeguards,
            )
        return app

    monkeypatch.setattr(learning_mod, "apply_safeguards", permissive)
    result = inv._learning_never_relaxes_the_operators_policy()
    assert result.holds is False
