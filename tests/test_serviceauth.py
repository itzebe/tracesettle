"""Per-service authentication tests.

These exercise the real :class:`ServiceRegistry`: real hashing, real
constant-time comparison, real rotation and revocation. No mocks.

The property under test is that a service credential resolves to exactly one
service identity, so a caller cannot adopt another service's identity by editing
a field, replaying another service's credential, or presenting a revoked one.
"""

from __future__ import annotations

import json
from datetime import datetime, timedelta, timezone

import pytest

from tracesettle.serviceauth import (
    SECRET_MIN_BYTES,
    ServiceAuthState,
    ServiceCredential,
    ServiceRegistry,
    hash_secret,
    mint_secret,
)

KEY_A = "treasury-agent"
KEY_B = "settlement-agent"


def _future(seconds: int = 3600) -> str:
    return (datetime.now(timezone.utc) + timedelta(seconds=seconds)).strftime("%Y-%m-%dT%H:%M:%SZ")


def _past(seconds: int = 3600) -> str:
    return (datetime.now(timezone.utc) - timedelta(seconds=seconds)).strftime("%Y-%m-%dT%H:%M:%SZ")


# --- minting and hashing ---------------------------------------------------


def test_mint_returns_a_secret_once_and_stores_only_a_hash():
    registry = ServiceRegistry()
    credential, secret = registry.mint(KEY_A)
    assert secret
    assert len(secret) >= SECRET_MIN_BYTES
    assert credential.secret_hash == hash_secret(secret)
    # The plaintext secret must never appear in the persisted or public view.
    assert secret not in json.dumps(registry.to_store())
    assert secret not in json.dumps([c.to_dict() for c in registry.credentials()])


def test_mint_secret_is_high_entropy_and_unique():
    secrets = {mint_secret() for _ in range(50)}
    assert len(secrets) == 50
    for s in secrets:
        assert len(s.encode("utf-8")) >= SECRET_MIN_BYTES


def test_add_rejects_a_weak_secret():
    registry = ServiceRegistry()
    with pytest.raises(ValueError):
        registry.add(KEY_A, "short")


def test_add_rejects_a_duplicate_credential_id():
    registry = ServiceRegistry()
    registry.add(KEY_A, mint_secret(), credential_id="cred_dup")
    with pytest.raises(ValueError):
        registry.add(KEY_B, mint_secret(), credential_id="cred_dup")


# --- authentication --------------------------------------------------------


def test_correct_credential_resolves_to_its_service():
    registry = ServiceRegistry()
    _, secret = registry.mint(KEY_A)
    result = registry.authenticate(secret)
    assert result.state is ServiceAuthState.OK
    assert result.service_id == KEY_A
    assert result.ok


def test_wrong_credential_is_invalid():
    registry = ServiceRegistry()
    registry.mint(KEY_A)
    assert registry.authenticate("not-a-real-credential-value-000000000000").state is (
        ServiceAuthState.INVALID
    )


def test_missing_credential_is_missing():
    registry = ServiceRegistry()
    registry.mint(KEY_A)
    assert registry.authenticate(None).state is ServiceAuthState.MISSING
    assert registry.authenticate("").state is ServiceAuthState.MISSING


def test_credential_is_bound_to_one_service():
    registry = ServiceRegistry()
    _, secret_a = registry.mint(KEY_A)
    _, secret_b = registry.mint(KEY_B)
    assert registry.authenticate(secret_a).service_id == KEY_A
    assert registry.authenticate(secret_b).service_id == KEY_B
    # Swapping the secrets swaps the identities: the credential, not any
    # declared field, is the source of identity.
    assert registry.authenticate(secret_a).service_id != KEY_B


def test_another_services_credential_cannot_impersonate():
    """Service A's credential authenticates as A, never as B."""
    registry = ServiceRegistry()
    _, secret_a = registry.mint(KEY_A)
    registry.mint(KEY_B)
    result = registry.authenticate(secret_a)
    assert result.service_id == KEY_A
    assert result.service_id != KEY_B


# --- expiry and revocation -------------------------------------------------


def test_expired_credential_is_refused():
    registry = ServiceRegistry()
    secret = mint_secret()
    registry.add(KEY_A, secret, expires_at=_past())
    assert registry.credentials()[0].is_expired(datetime.now(timezone.utc))
    assert registry.authenticate(secret).state is ServiceAuthState.EXPIRED


def test_credential_valid_until_its_expiry():
    registry = ServiceRegistry()
    secret = mint_secret()
    registry.add(KEY_A, secret, expires_at=_future())
    assert registry.authenticate(secret).state is ServiceAuthState.OK


def test_revoked_credential_is_refused():
    registry = ServiceRegistry()
    credential, secret = registry.mint(KEY_A)
    assert registry.authenticate(secret).state is ServiceAuthState.OK
    assert registry.revoke(credential.credential_id) is True
    assert registry.authenticate(secret).state is ServiceAuthState.REVOKED


def test_revoke_unknown_credential_returns_false():
    registry = ServiceRegistry()
    registry.mint(KEY_A)
    assert registry.revoke("cred_does_not_exist") is False


# --- rotation --------------------------------------------------------------


def test_rotation_issues_a_new_credential_and_revokes_the_old():
    registry = ServiceRegistry()
    old_credential, old_secret = registry.mint(KEY_A)
    new_credential, new_secret = registry.rotate(KEY_A)
    assert new_credential.credential_id != old_credential.credential_id
    assert registry.authenticate(new_secret).state is ServiceAuthState.OK
    # The previous secret is no longer usable.
    assert registry.authenticate(old_secret).state is ServiceAuthState.REVOKED


def test_rotation_can_overlap_for_a_cutover_window():
    registry = ServiceRegistry()
    _, old_secret = registry.mint(KEY_A)
    _, new_secret = registry.rotate(KEY_A, revoke_previous=False)
    assert registry.authenticate(old_secret).state is ServiceAuthState.OK
    assert registry.authenticate(new_secret).state is ServiceAuthState.OK


def test_rotation_of_one_service_does_not_touch_another():
    registry = ServiceRegistry()
    _, secret_b = registry.mint(KEY_B)
    registry.mint(KEY_A)
    registry.rotate(KEY_A)
    assert registry.authenticate(secret_b).state is ServiceAuthState.OK


# --- registry views --------------------------------------------------------


def test_enabled_is_false_until_a_credential_exists():
    registry = ServiceRegistry()
    assert registry.enabled() is False
    registry.mint(KEY_A)
    assert registry.enabled() is True


def test_active_service_ids_excludes_revoked_and_expired():
    registry = ServiceRegistry()
    credential, _ = registry.mint(KEY_A)
    registry.add(KEY_B, mint_secret(), expires_at=_past())
    assert registry.active_service_ids() == (KEY_A,)
    registry.revoke(credential.credential_id)
    assert registry.active_service_ids() == ()


def test_credentials_for_returns_only_that_service():
    registry = ServiceRegistry()
    registry.mint(KEY_A)
    registry.mint(KEY_A)
    registry.mint(KEY_B)
    assert len(registry.credentials_for(KEY_A)) == 2
    assert len(registry.credentials_for(KEY_B)) == 1


# --- persistence -----------------------------------------------------------


def test_store_round_trips_without_the_plaintext():
    registry = ServiceRegistry()
    _, secret = registry.mint(KEY_A)
    registry.mint(KEY_B)
    restored = ServiceRegistry.from_store(json.loads(json.dumps(registry.to_store())))
    assert restored.authenticate(secret).service_id == KEY_A
    assert restored.enabled()


def test_load_rejects_malformed_json():
    with pytest.raises(ValueError):
        ServiceRegistry.load("{not json")


def test_from_store_rejects_a_missing_secret_hash():
    with pytest.raises(ValueError):
        ServiceRegistry.from_store(
            {"version": 1, "credentials": [{"credential_id": "c", "service_id": KEY_A}]}
        )


def test_from_store_rejects_a_plaintext_secret_hash():
    """A stored entry that is not a sha256: hash is rejected, never accepted."""
    with pytest.raises(ValueError):
        ServiceRegistry.from_store(
            {
                "version": 1,
                "credentials": [
                    {"credential_id": "c", "service_id": KEY_A, "secret_hash": "plaintext-secret"}
                ],
            }
        )


def test_credential_to_dict_never_exposes_the_hash():
    registry = ServiceRegistry()
    credential, _ = registry.mint(KEY_A)
    public = credential.to_dict()
    assert "secret_hash" not in public
    assert credential.secret_hash not in json.dumps(public)


def test_from_store_requires_an_object():
    with pytest.raises(ValueError):
        ServiceRegistry.from_store(["not", "an", "object"])


def test_credential_is_immutable():
    registry = ServiceRegistry()
    credential, _ = registry.mint(KEY_A)
    with pytest.raises(Exception):
        credential.service_id = KEY_B  # type: ignore[misc]


def test_hash_secret_is_stable_and_one_way():
    assert hash_secret("abc") == hash_secret("abc")
    assert hash_secret("abc") != hash_secret("abd")
    assert hash_secret("abc").startswith("sha256:")
    assert "abc" not in hash_secret("abc")


def test_service_credential_from_store_requires_known_fields():
    with pytest.raises(ValueError):
        ServiceCredential.from_store({"service_id": KEY_A, "secret_hash": "sha256:00"})
