"""WI-02 Auth & RBAC tests."""

from __future__ import annotations

import pytest

from portal.auth.csrf import CsrfTokenManager
from portal.auth.mfa import MfaNonceManager, StepUpRequired, require_mfa
from portal.auth.models import Role, User
from portal.auth.rbac import (
    current_user,
    map_groups_to_roles,
    require_any_role,
    require_role,
)
from portal.auth.session import InMemorySessionStore


# ─── RBAC ────────────────────────────────────────────────────────────────────


@pytest.mark.asyncio
async def test_require_role_passes_when_user_has_role(make_user) -> None:
    dep = require_role(Role.ADMIN)
    user = make_user(roles=[Role.ADMIN])
    out = await dep(user=user)
    assert out is user


@pytest.mark.asyncio
async def test_require_role_403_when_missing(make_user) -> None:
    from fastapi import HTTPException

    dep = require_role(Role.ADMIN)
    user = make_user(roles=[Role.VIEWER])
    with pytest.raises(HTTPException) as info:
        await dep(user=user)
    assert info.value.status_code == 403


@pytest.mark.asyncio
async def test_require_any_role_passes_when_one_matches(make_user) -> None:
    dep = require_any_role(Role.ADMIN, Role.COMPLIANCE_OFFICER)
    user = make_user(roles=[Role.COMPLIANCE_OFFICER])
    out = await dep(user=user)
    assert out is user


def test_require_any_role_requires_at_least_one_role() -> None:
    with pytest.raises(ValueError):
        require_any_role()


def test_map_groups_to_roles_translates() -> None:
    g2r = {
        "compliance-portal-admin": "admin",
        "compliance-portal-officer": "compliance_officer",
        "compliance-portal-auditor": "auditor",
    }
    roles = map_groups_to_roles(["compliance-portal-officer", "unknown-group"], g2r)
    assert roles == [Role.COMPLIANCE_OFFICER]


def test_map_groups_to_roles_dedupes() -> None:
    g2r = {
        "g1": "admin",
        "g2": "admin",
    }
    roles = map_groups_to_roles(["g1", "g2"], g2r)
    assert roles == [Role.ADMIN]


def test_map_groups_to_roles_empty_when_no_match() -> None:
    assert map_groups_to_roles(["nope"], {"g": "admin"}) == []


# ─── Session rotation (AMD-15) ───────────────────────────────────────────────


@pytest.mark.asyncio
async def test_session_rotate_invalidates_old_id() -> None:
    """AMD-15 — old session id must be invalidated on rotate."""
    store = InMemorySessionStore()
    old_id = await store.create({"user": "alice"}, ttl_s=600)
    assert await store.exists(old_id) is True

    new_id = await store.rotate(old_id, {"user": "alice", "rotated": True}, ttl_s=600)

    assert old_id != new_id
    assert await store.exists(old_id) is False  # invalidated
    assert await store.exists(new_id) is True
    payload = await store.get(new_id)
    assert payload == {"user": "alice", "rotated": True}


@pytest.mark.asyncio
async def test_session_rotate_when_no_prior_id() -> None:
    """Rotate with old=None just creates a new session."""
    store = InMemorySessionStore()
    new_id = await store.rotate(None, {"user": "bob"}, ttl_s=600)
    assert await store.exists(new_id) is True
    assert (await store.get(new_id)) == {"user": "bob"}


@pytest.mark.asyncio
async def test_session_id_has_high_entropy() -> None:
    """`secrets.token_urlsafe(32)` yields >= 43-char base64url string (256 bits)."""
    store = InMemorySessionStore()
    sid = await store.create({"u": 1}, ttl_s=60)
    assert len(sid) >= 40
    # Verify base64url alphabet
    assert all(c.isalnum() or c in "-_" for c in sid)


# ─── MFA step-up + nonce binding (AMD-03) ────────────────────────────────────


@pytest.mark.asyncio
async def test_require_mfa_passes_when_fresh(make_user) -> None:
    dep = require_mfa(max_age_s=300)
    user = make_user(mfa_age_s=10, roles=[Role.ADMIN])
    out = await dep(user=user)
    assert out is user


@pytest.mark.asyncio
async def test_require_mfa_raises_stepup_when_stale(make_user) -> None:
    dep = require_mfa(max_age_s=60)
    user = make_user(mfa_age_s=120, roles=[Role.ADMIN])
    with pytest.raises(StepUpRequired) as info:
        await dep(user=user)
    assert info.value.max_age_s == 60


@pytest.mark.asyncio
async def test_require_mfa_raises_when_no_mfa_at(make_user) -> None:
    dep = require_mfa(max_age_s=60)
    user = make_user(mfa_age_s=None, roles=[Role.ADMIN])
    with pytest.raises(StepUpRequired):
        await dep(user=user)


def test_mfa_nonce_consume_once() -> None:
    mgr = MfaNonceManager(max_age_s=60)
    token = mgr.issue("alice", "gate.decide:abc")
    assert mgr.consume(token, "alice", "gate.decide:abc") is True
    # Replay: must fail
    assert mgr.consume(token, "alice", "gate.decide:abc") is False


def test_mfa_nonce_bound_to_user_and_action() -> None:
    mgr = MfaNonceManager(max_age_s=60)
    token = mgr.issue("alice", "gate.decide:abc")
    # Wrong user
    assert mgr.consume(token, "bob", "gate.decide:abc") is False


def test_mfa_nonce_expires() -> None:
    mgr = MfaNonceManager(max_age_s=0)  # immediate expiry
    token = mgr.issue("alice", "x")
    import time

    time.sleep(0.01)
    assert mgr.consume(token, "alice", "x") is False


def test_mfa_nonce_fingerprint_does_not_leak() -> None:
    fp = MfaNonceManager.fingerprint("very-secret-token")
    assert "very-secret-token" not in fp
    assert len(fp) == 16


# ─── CSRF ────────────────────────────────────────────────────────────────────


def test_csrf_generate_and_verify() -> None:
    tm = CsrfTokenManager(secret="x" * 32)
    token = tm.generate()
    assert tm.verify(token) is True


def test_csrf_rejects_unsigned() -> None:
    tm = CsrfTokenManager(secret="x" * 32)
    assert tm.verify("not-a-real-token") is False
    assert tm.verify("") is False


def test_csrf_matches_requires_equal_tokens() -> None:
    tm = CsrfTokenManager(secret="x" * 32)
    a = tm.generate()
    b = tm.generate()
    assert tm.matches(a, a) is True
    assert tm.matches(a, b) is False
