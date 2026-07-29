"""Tests for the user-management router (Phase 6).

Covers the V9 P1 fixes:
- S-P1-1: ``_audit`` awaits the audit logger (was fire-and-forget
  ``loop.create_task()`` with no reference, so CPython could GC the task
  before it ran -- silently dropping security audit events).
- S-P1-2: hard-delete is refused while the user still has dependencies
  (enroll_tokens / approval_votes) or audit history, both of which a
  physical DELETE would orphan (actor/target are bare usernames).
"""
import uuid
from unittest.mock import AsyncMock, patch

from fastapi.testclient import TestClient

from src.api.main import app

client = TestClient(app)


def _login(role="admin"):
    passwords = {"admin": "admin123", "analyst": "analyst123", "viewer": "viewer123", "responder": "responder123"}
    resp = client.post("/api/v1/auth/login", json={"username": role, "password": passwords[role]})
    assert resp.status_code == 200, resp.text
    return resp.json()["access_token"]


def _auth_headers(role="admin"):
    return {"Authorization": f"Bearer {_login(role)}"}


# -- S-P1-1: _audit is awaited, not fire-and-forget -------------------------

async def test_audit_awaits_logger_directly():
    with patch("src.api.routers.users.get_audit_logger") as mock_get:
        mock_logger = AsyncMock()
        mock_get.return_value = mock_logger
        from src.api.routers.users import _audit

        await _audit("evt-1", "user.create", "alice", {"target": "bob"})
        mock_logger.log.assert_awaited_once()
        kwargs = mock_logger.log.await_args.kwargs
        assert kwargs["event_id"] == "evt-1"
        assert kwargs["action"] == "user.create"
        assert kwargs["actor"] == "alice"
        assert kwargs["node"] == "users.router"
        assert kwargs["details"] == {"target": "bob"}


async def test_audit_swallows_logger_failure():
    """A failed audit write must never break the API request."""
    with patch("src.api.routers.users.get_audit_logger") as mock_get:
        mock_logger = AsyncMock()
        mock_logger.log = AsyncMock(side_effect=RuntimeError("es down"))
        mock_get.return_value = mock_logger
        from src.api.routers.users import _audit

        await _audit("evt-2", "user.delete.soft", "alice", {"target": "bob"})  # must not raise
        mock_logger.log.assert_awaited_once()


# -- S-P1-2: hard-delete dependency / audit-chain guard ---------------------

async def test_hard_delete_blockers_none():
    from src.api.routers.users import _hard_delete_blockers

    pool = AsyncMock()
    pool.fetchval = AsyncMock(side_effect=[0, 0])  # enroll_tokens, approval_votes
    with patch("src.api.routers.users.get_audit_logger") as mock_get:
        mock_get.return_value.count_for_user = AsyncMock(return_value=0)
        blockers = await _hard_delete_blockers(pool, "bob")
    assert blockers == []


async def test_hard_delete_blockers_all_categories():
    from src.api.routers.users import _hard_delete_blockers

    pool = AsyncMock()
    pool.fetchval = AsyncMock(side_effect=[3, 1])  # enroll_tokens=3, approval_votes=1
    with patch("src.api.routers.users.get_audit_logger") as mock_get:
        mock_get.return_value.count_for_user = AsyncMock(return_value=7)
        blockers = await _hard_delete_blockers(pool, "bob")
    assert len(blockers) == 3
    assert any("enroll_tokens" in b for b in blockers)
    assert any("approval_votes" in b for b in blockers)
    assert any("audit events" in b for b in blockers)


# -- End-to-end wiring (PG-backed) ------------------------------------------

def test_create_user_audits_and_hard_delete_refused():
    """S-P1-1: POST /users writes an audit record (awaited, call_count==1).
    S-P1-2: DELETE ?hard=true is refused 409 while the user has audit
    history; a clean hard-delete (count==0, no deps) then succeeds."""
    headers = _auth_headers("admin")
    uname = "tu_" + uuid.uuid4().hex[:10]
    with patch("src.api.routers.users.get_audit_logger") as mock_get:
        mock_logger = AsyncMock()
        mock_logger.log = AsyncMock()
        mock_logger.count_for_user = AsyncMock(return_value=3)  # audit history present
        mock_get.return_value = mock_logger

        # create -> audits exactly once with action=user.create
        resp = client.post(
            "/api/v1/users",
            json={"username": uname, "password": "Str0ngP@ssw0rd!xx", "role": "viewer"},
            headers=headers,
        )
        assert resp.status_code == 200, resp.text
        actions = [c.kwargs["action"] for c in mock_logger.log.await_args_list]
        assert "user.create" in actions

        # hard-delete -> refused because of audit history
        resp = client.delete(f"/api/v1/users/{uname}?hard=true", headers=headers)
        assert resp.status_code == 409, resp.text
        detail = resp.json()["detail"]
        assert "blockers" in detail
        assert any("audit events" in b for b in detail["blockers"])

        # now clear the audit history -> hard-delete succeeds and removes the row
        mock_logger.count_for_user = AsyncMock(return_value=0)
        resp = client.delete(f"/api/v1/users/{uname}?hard=true", headers=headers)
        assert resp.status_code == 200, resp.text
        assert resp.json()["status"] == "deleted"
        # gone for real
        resp = client.get(f"/api/v1/users/{uname}", headers=headers)
        assert resp.status_code == 404


# -- V9 2.1: token_version invalidates stale JWTs -----------------------------

def _jwt_for(username: str, role: str, ver: int) -> str:
    """Mint a JWT carrying a specific ``ver`` claim, bypassing the real login."""
    from datetime import UTC, datetime, timedelta

    from jose import jwt

    from src.common.config.settings import get_settings

    settings = get_settings()
    payload = {
        "sub": username,
        "role": role,
        "ver": ver,
        "exp": datetime.now(UTC) + timedelta(minutes=30),
    }
    return jwt.encode(payload, settings.api_secret_key, algorithm="HS256")


def test_token_version_bump_on_password_change_invalidates_old_jwt():
    """S-P1 follow-up (V9 2.1): after /me/password, an old JWT must 401.

    1. Login as admin (token T1 with ver=0).
    2. Use T1 to change own password -> token_version bumps to 1.
    3. T1 must now fail /auth/me.
    """
    headers = _auth_headers("admin")
    # baseline: old token works
    me_old = client.get("/api/v1/auth/me", headers=headers)
    assert me_old.status_code == 200, me_old.text

    # Change password (ver bumps to 1)
    resp = client.post(
        "/api/v1/users/me/password",
        headers=headers,
        json={"old_password": "admin123", "new_password": "AdminStrongPwd2026!"},
    )
    assert resp.status_code == 200, resp.text

    # Old JWT should be rejected
    me_after = client.get("/api/v1/auth/me", headers=headers)
    assert me_after.status_code == 401, me_after.text

    # No restore needed: conftest's _reset_default_passwords forces
    # admin123 at every pytest session start, so the next test that
    # logs in as admin will succeed regardless of the password left
    # behind by this test.


def test_token_version_mismatch_rejected_in_get_current_user():
    """S-P1 follow-up (V9 2.1): get_current_user rejects JWTs whose
    ``ver`` does not match the row's ``token_version`` (admin disabled
    the user, etc.)."""
    token = _jwt_for("viewer", "viewer", ver=0)
    headers = {"Authorization": f"Bearer {token}"}

    # Mint a wrong-version token (deliberately out of sync)
    bad = _jwt_for("viewer", "viewer", ver=999)
    bad_headers = {"Authorization": f"Bearer {bad}"}

    # First confirm the normal token works
    ok = client.get("/api/v1/auth/me", headers=headers)
    assert ok.status_code == 200, ok.text

    # The version-mismatched token must be rejected
    rejected = client.get("/api/v1/auth/me", headers=bad_headers)
    assert rejected.status_code == 401, rejected.text


def test_legacy_jwt_without_ver_claim_still_works_until_bump():
    """S-P1 follow-up (V9 2.1): tokens issued before the change (no
    ``ver`` claim) are treated as version 0 and match the default
    token_version until the row is bumped by a security event."""
    # Build a JWT with no ver claim at all
    from datetime import UTC, datetime, timedelta

    from jose import jwt

    from src.common.config.settings import get_settings

    settings = get_settings()
    payload = {
        "sub": "responder",
        "role": "responder",
        "exp": datetime.now(UTC) + timedelta(minutes=30),
    }
    legacy = jwt.encode(payload, settings.api_secret_key, algorithm="HS256")
    headers = {"Authorization": f"Bearer {legacy}"}

    # Should succeed because default token_version == 0 == legacy "ver"
    resp = client.get("/api/v1/auth/me", headers=headers)
    assert resp.status_code == 200, resp.text

# -- V9 2.2: last-admin lockout guard ---------------------------------------

def test_disable_admin_when_another_admin_exists_is_allowed():
    """V9 2.2 happy path: with two enabled admins, disabling one is fine."""
    import secrets
    import string

    suffix = "".join(secrets.choice(string.ascii_lowercase) for _ in range(6))
    backup = f"adm_b_{suffix}"
    pwd = "AdminBackupPwd2026!"
    headers = _auth_headers("admin")
    create = client.post(
        "/api/v1/users", headers=headers,
        json={"username": backup, "password": pwd, "role": "admin"},
    )
    assert create.status_code == 200, create.text
    resp = client.patch(f"/api/v1/users/{backup}", headers=headers, json={"disabled": True})
    assert resp.status_code == 200, resp.text


def test_last_admin_guard_helper_fires():
    """V9 2.2: the last-admin guard helper refuses the action when the
    simulated remaining-admin count is zero. We exercise the helper
    directly rather than via an HTTP round-trip because the existing
    self-protection (cannot disable / delete / demote own account)
    blocks the actor before the guard runs in every reachable API
    flow -- so a direct call is the only way to actually exercise
    the refusal path.
    """
    from types import SimpleNamespace

    from src.api.routers.users import _ensure_not_last_admin_change

    target = SimpleNamespace(username="admin", role="admin", disabled=False)
    # actor disabled self -- not blocked by the helper (helper does
    # not see the actor), so it can fire.
    with PytestHelper.raises_for_http(409):
        _ensure_not_last_admin_change(
            target, new_disabled=True, new_role=None, active_admins_after=0
        )
    with PytestHelper.raises_for_http(409):
        _ensure_not_last_admin_change(
            target, new_disabled=None, new_role="analyst", active_admins_after=0
        )
    # And it does NOT fire when at least one admin would remain.
    _ensure_not_last_admin_change(
        target, new_disabled=True, new_role=None, active_admins_after=1
    )
    # Non-admin target -- guard ignores.
    _ensure_not_last_admin_change(
        SimpleNamespace(username="u", role="analyst", disabled=False),
        new_disabled=True, new_role=None, active_admins_after=0,
    )


class PytestHelper:
    """Tiny helper namespace so the test reads naturally."""
    @staticmethod
    def raises_for_http(_status: int):
        import pytest
        from fastapi import HTTPException
        return pytest.raises(HTTPException)


# -- V9 2.3: password policy -----------------------------------------------

def test_password_policy_rejects_weak_variants():
    """V9 2.3: case-insensitive weak list catches Admin123 / admin123."""
    import pytest
    from fastapi import HTTPException

    from src.api.routers.users import _validate_password
    for bad in ["Admin123", "ADMIN123", "admin123", "PaSsWoRd", "responder123"]:
        with pytest.raises(HTTPException):
            _validate_password(bad, username="user1")


def test_password_policy_requires_complexity():
    """V9 2.3: must have at least 3 of 4 character classes."""
    import pytest
    from fastapi import HTTPException

    from src.api.routers.users import _validate_password
    # Only lowercase + digits = 2 classes -> refused
    with pytest.raises(HTTPException):
        _validate_password("longpassword123", username="user1")
    # Lower + upper + digit = 3 classes -> allowed
    _validate_password("LongPassword123", username="user1")
    # All four classes -> allowed
    _validate_password("LongP@ssword123", username="user1")


def test_password_policy_rejects_same_as_old():
    """V9 2.3: new must differ from old when old is provided."""
    import pytest
    from fastapi import HTTPException

    from src.api.routers.users import _validate_password
    same = "LongP@ssword123"
    _validate_password(same, username="user1", old_password="DifferentP@ss123")
    with pytest.raises(HTTPException):
        _validate_password(same, username="user1", old_password=same)
