"""User management API (Phase 6, 2026-07-28).

Endpoints:
  GET    /api/v1/users                       (admin)            list users
  GET    /api/v1/users/me                    (any user)         self info
  GET    /api/v1/users/{username}            (admin)            get one
  POST   /api/v1/users                       (admin)            create
  PATCH  /api/v1/users/{username}           (admin)            update
  DELETE /api/v1/users/{username}           (admin)            soft delete (?hard=true for hard)
  POST   /api/v1/users/{username}/restore   (admin)            clear deleted_at
  POST   /api/v1/users/me/password           (any user)         change own password

All write actions are audit-logged (actor + target + before/after).
Self-protection: admins cannot delete/disable/rename themselves.
"""

from __future__ import annotations

import re
import uuid
from typing import Any

from fastapi import APIRouter, Depends, HTTPException, Query
from passlib.context import CryptContext

from src.agents.models import (
    ChangePasswordRequest,
    UserCreate,
    UserListResponse,
    UserPublic,
    UserUpdate,
)
from src.api.auth.jwt import (
    UserInDB,
    get_user,
    verify_password,
)
from src.api.auth.routes import get_current_user, require_role
from src.common.audit.audit_logger import get_audit_logger
from src.common.db.pg import _LEGACY_WEAK_PASSWORDS, get_pg_pool
from src.common.logging.logger import get_logger

router = APIRouter(prefix="/api/v1/users", tags=["users"])

logger = get_logger(__name__)

# Use the same CryptContext the rest of the auth path uses so the
# verification round-trip on a freshly hashed password works in
# integration tests as well.
_pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")

_USERNAME_RE = re.compile(r"^[A-Za-z0-9_]{3,32}$")
# P1-SEC-05: minimum password length 12, and refuse the well-known
# weak list kept in src/common/db/pg.py.
_MIN_PW_LEN = 12


def _to_public(u: UserInDB) -> UserPublic:
    """Project a DB row (UserInDB) into the API model (UserPublic).

    created_at / updated_at / last_login_at are datetime objects from
    asyncpg; Pydantic serialises them as ISO 8601 strings. deleted_at
    is None for active users; we surface it as-is so the admin
    listing with ``?include_deleted=true`` can show the soft-delete
    timestamp.
    """
    return UserPublic(
        username=u.username,
        role=u.role,
        disabled=u.disabled,
        created_at=u.created_at,
        updated_at=u.updated_at,
        last_login_at=u.last_login_at,
        deleted_at=u.deleted_at,
    )


async def _load_or_404(username: str, include_deleted: bool = False) -> UserInDB:
    user = await get_user(username, include_deleted=include_deleted)
    if not user:
        raise HTTPException(status_code=404, detail="user not found")
    return user


async def _audit(event_id: str, action: str, actor: str, details: dict[str, Any]) -> None:
    """Best-effort audit log; never fail the user request because of it.

    S-P1-1 (2026-07-29): previously this scheduled the write with
    loop.create_task() without keeping a reference, so CPython could GC
    the task before it ran -- silently dropping security audit events. We
    now await the write directly so the audit record is durable before the
    response returns. Failures are still swallowed (logging must not break
    the API) but are now logged for diagnosis.
    """
    try:
        await get_audit_logger().log(
            event_id=event_id,
            node="users.router",
            action=action,
            actor=actor,
            details=details,
        )
    except Exception as exc:
        logger.warning("user_audit_failed", action=action, actor=actor, error=str(exc))


def _validate_password(
    new_password: str,
    username: str | None = None,
    old_password: str | None = None,
) -> None:
    """V9 2.3 (2026-07-30): stronger password policy.

    Adds three things on top of the previous length + (case-sensitive)
    weak-list check:
      - case-insensitive weak-list match (Admin123 slipped through
        before because the comparison was case-sensitive);
      - complexity: at least 3 of 4 character classes (lower / upper /
        digit / symbol). Symbols include ASCII punctuation;
      - old != new (only enforced when caller passes old_password,
        which /me/password does and the create-user flow cannot).
    """
    if len(new_password) < _MIN_PW_LEN:
        raise HTTPException(
            status_code=400,
            detail=f"password must be at least {_MIN_PW_LEN} characters",
        )
    if new_password.lower() in {w.lower() for w in _LEGACY_WEAK_PASSWORDS}:
        raise HTTPException(
            status_code=400,
            detail="password is on the weak-password list; pick another",
        )
    classes = sum(
        [
            any(c.islower() for c in new_password),
            any(c.isupper() for c in new_password),
            any(c.isdigit() for c in new_password),
            any(not c.isalnum() for c in new_password),
        ]
    )
    if classes < 3:
        raise HTTPException(
            status_code=400,
            detail=(
                "password must contain at least 3 of 4 classes: lowercase, uppercase, digit, symbol"
            ),
        )
    if username and new_password.lower() == username.lower():
        raise HTTPException(
            status_code=400,
            detail="password must differ from username",
        )
    if old_password is not None and new_password == old_password:
        raise HTTPException(
            status_code=400,
            detail="new password must differ from the old password",
        )


def _validate_username_format(username: str) -> None:
    if not _USERNAME_RE.match(username):
        raise HTTPException(
            status_code=400,
            detail="username must be 3-32 chars of [A-Za-z0-9_]",
        )


# ---- /me (any user) -------------------------------------------------


@router.get("/me", response_model=UserPublic)
async def get_me(
    current_user: UserInDB = Depends(get_current_user),
) -> UserPublic:
    """Return the current user's info (incl. created_at / last_login_at)."""
    if current_user is None:
        raise HTTPException(status_code=401, detail="Not authenticated")
    # Reload with all fields populated (get_user may have been called
    # earlier with the default fields only; refetch to get timestamps).
    fresh = await get_user(current_user.username)
    return _to_public(fresh or current_user)


@router.post("/me/password")
async def change_own_password(
    body: ChangePasswordRequest,
    current_user: UserInDB = Depends(get_current_user),
) -> dict[str, str]:
    if current_user is None:
        raise HTTPException(status_code=401, detail="Not authenticated")
    # Refetch fresh so the latest disabled / deleted_at is honoured
    # (defence-in-depth in case the JWT predates a status change).
    fresh = await _load_or_404(current_user.username)
    if not verify_password(body.old_password, fresh.hashed_password):
        raise HTTPException(status_code=400, detail="old_password is incorrect")
    _validate_password(
        body.new_password,
        username=fresh.username,
        old_password=body.old_password,
    )
    new_hash = _pwd_context.hash(body.new_password)
    pool = await get_pg_pool()
    # V9 (2026-07-30): bump token_version so any unexpired JWT issued
    # before this password change is rejected by get_current_user
    # (which compares the JWT ver claim against users.token_version).
    await pool.execute(
        "UPDATE users SET hashed_password = $1, updated_at = NOW(), token_version = token_version + 1 WHERE username = $2",
        new_hash,
        fresh.username,
    )
    await _audit(
        event_id=str(uuid.uuid4()),
        action="user.password",
        actor=fresh.username,
        details={"target": fresh.username},
    )
    return {"status": "ok"}


# ---- admin-only endpoints --------------------------------------------


@router.get("", response_model=UserListResponse)
async def list_users(
    include_deleted: bool = Query(default=False, description="include soft-deleted users"),
    current_user: UserInDB = Depends(require_role("admin")),
) -> UserListResponse:
    pool = await get_pg_pool()
    where = ""
    if not include_deleted:
        where = " WHERE deleted_at IS NULL"
    rows = await pool.fetch(
        f"SELECT username, role, disabled, created_at, updated_at, last_login_at, deleted_at FROM users{where} ORDER BY username"
    )
    items = [
        UserInDB(
            username=r["username"],
            # hashed_password intentionally not selected: UserInDB
            # requires the field, but this endpoint only renders
            # UserPublic which never carries it. An empty string is
            # safe because the only caller that compares
            # hashed_password is /me/password, which re-fetches the
            # row through get_user() and never sees this list.
            hashed_password="",
            role=r["role"],
            disabled=r["disabled"],
            created_at=r["created_at"],
            updated_at=r["updated_at"],
            last_login_at=r["last_login_at"],
            deleted_at=r["deleted_at"],
        )
        for r in rows
    ]
    return UserListResponse(items=[_to_public(i) for i in items], count=len(items))


@router.get("/{username}", response_model=UserPublic)
async def get_user_one(
    username: str,
    include_deleted: bool = Query(default=False),
    current_user: UserInDB = Depends(require_role("admin")),
) -> UserPublic:
    user = await get_user(username, include_deleted=include_deleted)
    if not user:
        raise HTTPException(status_code=404, detail="user not found")
    return _to_public(user)


@router.post("", response_model=UserPublic)
async def create_user(
    body: UserCreate,
    current_user: UserInDB = Depends(require_role("admin")),
) -> UserPublic:
    _validate_username_format(body.username)
    _validate_password(body.password, username=body.username)
    new_hash = _pwd_context.hash(body.password)
    pool = await get_pg_pool()
    try:
        await pool.execute(
            "INSERT INTO users (username, hashed_password, role) VALUES ($1, $2, $3)",
            body.username,
            new_hash,
            body.role,
        )
    except Exception as exc:  # likely UniqueViolationError
        # asyncpg UniqueViolationError is the right signal, but we do
        # not import the type here to keep imports slim. Any error that
        # mentions duplicate is good enough to surface to the caller.
        if "duplicate" in str(exc).lower() or "unique" in str(exc).lower():
            raise HTTPException(status_code=409, detail="username already exists")
        raise
    fresh = await _load_or_404(body.username)
    await _audit(
        event_id=str(uuid.uuid4()),
        action="user.create",
        actor=current_user.username,
        details={"target": body.username, "role": body.role},
    )
    return _to_public(fresh)


@router.patch("/{username}", response_model=UserPublic)
async def update_user(
    username: str,
    body: UserUpdate,
    current_user: UserInDB = Depends(require_role("admin")),
) -> UserPublic:
    if not any([body.username, body.role is not None, body.disabled is not None]):
        raise HTTPException(status_code=400, detail="no fields to update")
    target = await _load_or_404(username)

    # Self-protection: admin cannot disable / change own role / rename
    # themselves. Otherwise the only admin can accidentally lock out
    # the system.
    if target.username == current_user.username:
        if body.username is not None and body.username != target.username:
            raise HTTPException(status_code=403, detail="cannot rename own account")
        if body.role is not None and body.role != target.role:
            raise HTTPException(status_code=403, detail="cannot change own role")
        if body.disabled is True:
            raise HTTPException(status_code=403, detail="cannot disable own account")

    new_username = body.username
    if new_username is not None and new_username != target.username:
        _validate_username_format(new_username)
    # V9 2.2 (2026-07-30): guard against leaving the system with zero
    # enabled admins. Exclude the target row from the count so we are
    # asking "would this edit leave zero admins?" not "do we currently
    # have zero admins?".
    pool_for_guard = await get_pg_pool()
    remaining_admins = await _count_active_admins(pool_for_guard, exclude_username=target.username)
    _ensure_not_last_admin_change(
        target,
        new_disabled=body.disabled,
        new_role=body.role,
        active_admins_after=remaining_admins,
    )
    if body.role is not None or new_username is not None or body.disabled is not None:
        sets: list[str] = ["updated_at = NOW()"]
        params: list[Any] = []
        if body.role is not None:
            sets.append("role = $" + str(len(params) + 1))
            params.append(body.role)
        # V9 (2026-07-30): when admin flips disabled, bump token_version
        # so existing JWTs are rejected immediately. The existing
        # get_current_user also checks disabled, but the bump forces a
        # 401 even if downstream code skipped that re-check.
        disabled_changed = body.disabled is not None and body.disabled != target.disabled
        if body.disabled is not None:
            sets.append("disabled = $" + str(len(params) + 1))
            params.append(body.disabled)
        if new_username is not None and new_username != target.username:
            sets.append("username = $" + str(len(params) + 1))
            params.append(new_username)
        if disabled_changed:
            sets.append("token_version = token_version + 1")
        params.append(target.username)
        pool = await get_pg_pool()
        try:
            await pool.execute(
                f"UPDATE users SET {', '.join(sets)} WHERE username = ${len(params)}",
                *params,
            )
        except Exception as exc:
            # V9 (2026-07-30): match the duplicate-key error by asyncpg's
            # typed exception instead of substring sniffing the message,
            # which broke across asyncpg/PG versions. (S-P2 2.4)
            import asyncpg

            if isinstance(exc, asyncpg.UniqueViolationError):
                raise HTTPException(status_code=409, detail="username already exists")
            # Fallback in case some non-asyncpg driver surfaces it as a
            # plain Exception with a duplicate-key message.
            if "duplicate" in str(exc).lower() or "unique" in str(exc).lower():
                raise HTTPException(status_code=409, detail="username already exists")
            raise

    after = await _load_or_404(
        new_username if new_username else target.username,
        include_deleted=True,
    )
    await _audit(
        event_id=str(uuid.uuid4()),
        action="user.update",
        actor=current_user.username,
        details={
            "target": target.username,
            "new_username": body.username,
            "role": body.role,
            "disabled": body.disabled,
        },
    )
    return _to_public(after)


async def _count_active_admins(pool, exclude_username: str | None = None) -> int:
    """Return the number of currently-enabled admins.

    V9 2.2 (2026-07-30): a self-protection guard -- the system must
    always retain at least one enabled admin or nobody can manage it.
    Pass ``exclude_username`` to ignore the row we are about to mutate
    (otherwise checking "would this leave zero admins" would always
    raise when the operator is editing an admin).
    """
    sql = "SELECT COUNT(*) FROM users WHERE role = 'admin' AND disabled = FALSE AND deleted_at IS NULL"
    if exclude_username is not None:
        sql += " AND username <> $1"
    if exclude_username is None:
        return await pool.fetchval(sql)
    return await pool.fetchval(sql, exclude_username)


def _ensure_not_last_admin_change(
    target,
    new_disabled: bool | None,
    new_role: str | None,
    active_admins_after: int,
) -> None:
    """V9 2.2 (2026-07-30): refuse mutations that would leave the
    system with zero enabled admins. Raises 409 with a clear hint."""
    would_disable = (new_disabled is True) or target.disabled
    would_demote = (new_role is not None and new_role != "admin") and target.role == "admin"
    if target.role == "admin" and (would_disable or would_demote) and active_admins_after < 1:
        raise HTTPException(
            status_code=409,
            detail="cannot leave the system with zero enabled admins; promote another admin first",
        )


async def _hard_delete_blockers(pool: Any, username: str) -> list[str]:
    """S-P1-2: dependencies / audit history that a physical DELETE would
    orphan. Hard-delete is refused while any blocker exists -- the admin
    should soft-delete (the default) instead, which keeps the row and so
    preserves the audit chain (actor/target are stored as bare usernames).
    """
    blockers: list[str] = []
    n_tokens = await pool.fetchval(
        "SELECT COUNT(*) FROM enroll_tokens WHERE created_by = $1", username
    )
    if n_tokens:
        blockers.append(f"enroll_tokens (created_by): {n_tokens}")
    n_votes = await pool.fetchval("SELECT COUNT(*) FROM approval_votes WHERE voter = $1", username)
    if n_votes:
        blockers.append(f"approval_votes (voter): {n_votes}")
    # Audit chain: actor/target are bare usernames in ES; a physical
    # DELETE orphans every audit entry they appear in.
    try:
        n_audit = await get_audit_logger().count_for_user(username)
    except Exception as exc:  # noqa: BLE001
        logger.warning("audit_count_for_hard_delete_failed", username=username, error=str(exc))
        n_audit = 0
    if n_audit:
        blockers.append(f"audit events (actor/target): {n_audit}")
    return blockers


@router.delete("/{username}")
async def delete_user(
    username: str,
    hard: bool = Query(default=False, description="actually DELETE the row"),
    current_user: UserInDB = Depends(require_role("admin")),
) -> dict[str, str]:
    target = await _load_or_404(username, include_deleted=True)
    if target.username == current_user.username:
        raise HTTPException(status_code=403, detail="cannot delete own account")
    pool = await get_pg_pool()
    # V9 2.2 (2026-07-30): refuse to delete an admin if they are the
    # last enabled one. Soft- and hard-delete both go through here; a
    # soft-delete with no remaining admins is equally a lockout since
    # the row is filtered out of get_user().
    remaining_admins = await _count_active_admins(pool, exclude_username=target.username)
    _ensure_not_last_admin_change(
        target,
        new_disabled=True,
        new_role=None,
        active_admins_after=remaining_admins,
    )
    if hard:
        # S-P1-2: refuse to physically delete a user who still has
        # dependencies or audit history -- both would orphan data (PG
        # rows / audit chain). Soft-delete (below) is the safe default.
        blockers = await _hard_delete_blockers(pool, target.username)
        if blockers:
            raise HTTPException(
                status_code=409,
                detail={
                    "message": (
                        "cannot hard-delete user with dependencies or audit "
                        "history; use soft-delete (default) or reassign first"
                    ),
                    "blockers": blockers,
                },
            )
        await pool.execute("DELETE FROM users WHERE username = $1", target.username)
        await _audit(
            event_id=str(uuid.uuid4()),
            action="user.delete.hard",
            actor=current_user.username,
            details={"target": target.username},
        )
        return {"status": "deleted"}
    # soft delete: set deleted_at; row stays for restore. V9 (2026-07-30)
    # also bumps token_version so existing JWTs are rejected immediately.
    await pool.execute(
        "UPDATE users SET deleted_at = NOW(), updated_at = NOW(), token_version = token_version + 1 WHERE username = $1",
        target.username,
    )
    await _audit(
        event_id=str(uuid.uuid4()),
        action="user.delete.soft",
        actor=current_user.username,
        details={"target": target.username},
    )
    return {"status": "soft_deleted"}


@router.post("/{username}/restore", response_model=UserPublic)
async def restore_user(
    username: str,
    current_user: UserInDB = Depends(require_role("admin")),
) -> UserPublic:
    # include_deleted=True so we can find soft-deleted rows
    target = await get_user(username, include_deleted=True)
    if not target:
        raise HTTPException(status_code=404, detail="user not found")
    if target.deleted_at is None:
        raise HTTPException(status_code=409, detail="user is not soft-deleted")
    pool = await get_pg_pool()
    # V9 (2026-07-30): bump token_version on restore as well. The row
    # was filtered out by get_user() while deleted_at was set, so old
    # tokens were already useless; the bump is belt-and-suspenders in
    # case some code path bypassed the deleted_at filter.
    await pool.execute(
        "UPDATE users SET deleted_at = NULL, updated_at = NOW(), token_version = token_version + 1 WHERE username = $1",
        target.username,
    )
    fresh = await _load_or_404(target.username)
    await _audit(
        event_id=str(uuid.uuid4()),
        action="user.restore",
        actor=current_user.username,
        details={"target": target.username},
    )
    return _to_public(fresh)
