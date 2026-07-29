"""JWT auth utilities - token creation and validation (PG-backed users)."""

from __future__ import annotations

from datetime import UTC, datetime, timedelta
from typing import Literal

from jose import JWTError, jwt
from passlib.context import CryptContext

from src.common.config.settings import get_settings

pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")

Role = Literal["admin", "analyst", "viewer", "responder"]


class UserInDB:
    """In-memory shape of a row from the ``users`` table.

    V9 (2026-07-30) added ``last_login_at``, ``deleted_at`` and
    ``token_version`` so login can stamp timestamps, soft-delete /
    restore work without losing the row, and the JWT carries a
    ``ver`` claim that get_current_user checks against the row's
    current token_version to reject stale tokens.
    """

    def __init__(
        self,
        username: str,
        hashed_password: str,
        role,
        disabled: bool = False,
        created_at=None,
        updated_at=None,
        last_login_at=None,
        deleted_at=None,
        token_version: int = 0,
    ):
        self.username = username
        self.hashed_password = hashed_password
        self.role = role
        self.disabled = disabled
        self.created_at = created_at
        self.updated_at = updated_at
        self.last_login_at = last_login_at
        self.deleted_at = deleted_at
        self.token_version = token_version


def verify_password(plain: str, hashed: str) -> bool:
    return pwd_context.verify(plain, hashed)


async def get_user(username: str, include_deleted: bool = False):
    """Fetch user from PostgreSQL.

    By default soft-deleted rows (``deleted_at IS NOT NULL``) are hidden
    so the regular ``/auth/me``, login, and ``/users`` listing all treat
    them as gone. Pass ``include_deleted=True`` only from the admin
    restore flow so a soft-deleted username can still be looked up.
    """
    from src.common.db.pg import get_pg_pool

    pool = await get_pg_pool()
    where = "WHERE username = $1"
    if not include_deleted:
        where += " AND deleted_at IS NULL"
    row = await pool.fetchrow(
        # token_version added in V9 so get_current_user can detect a
        # stale JWT (claim ver no longer matches the row).
        "SELECT username, hashed_password, role, disabled, created_at, updated_at, last_login_at, deleted_at, token_version FROM users " + where,
        username,
    )
    if row:
        return UserInDB(
            username=row["username"],
            hashed_password=row["hashed_password"],
            role=row["role"],
            disabled=row["disabled"],
            created_at=row["created_at"],
            updated_at=row["updated_at"],
            last_login_at=row["last_login_at"],
            deleted_at=row["deleted_at"],
            token_version=row["token_version"],
        )
    return None


async def record_login(username: str) -> None:
    """Stamp ``last_login_at = NOW()`` after a successful login.

    Best-effort write: if it fails the login should still succeed,
    so we only log a warning. The column is informational, not part
    of any access decision.
    """
    from src.common.db.pg import get_pg_pool
    from src.common.logging.logger import get_logger

    logger = get_logger(__name__)
    try:
        pool = await get_pg_pool()
        await pool.execute(
            "UPDATE users SET last_login_at = NOW() WHERE username = $1",
            username,
        )
    except Exception as exc:
        logger.warning("last_login_update_failed", username=username, error=str(exc))


async def authenticate_user(username: str, password: str):
    """Verify credentials and return the live ``UserInDB``.

    Returns ``None`` for any of: unknown username, wrong password,
    disabled account, soft-deleted account. Login attempts against a
    disabled / deleted account are blocked at the boundary so an
    existing JWT is the only thing that could be abused; even that
    is caught by ``get_current_user`` which re-checks ``disabled``
    on every request and (V9) compares the JWT's ``ver`` claim
    against ``users.token_version``.
    """
    user = await get_user(username)
    if not user or not verify_password(password, user.hashed_password):
        return None
    if user.disabled:
        return None
    if user.deleted_at is not None:
        return None
    await record_login(username)
    return user


def create_access_token(
    data,
    expires_delta=None,
    # V9 (2026-07-30): the caller passes the user's current
    # token_version so the JWT carries a ``ver`` claim.
    # get_current_user rejects tokens whose ver no longer matches
    # the row's token_version (bumped on password change / disable
    # / soft-delete / restore). Older tokens with no ver claim are
    # treated as version 0, which still matches until any of those
    # events fires.
    token_version: int = 0,
):
    settings = get_settings()
    to_encode = dict(data)
    to_encode["ver"] = token_version
    expire = datetime.now(UTC) + (
        expires_delta or timedelta(minutes=settings.api_access_token_expire_minutes)
    )
    to_encode.update({"exp": expire})
    return jwt.encode(to_encode, settings.api_secret_key, algorithm="HS256")


def decode_token(token: str):
    settings = get_settings()
    try:
        payload = jwt.decode(token, settings.api_secret_key, algorithms=["HS256"])
        return payload
    except JWTError:
        return None
