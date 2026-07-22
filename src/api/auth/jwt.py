"""JWT auth utilities - token creation and validation (PG-backed users)."""

from datetime import UTC, datetime, timedelta
from typing import Any, Literal

from jose import JWTError, jwt
from passlib.context import CryptContext

from src.common.config.settings import get_settings

pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")

Role = Literal["admin", "analyst", "viewer", "responder"]


class UserInDB:
    def __init__(self, username: str, hashed_password: str, role: Role, disabled: bool = False):
        self.username = username
        self.hashed_password = hashed_password
        self.role = role
        self.disabled = disabled


def verify_password(plain: str, hashed: str) -> bool:
    return pwd_context.verify(plain, hashed)


async def get_user(username: str) -> UserInDB | None:
    """Fetch user from PostgreSQL. Default users are seeded on startup by init_schema."""
    from src.common.db.pg import get_pg_pool

    pool = await get_pg_pool()
    row = await pool.fetchrow(
        "SELECT username, hashed_password, role, disabled FROM users WHERE username = $1",
        username,
    )
    if row:
        return UserInDB(
            username=row["username"],
            hashed_password=row["hashed_password"],
            role=row["role"],
            disabled=row["disabled"],
        )
    return None


async def authenticate_user(username: str, password: str) -> UserInDB | None:
    user = await get_user(username)
    if not user or not verify_password(password, user.hashed_password):
        return None
    # P1-API-01: refuse disabled users at the login boundary. Without
    # this, an admin could flip ``disabled=true`` and the user would
    # still be able to use any unexpired JWT issued before the flip.
    if user.disabled:
        return None
    return user


def create_access_token(data: dict[str, Any], expires_delta: timedelta | None = None) -> str:
    settings = get_settings()
    to_encode = data.copy()
    expire = datetime.now(UTC) + (
        expires_delta or timedelta(minutes=settings.api_access_token_expire_minutes)
    )
    to_encode.update({"exp": expire})
    return jwt.encode(to_encode, settings.api_secret_key, algorithm="HS256")


def decode_token(token: str) -> dict[str, Any] | None:
    settings = get_settings()
    try:
        payload = jwt.decode(token, settings.api_secret_key, algorithms=["HS256"])
        return payload
    except JWTError:
        return None
