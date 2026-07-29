"""Auth API routes - login, token refresh, user info."""

from typing import Any

from fastapi import APIRouter, Depends, HTTPException, status
from fastapi.security import HTTPBearer
from pydantic import BaseModel

from src.api.auth.jwt import (
    UserInDB,
    authenticate_user,
    create_access_token,
    decode_token,
    get_user,
)
from src.api.auth.sse_tokens import SseScope, mint_sse_token_for

router = APIRouter(prefix="/api/v1/auth", tags=["auth"])


class LoginRequest(BaseModel):
    username: str
    password: str


class TokenResponse(BaseModel):
    access_token: str
    token_type: str = "bearer"
    role: str


class UserResponse(BaseModel):
    username: str
    role: str
    disabled: bool


async def get_current_user(token: Any = Depends(HTTPBearer(auto_error=False))) -> UserInDB | None:
    """Extract and validate the current user from JWT.

    P1-API-01: refetch the user on every request so a freshly-disabled
    account is rejected immediately, even when the JWT itself is still
    valid. The token signature is still checked inside decode_token.

    V9 (2026-07-30): also compare the JWT's ``ver`` claim against the
    row's ``token_version``. Any security state change (password
    change, disable, soft-delete, restore) bumps ``token_version``,
    so a JWT issued before the bump fails this check and the request
    is rejected with 401 -- which is what we want.
    """
    if token is None:
        return None
    payload = decode_token(token.credentials)
    if payload is None:
        return None
    username = payload.get("sub")
    if username is None:
        return None
    # include_deleted=True so we can still see soft-deleted users and
    # reject them via the deleted_at check below.
    user = await get_user(username, include_deleted=True)
    if user is None or user.disabled:
        return None
    if user.deleted_at is not None:
        return None
    # V9 ver check: missing claim is treated as version 0 (matches the
    # default token_version for fresh rows), so legacy tokens still
    # pass until a bump happens.
    try:
        token_ver = int(payload.get("ver", 0))
    except (TypeError, ValueError):
        token_ver = 0
    if token_ver != user.token_version:
        return None
    return user


def require_role(*roles: str):
    """Dependency factory: require one of the specified roles."""

    async def role_checker(current_user: UserInDB | None = Depends(get_current_user)):
        if current_user is None:
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED, detail="Not authenticated"
            )
        if current_user.role not in roles:
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN, detail="Insufficient permissions"
            )
        return current_user

    return role_checker


@router.post("/login", response_model=TokenResponse)
async def login(req: LoginRequest):
    user = await authenticate_user(req.username, req.password)
    if not user:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid credentials")
    # V9 (2026-07-30): stamp the current token_version into the JWT as
    # a ``ver`` claim so get_current_user can reject stale tokens after
    # password change / disable / soft-delete / restore.
    token = create_access_token(
        data={"sub": user.username, "role": user.role},
        token_version=user.token_version,
    )
    return TokenResponse(access_token=token, role=user.role)


@router.get("/me", response_model=UserResponse)
async def get_me(
    current_user: UserInDB = Depends(require_role("admin", "analyst", "viewer", "responder")),
):
    return UserResponse(
        username=current_user.username, role=current_user.role, disabled=current_user.disabled
    )


class SseTokenRequest(BaseModel):
    scope: SseScope


class SseTokenResponse(BaseModel):
    token: str
    expires_in: int


@router.post("/sse-token", response_model=SseTokenResponse)
async def issue_sse_token(
    req: SseTokenRequest,
    current_user: UserInDB = Depends(require_role("admin", "analyst", "responder", "viewer")),
):
    from src.api.auth.sse_tokens import _SSE_TOKEN_TTL_SECONDS

    short = mint_sse_token_for(current_user.username, current_user.role, req.scope)
    return SseTokenResponse(token=short, expires_in=_SSE_TOKEN_TTL_SECONDS)
