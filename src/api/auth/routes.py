"""Auth API routes — login, token refresh, user info."""

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
    """
    if token is None:
        return None
    payload = decode_token(token.credentials)
    if payload is None:
        return None
    username = payload.get("sub")
    if username is None:
        return None
    user = await get_user(username)
    if user is None or user.disabled:
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
    token = create_access_token(data={"sub": user.username, "role": user.role})
    return TokenResponse(access_token=token, role=user.role)


@router.get("/me", response_model=UserResponse)
async def get_me(
    current_user: UserInDB = Depends(require_role("admin", "analyst", "viewer", "responder")),
):
    return UserResponse(
        username=current_user.username, role=current_user.role, disabled=current_user.disabled
    )


class SseTokenRequest(BaseModel):
    # F3 (2026-07-21): use the Literal alias instead of bare str so
    # FastAPI returns 422 with a clear "input should be one of ..." message
    # when the frontend typos the scope. Without this mint_sse_token would
    # happily store any string and decode_sse_token would reject it with a
    # generic 401 PermissionError -- hard to debug from the SPA.
    scope: SseScope


class SseTokenResponse(BaseModel):
    token: str
    expires_in: int  # seconds


@router.post("/sse-token", response_model=SseTokenResponse)
async def issue_sse_token(
    req: SseTokenRequest,
    current_user: UserInDB = Depends(require_role("admin", "analyst", "responder", "viewer")),
):
    """Mint a short-lived SSE token scoped to one channel.

    P1-API-04 (2026-07-20): the regular user JWT is too long-lived (120
    minutes default) to be passed as a query string. Frontend calls this
    right before opening an EventSource and uses the returned token in
    the URL -- even if the URL lands in an access log the token expires
    in 60 seconds and only carries permission for one channel.
    """
    from src.api.auth.sse_tokens import _SSE_TOKEN_TTL_SECONDS

    # F8 (2026-07-21): skip the wasteful re-sign. The long-lived JWT would
    # only differ from what the caller already holds if it expired during
    # the request -- which decode_token would have rejected upstream. The
    # 60s wrapper carries just (sub, role, scope) and never escapes this
    # process, so minting from the in-memory current_user is safe.
    short = mint_sse_token_for(current_user.username, current_user.role, req.scope)
    return SseTokenResponse(token=short, expires_in=_SSE_TOKEN_TTL_SECONDS)
