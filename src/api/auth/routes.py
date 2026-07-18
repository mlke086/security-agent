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
    """Extract and validate the current user from JWT."""
    if token is None:
        return None
    payload = decode_token(token.credentials)
    if payload is None:
        return None
    username = payload.get("sub")
    if username is None:
        return None
    return await get_user(username)


def require_role(*roles: str):
    """Dependency factory: require one of the specified roles."""
    async def role_checker(current_user: UserInDB | None = Depends(get_current_user)):
        if current_user is None:
            raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Not authenticated")
        if current_user.role not in roles:
            raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="Insufficient permissions")
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
async def get_me(current_user: UserInDB = Depends(require_role("admin", "analyst", "viewer", "responder"))):
    return UserResponse(username=current_user.username, role=current_user.role, disabled=current_user.disabled)
