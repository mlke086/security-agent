"""Short-lived tokens scoped to a single SSE channel.

P1-API-04 (2026-07-20): SSE endpoints take the token as a query string
parameter (which leaks into reverse-proxy access logs, browser history,
and Referer headers). The mitigation is to mint a separate, narrowly
scoped, short-lived token specifically for the SSE connection so that
even if the URL is captured the token expires within a minute. The
underlying JWT secret / user identity is unchanged.
"""

from __future__ import annotations

from datetime import UTC, datetime, timedelta
from typing import Literal

from jose import JWTError, jwt

from src.api.auth.jwt import decode_token
from src.common.config.settings import get_settings

# Channels we know how to scope tokens for. Anything outside this allowlist
# falls back to "events" (the safest public stream).
SseScope = Literal["events", "events_list", "metrics", "approval"]

_SSE_TOKEN_TTL_SECONDS = 60  # P1-API-04: 60s is enough for an SSE handshake


def mint_sse_token(user_jwt: str, scope: SseScope) -> str:
    """Wrap an existing JWT with a narrow scope + 60s TTL.

    Kept for backwards compatibility with any code that still holds a
    long-lived bearer string. New call sites should prefer
    :func:`mint_sse_token_for` which avoids re-decoding the JWT just to
    extract sub/role.
    """
    payload = decode_token(user_jwt) or {}
    return mint_sse_token_for(str(payload.get("sub", "")), str(payload.get("role", "")), scope)


def mint_sse_token_for(sub: str, role: str, scope: SseScope) -> str:
    """Mint a 60s SSE token directly from an authenticated user.

    F8 (2026-07-21): the previous design accepted only a long-lived JWT
    string, forcing the route handler to re-sign one just so this helper
    could decode it back. Now the route already has the authenticated
    user (via HTTPBearer + PG-backed get_current_user), so we can mint
    the wrapper straight from sub/role.
    """
    settings = get_settings()
    wrapped = {
        "sub": sub,
        "role": role,
        "scope": scope,
        "exp": datetime.now(UTC) + timedelta(seconds=_SSE_TOKEN_TTL_SECONDS),
    }
    return jwt.encode(wrapped, settings.api_secret_key, algorithm="HS256")


def decode_sse_token(token: str, expected_scope: str) -> dict:
    """Decode an SSE token and enforce the scope."""
    settings = get_settings()
    try:
        payload = jwt.decode(token, settings.api_secret_key, algorithms=["HS256"])
    except JWTError as exc:
        raise PermissionError("invalid sse token: " + str(exc)) from exc
    if payload.get("scope") != expected_scope:
        raise PermissionError(
            "sse token scope mismatch: want "
            + str(expected_scope)
            + ", got "
            + str(payload.get("scope"))
        )
    return payload
