"""Helper extracted from main.py to dodge FastAPI auto-registration.

P1-GO-4 (2026-07-19): when this helper lived as a module-level def
inside main.py with `websocket: WebSocket` as its first parameter,
FastAPI auto-registered it as a second WebSocket endpoint at
`/api/v1/agents/ws` (under whatever the helper was named) and
short-circuited the real handler with a 403. Moving the helper to
this separate module keeps the function definition out of
main.py scope so FastAPI never sees it during router build.
"""

from collections.abc import Mapping


def bearer_token_from_headers(
    headers: Mapping[str, str],
    query_token: str,
) -> str:
    """Return the agent auth token.

    Source preference:
      1. ``Authorization: Bearer <token>`` header (preferred, never
         logged by intermediaries).
      2. ``?token=...`` query parameter (legacy fallback; kept so
         operators can still curl the upgrade URL by hand during
         debugging).
    Returns empty string when neither source is set.
    """
    auth = headers.get("authorization", "")
    if auth.startswith("Bearer "):
        return auth[len("Bearer ") :]
    return query_token
