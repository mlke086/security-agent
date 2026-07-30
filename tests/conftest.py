"""Shared pytest configuration.

Forces an in-memory event store and a valid API secret so the suite runs
offline-safe and isolated from the real Elasticsearch-backed store.
These env vars must be set before the src.common.config.settings.get_settings()
is first called; conftest.py is imported by pytest before any test module.
"""

import asyncio
import os

import pytest as _pytest


os.environ.setdefault("STORE_BACKEND", "memory")
os.environ.setdefault("API_SECRET_KEY", "test-secret-key-12345678")
os.environ.setdefault("HITL_TIMEOUT_SEC", "5")
os.environ.setdefault("NACOS_SERVER", "")  # disable nacos in tests; settings come from env

# Initialize PostgreSQL schema (users/tokens/approvals) once at session start.
# get_pg_pool() auto-detects event-loop mismatches, so the pool created here
# (in a throwaway loop) is safely discarded; schema/users persist in PG.
try:
    from src.common.db.pg import init_schema as _init_schema

    asyncio.run(_init_schema())
except Exception as _e:
    import warnings

    warnings.warn("PG schema init skipped: " + repr(_e))


# P1 follow-up (V9 2.1): ensure the default test passwords are
# admin123 / analyst123 / ... regardless of state left by prior runs.
# tests/unit/api/test_users_api.py rotates admin's password to verify
# the token_version bump; that mutation persists in PG across pytest
# sessions, so without this reset the next session's _login("admin")
# would 401 from the first call. The reset uses UPSERT so it is safe
# even on a fresh DB.
import os as _os_reset_pwd  # noqa: E402  -- keep near conftest top


async def _reset_default_passwords() -> None:
    from passlib.context import CryptContext as _CC
    from src.common.db.pg import get_pg_pool as _gpp_reset

    pwd = _CC(schemes=["bcrypt"], deprecated="auto")
    pool = await _gpp_reset()
    test_users = [
        ("admin", "admin123", "admin"),
        ("analyst", "analyst123", "analyst"),
        ("viewer", "viewer123", "viewer"),
        ("responder", "responder123", "responder"),
    ]
    async with pool.acquire() as conn:
        for username, password, role in test_users:
            await conn.execute(
                "INSERT INTO users (username, hashed_password, role)"
                " VALUES ($1, $2, $3)"
                " ON CONFLICT (username) DO UPDATE SET"
                " hashed_password = EXCLUDED.hashed_password,"
                " role = EXCLUDED.role,"
                " disabled = FALSE,"
                " deleted_at = NULL,"
                " token_version = 0",
                username,
                pwd.hash(password),
                role,
            )


try:
    asyncio.run(_reset_default_passwords())
except Exception as _e:
    import warnings as _w

    _w.warn("PG test-password reset skipped: " + repr(_e))

# P1-1: seed the 4 test users (admin / analyst / viewer / responder) with
# the passwords the test suite hard-codes (admin123 / ...). Production
# seeder refuses weak passwords (P1-SEC-06); conftest must bypass that.
# Uses UPSERT so re-runs do not conflict.
try:
    from passlib.context import CryptContext
    from src.common.db.pg import get_pg_pool as _get_pool_for_seed

    async def _seed_test_users() -> None:
        pwd = CryptContext(schemes=["bcrypt"], deprecated="auto")
        pool = await _get_pool_for_seed()
        test_users = [
            ("admin", "admin123", "admin"),
            ("analyst", "analyst123", "analyst"),
            ("viewer", "viewer123", "viewer"),
            ("responder", "responder123", "responder"),
        ]
        async with pool.acquire() as conn:
            for username, password, role in test_users:
                await conn.execute(
                    "INSERT INTO users (username, hashed_password, role)"
                    " VALUES ($1, $2, $3)"
                    " ON CONFLICT (username) DO UPDATE SET"
                    " hashed_password = EXCLUDED.hashed_password,"
                    " role = EXCLUDED.role,"
                    " disabled = FALSE",
                    username,
                    pwd.hash(password),
                    role,
                )

    asyncio.run(_seed_test_users())
except Exception as _e:
    import warnings

    warnings.warn("PG test-user seed skipped: " + repr(_e))


@_pytest.fixture(autouse=True)
def _reset_test_passwords_each_test():
    """Reset admin/analyst/viewer/responder passwords to the canonical
    admin123 / ... at the start of every pytest session. Module-level
    reset above covers cold starts; this covers sessions where an
    earlier test in the SAME session mutated the password (e.g.
    test_token_version_bump_on_password_change_invalidates_old_jwt
    rotates admin to AdminStrongPwd2026! and never restores).
    Runs after the module-level reset so the canonical row exists."""
    import asyncio as _aio_reset
    from passlib.context import CryptContext as _CC2
    from src.common.db.pg import get_pg_pool as _gpp_reset2

    pwd = _CC2(schemes=["bcrypt"], deprecated="auto")
    test_users = [
        ("admin", "admin123", "admin"),
        ("analyst", "analyst123", "analyst"),
        ("viewer", "viewer123", "viewer"),
        ("responder", "responder123", "responder"),
    ]

    async def _do_reset():
        pool = await _gpp_reset2()
        async with pool.acquire() as conn:
            for username, password, role in test_users:
                await conn.execute(
                    "INSERT INTO users (username, hashed_password, role)"
                    " VALUES ($1, $2, $3)"
                    " ON CONFLICT (username) DO UPDATE SET"
                    " hashed_password = EXCLUDED.hashed_password,"
                    " role = EXCLUDED.role,"
                    " disabled = FALSE,"
                    " deleted_at = NULL,"
                    " token_version = 0",
                    username,
                    pwd.hash(password),
                    role,
                )

    try:
        _aio_reset.run(_do_reset())
    except Exception as _exc:
        import warnings as _w2

        _w2.warn("PG session password reset skipped: " + repr(_exc))
    return None


@_pytest.fixture(autouse=True)
async def _truncate_events() -> None:
    """Truncate PG events table before each test for isolation.

    Only active when STORE_BACKEND is "pg"; memory-mode tests are naturally
    isolated because each run gets a fresh singleton.
    """
    if os.environ.get("STORE_BACKEND") != "pg":
        return
    try:
        from src.common.db.pg import get_pg_pool as _gpp

        pool = await _gpp()
        async with pool.acquire() as conn:
            await conn.execute("TRUNCATE events")
    except Exception:
        pass



# V9 5.2: auth_headers fixture. Returns a function ``auth(role) -> dict``
# that logs in via the live FastAPI TestClient and returns a fresh
# Authorization header. Tests use this instead of hard-coding passwords
# so the suite stays correct even if a prior run mutated the password
# table.
@_pytest.fixture(scope="session")
def auth_headers():
    from fastapi.testclient import TestClient
    from src.api.main import app
    from src.api.auth.jwt import create_access_token
    # Build a per-role mapping by minting a JWT directly: it is
    # cheaper than a full login round-trip per test, and the
    # token_version reset fixture above guarantees the ver claim
    # matches the row.
    passwords = {
        "admin": "admin123",
        "analyst": "analyst123",
        "viewer": "viewer123",
        "responder": "responder123",
    }
    minted = {
        role: {"Authorization": "Bearer " + create_access_token(
            data={"sub": role, "role": role},
            token_version=0,
        )}
        for role in passwords
    }
    # Sanity-check by calling /auth/me with one of them; if the
    # login still fails because the password has drifted (e.g. the
    # TestClient was constructed before the reset fixture ran), the
    # suite surfaces a clear error rather than silent 401s downstream.
    client = TestClient(app)
    me = client.get("/api/v1/auth/me", headers=minted["admin"])
    if me.status_code != 200:
        raise RuntimeError(
            f"conftest auth_headers fixture: /auth/me returned {me.status_code} "
            f"-- the password reset fixture may not have run yet. Body: {me.text}"
        )
    return minted.__getitem__


# V9 5.2: convenience fixture that hands out a single TestClient
# initialised AFTER the password reset so it sees the canonical
# state. Tests that previously called ``TestClient(app)`` themselves
# should switch to this one.
@_pytest.fixture(scope="session")
def http_client():
    from fastapi.testclient import TestClient
    from src.api.main import app
    return TestClient(app)
