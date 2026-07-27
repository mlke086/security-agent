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
                    username, pwd.hash(password), role,
                )
    asyncio.run(_seed_test_users())
except Exception as _e:
    import warnings
    warnings.warn("PG test-user seed skipped: " + repr(_e))


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