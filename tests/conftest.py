"""Shared pytest configuration.

Forces an in-memory event store and a valid API secret so the suite runs
offline-safe and isolated from the real Elasticsearch-backed store.
These env vars must be set before ``src.common.config.settings.get_settings()``
is first called; conftest.py is imported by pytest before any test module.
"""

import asyncio
import os

import pytest as _pytest

os.environ.setdefault("STORE_BACKEND", "memory")
os.environ.setdefault("API_SECRET_KEY", "test-secret-key-12345678")
os.environ.setdefault("HITL_TIMEOUT_SEC", "5")

# Initialize PostgreSQL schema (users/tokens/approvals) once at session start.
# get_pg_pool() auto-detects event-loop mismatches, so the pool created here
# (in a throwaway loop) is safely discarded; schema/users persist in PG.
try:
    from src.common.db.pg import init_schema as _init_schema
    asyncio.run(_init_schema())
except Exception as _e:
    import warnings
    warnings.warn(f"PG schema init skipped: {_e}")


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
