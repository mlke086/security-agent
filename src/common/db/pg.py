"""PostgreSQL connection pool and schema management.

Phase 1 persistence: users & RBAC, enroll tokens, agent auth tokens, HITL approvals.
Phase 2 adds hosts (agent inventory) and events (event lifecycle records).
"""
from __future__ import annotations

import asyncpg

from src.common.config.settings import get_settings
from src.common.logging.logger import get_logger

logger = get_logger(__name__)

_pool: asyncpg.Pool | None = None

_SCHEMA_SQL = """
-- Users & RBAC (Phase 1)
CREATE TABLE IF NOT EXISTS users (
    username        VARCHAR(64) PRIMARY KEY,
    hashed_password TEXT NOT NULL,
    role            VARCHAR(32) NOT NULL,
    disabled        BOOLEAN NOT NULL DEFAULT FALSE,
    created_at      TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at      TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

-- Agent enroll tokens (Phase 1)
CREATE TABLE IF NOT EXISTS enroll_tokens (
    token           VARCHAR(128) PRIMARY KEY,
    group_name      VARCHAR(128),
    expires_at      TIMESTAMPTZ NOT NULL,
    uses_remaining  INTEGER NOT NULL DEFAULT 1,
    created_at      TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    created_by      VARCHAR(64),
    used_at         TIMESTAMPTZ,
    used_by_host    VARCHAR(256)
);

-- Agent auth tokens (WS authentication, Phase 1)
CREATE TABLE IF NOT EXISTS agent_tokens (
    agent_id    VARCHAR(64) PRIMARY KEY,
    token_hash  TEXT NOT NULL,
    issued_at   TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    revoked_at  TIMESTAMPTZ
);

-- HITL approvals (Phase 1)
CREATE TABLE IF NOT EXISTS approvals (
    approval_id     UUID PRIMARY KEY,
    event_id        VARCHAR(64) NOT NULL,
    status          VARCHAR(32) NOT NULL DEFAULT 'pending',
    required        INTEGER NOT NULL DEFAULT 1,
    operation_level VARCHAR(8) NOT NULL,
    created_at      TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    resolved_at     TIMESTAMPTZ
);
CREATE INDEX IF NOT EXISTS idx_approvals_event_id ON approvals(event_id);
CREATE INDEX IF NOT EXISTS idx_approvals_status ON approvals(status);

-- Approval votes (multi-approver audit trail, Phase 1)
CREATE TABLE IF NOT EXISTS approval_votes (
    id          SERIAL PRIMARY KEY,
    approval_id UUID NOT NULL REFERENCES approvals(approval_id) ON DELETE CASCADE,
    voter       VARCHAR(64) NOT NULL,
    decision    VARCHAR(16) NOT NULL,
    voted_at    TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    UNIQUE(approval_id, voter)
);

-- Agent host inventory (Phase 2: PG primary, ES mirror)
CREATE TABLE IF NOT EXISTS hosts (
    agent_id        VARCHAR(64) PRIMARY KEY,
    hostname        VARCHAR(256),
    ip              VARCHAR(64),
    os              VARCHAR(64),
    arch            VARCHAR(32),
    kernel          VARCHAR(128),
    status          VARCHAR(32) NOT NULL DEFAULT 'online',
    group_name      VARCHAR(128),
    agent_version   VARCHAR(32),
    rule_version    VARCHAR(32),
    last_heartbeat  TIMESTAMPTZ,
    created_at      TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at      TIMESTAMPTZ NOT NULL DEFAULT NOW()
);
CREATE INDEX IF NOT EXISTS idx_hosts_status ON hosts(status);
CREATE INDEX IF NOT EXISTS idx_hosts_group ON hosts(group_name);

-- Event lifecycle records (Phase 2: PG primary, ES for full-text search)
CREATE TABLE IF NOT EXISTS events (
    event_id    VARCHAR(64) PRIMARY KEY,
    data        JSONB NOT NULL,
    updated_at  TIMESTAMPTZ NOT NULL DEFAULT NOW()
);
CREATE INDEX IF NOT EXISTS idx_events_status ON events ((data->>'status'));
CREATE INDEX IF NOT EXISTS idx_events_submitted ON events ((data->>'submitted_at'));
"""

# Default users to seed on first run
_DEFAULT_USERS = [
    ("admin", "admin123", "admin"),
    ("analyst", "analyst123", "analyst"),
    ("viewer", "viewer123", "viewer"),
    ("responder", "responder123", "responder"),
]


async def get_pg_pool() -> asyncpg.Pool:
    """Return the singleton asyncpg connection pool.

    If the existing pool was created in a different event loop (e.g. TestClient
    runs in its own thread/loop), it is discarded and a fresh one is created.
    """
    global _pool
    try:
        current_loop = __import__("asyncio").get_running_loop()
    except RuntimeError:
        current_loop = None
    if _pool is not None and getattr(_pool, "_loop", None) is not current_loop:
        _pool = None  # Pool belongs to a different/stale loop
    if _pool is None:
        s = get_settings()
        _pool = await asyncpg.create_pool(
            host=s.pg_host,
            port=s.pg_port,
            database=s.pg_database,
            user=s.pg_user,
            password=s.pg_password,
            min_size=2,
            max_size=s.pg_pool_size,
            command_timeout=30,
        )
        logger.info("pg_pool_created", host=s.pg_host, db=s.pg_database)
    return _pool


async def init_schema() -> None:
    """Create tables if they don't exist and seed default users."""
    pool = await get_pg_pool()
    async with pool.acquire() as conn:
        await conn.execute(_SCHEMA_SQL)
        # Seed default users if table is empty
        count = await conn.fetchval("SELECT COUNT(*) FROM users")
        if count == 0:
            from passlib.context import CryptContext
            pwd = CryptContext(schemes=["bcrypt"], deprecated="auto")
            for username, password, role in _DEFAULT_USERS:
                await conn.execute(
                    "INSERT INTO users (username, hashed_password, role) VALUES ($1, $2, $3)",
                    username, pwd.hash(password), role,
                )
            logger.info("pg_default_users_seeded", count=len(_DEFAULT_USERS))


async def close_pool() -> None:
    global _pool
    if _pool is not None:
        await _pool.close()
        _pool = None
        logger.info("pg_pool_closed")
