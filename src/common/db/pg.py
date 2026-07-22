"""PostgreSQL connection pool and schema management.

Phase 1 persistence: users & RBAC, enroll tokens, agent auth tokens, HITL approvals.
Phase 2 adds hosts (agent inventory) and events (event lifecycle records).
"""

from __future__ import annotations

import secrets

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

-- Host groups (Phase 2: user-defined host grouping). hosts.group_name is the
-- join key; kept in a separate table so operators can pre-create empty groups
-- before enrolling agents into them.
CREATE TABLE IF NOT EXISTS host_groups (
    group_name    VARCHAR(128) PRIMARY KEY,
    description   TEXT,
    created_at    TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

-- LLM model registry (需求4 模型管理). Stores provider config so operators
-- can add / switch / default models from the UI instead of editing .env.
-- api_key is stored in plain text here (Phase 1); harden with pgcrypto /
-- KMS in a later pass. is_default marks the single global default model.
CREATE TABLE IF NOT EXISTS llm_models (
    id                      SERIAL PRIMARY KEY,
    name                    VARCHAR(128) NOT NULL,
    provider                VARCHAR(32)  NOT NULL,   -- openai | claude | vllm
    model_name              VARCHAR(128) NOT NULL,   -- e.g. glm-5.2, deepseek-v4-pro
    api_key                 TEXT         NOT NULL DEFAULT '',
    base_url                TEXT         NOT NULL DEFAULT '',
    temperature             REAL         NOT NULL DEFAULT 0.1,
    max_tokens              INTEGER      NOT NULL DEFAULT 4096,
    supports_structured     BOOLEAN      NOT NULL DEFAULT TRUE,
    enabled                 BOOLEAN      NOT NULL DEFAULT TRUE,
    is_default              BOOLEAN      NOT NULL DEFAULT FALSE,
    created_at              TIMESTAMPTZ  NOT NULL DEFAULT NOW(),
    updated_at              TIMESTAMPTZ  NOT NULL DEFAULT NOW()
);
CREATE UNIQUE INDEX IF NOT EXISTS idx_llm_models_default ON llm_models(is_default) WHERE is_default;
CREATE INDEX IF NOT EXISTS idx_llm_models_enabled ON llm_models(enabled);

-- Scan conversations (需求3 对话式扫描). Stores multi-turn chat history so
-- the operator can refine scan intent across turns, switch models, and resume
-- past sessions. messages is a JSONB array of {role, content, ts}.
CREATE TABLE IF NOT EXISTS scan_conversations (
    id          UUID PRIMARY KEY,
    title       VARCHAR(256) NOT NULL DEFAULT '新对话',
    model_id    INTEGER,
    messages    JSONB NOT NULL DEFAULT '[]'::jsonb,
    created_at  TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at  TIMESTAMPTZ NOT NULL DEFAULT NOW()
);
CREATE INDEX IF NOT EXISTS idx_scan_conversations_created ON scan_conversations(created_at DESC);

-- Event lifecycle records (Phase 2: PG primary, ES for full-text search)
CREATE TABLE IF NOT EXISTS events (
    event_id    VARCHAR(64) PRIMARY KEY,
    data        JSONB NOT NULL,
    updated_at  TIMESTAMPTZ NOT NULL DEFAULT NOW()
);
CREATE INDEX IF NOT EXISTS idx_events_status ON events ((data->>'status'));
CREATE INDEX IF NOT EXISTS idx_events_submitted ON events ((data->>'submitted_at'));
"""

# Default users to seed on first run. Passwords are NOT hardcoded --
# they come from settings so production deployments can inject their
# own values via env vars / KMS. In dev (DEV_MODE=true) the seeder
# generates a random password per process and logs it so the operator
# can log in once.
_DEFAULT_USERS = [
    ("admin", "default_admin_password", "admin"),
    ("analyst", "default_analyst_password", "analyst"),
    ("viewer", "default_viewer_password", "viewer"),
    ("responder", "default_responder_password", "responder"),
]

# P1-SEC-06 (2026-07-20): the legacy "username + role" weak passwords
# we used to seed (admin/admin123, viewer/viewer123 ...). Used as a
# refusal list in production so we never silently re-introduce them.
_LEGACY_WEAK_PASSWORDS = frozenset(
    {
        "admin123",
        "analyst123",
        "viewer123",
        "responder123",
        "admin",
        "analyst",
        "viewer",
        "responder",
        "password",
        "changeme",
        "test",
    }
)


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
            # F-login (2026-07-21): the previous pool had no acquire-timeout,
            # so when PG was slow / a network blip killed the pre-warmed
            # connections, /auth/login + /auth/me callers blocked until
            # the default 30s command_timeout fired -- the SPA then
            # swallowed the resulting 500 as a generic "用户名或密码错误".
            # Give acquire a tighter budget so the login flow returns fast
            # and the frontend can surface the real error.
            command_timeout=10,
            timeout=5,
            max_inactive_connection_lifetime=60.0,
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
            settings = get_settings()
            dev_mode = bool(getattr(settings, "dev_mode", False))
            passwords_used: list[tuple[str, str]] = []
            for username, password_key, role in _DEFAULT_USERS:
                # Pull the per-role password from settings (env-driven)
                # unless we're in dev mode, in which case we generate a
                # random password so fresh dev installs don't share the
                # same default credentials across machines.
                password = getattr(settings, password_key, "")
                if not password or password in _LEGACY_WEAK_PASSWORDS:
                    if not dev_mode:
                        raise RuntimeError(
                            f"P1-SEC-06: {username} password is unset or uses a "
                            "weak legacy default. Set " + password_key + " in "
                            ".env (>=12 chars, not in the weak list) before "
                            "running init_schema()."
                        )
                    password = secrets.token_urlsafe(16)
                    passwords_used.append((username, password))
                if len(password) < 12:
                    if not dev_mode:
                        raise RuntimeError("P1-SEC-06: " + password_key + " must be >= 12 chars")
                await conn.execute(
                    "INSERT INTO users (username, hashed_password, role) VALUES ($1, $2, $3)",
                    username,
                    pwd.hash(password),
                    role,
                )
            logger.info(
                "pg_default_users_seeded",
                count=len(_DEFAULT_USERS),
                dev_mode=dev_mode,
            )
            if dev_mode and passwords_used:
                # Print once at startup so the operator can copy-paste.
                for username, password in passwords_used:
                    logger.warning(
                        "dev_password_issued",
                        user=username,
                        password=password,
                        note="Set the matching env var to pin a password",
                    )


async def close_pool() -> None:
    global _pool
    if _pool is not None:
        await _pool.close()
        _pool = None
        logger.info("pg_pool_closed")
