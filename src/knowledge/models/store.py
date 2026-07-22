"""LLM model registry storage (需求4 模型管理).

PG-backed CRUD for model provider configs. The ModelAdapter reads the default
model (or a caller-specified model_id) from here at call time, so operators can
add / switch / default models from the UI without restarting or editing .env.

On first access, if the table is empty we migrate the current .env LLM config
into one default row so existing deployments keep working unchanged.
"""

from __future__ import annotations

from dataclasses import dataclass

from src.common.config.settings import get_settings
from src.common.logging.logger import get_logger

logger = get_logger(__name__)


@dataclass
class ModelConfig:
    """A single model provider configuration (DB row -> in-memory)."""

    id: int
    name: str
    provider: str  # openai | claude | vllm
    model_name: str
    api_key: str
    base_url: str
    temperature: float
    max_tokens: int
    supports_structured: bool
    enabled: bool
    is_default: bool


async def _pg_conn():
    from src.common.db.pg import get_pg_pool as _get_pool

    pool = await _get_pool()
    return pool.acquire()


def _row_to_config(row) -> ModelConfig:
    return ModelConfig(
        id=row["id"],
        name=row["name"],
        provider=row["provider"],
        model_name=row["model_name"],
        api_key=row["api_key"] or "",
        base_url=row["base_url"] or "",
        temperature=float(row["temperature"]),
        max_tokens=int(row["max_tokens"]),
        supports_structured=bool(row["supports_structured"]),
        enabled=bool(row["enabled"]),
        is_default=bool(row["is_default"]),
    )


async def list_models() -> list[ModelConfig]:
    """List all model configs ordered: default first, then by id."""
    async with await _pg_conn() as conn:
        rows = await conn.fetch("SELECT * FROM llm_models ORDER BY is_default DESC, id ASC")
    return [_row_to_config(r) for r in rows]


async def get_model(model_id: int) -> ModelConfig | None:
    async with await _pg_conn() as conn:
        row = await conn.fetchrow("SELECT * FROM llm_models WHERE id=$1", model_id)
    return _row_to_config(row) if row else None


async def get_default_model() -> ModelConfig | None:
    """Return the global default model, or None if none is set / table empty."""
    async with await _pg_conn() as conn:
        row = await conn.fetchrow("SELECT * FROM llm_models WHERE is_default=TRUE LIMIT 1")
        if not row:
            # No explicit default: fall back to first enabled model.
            row = await conn.fetchrow(
                "SELECT * FROM llm_models WHERE enabled=TRUE ORDER BY id ASC LIMIT 1"
            )
    return _row_to_config(row) if row else None


async def create_model(
    name: str,
    provider: str,
    model_name: str,
    api_key: str = "",
    base_url: str = "",
    temperature: float = 0.1,
    max_tokens: int = 4096,
    supports_structured: bool = True,
    enabled: bool = True,
    is_default: bool = False,
) -> ModelConfig:
    async with await _pg_conn() as conn:
        # Only one default allowed: clear any existing default first.
        if is_default:
            await conn.execute("UPDATE llm_models SET is_default=FALSE WHERE is_default")
        row = await conn.fetchrow(
            """INSERT INTO llm_models
               (name, provider, model_name, api_key, base_url, temperature,
                max_tokens, supports_structured, enabled, is_default)
               VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10)
               RETURNING *""",
            name,
            provider,
            model_name,
            api_key,
            base_url,
            temperature,
            max_tokens,
            supports_structured,
            enabled,
            is_default,
        )
    logger.info("llm_model_created", name=name, provider=provider, model=model_name)
    return _row_to_config(row)


async def update_model(model_id: int, **fields) -> ModelConfig | None:
    allowed = {
        "name",
        "provider",
        "model_name",
        "api_key",
        "base_url",
        "temperature",
        "max_tokens",
        "supports_structured",
        "enabled",
    }
    async with await _pg_conn() as conn:
        sets: list[str] = ["updated_at=NOW()"]
        params: list = [model_id]
        idx = 1
        for k, v in fields.items():
            if k in allowed and v is not None:
                idx += 1
                sets.append(f"{k}=${idx}")
                params.append(v)
        if len(sets) > 1:
            await conn.execute(f"UPDATE llm_models SET {', '.join(sets)} WHERE id=$1", *params)
        row = await conn.fetchrow("SELECT * FROM llm_models WHERE id=$1", model_id)
    return _row_to_config(row) if row else None


async def delete_model(model_id: int) -> bool:
    async with await _pg_conn() as conn:
        result = await conn.execute("DELETE FROM llm_models WHERE id=$1", model_id)
    # asyncpg returns 'DELETE n' style status
    return result.endswith(" 1") or result == "DELETE 1"


async def set_default_model(model_id: int) -> ModelConfig | None:
    async with await _pg_conn() as conn:
        row = await conn.fetchrow("SELECT id FROM llm_models WHERE id=$1", model_id)
        if not row:
            return None
        await conn.execute("UPDATE llm_models SET is_default=FALSE WHERE is_default")
        await conn.execute(
            "UPDATE llm_models SET is_default=TRUE, enabled=TRUE, updated_at=NOW() WHERE id=$1",
            model_id,
        )
        row = await conn.fetchrow("SELECT * FROM llm_models WHERE id=$1", model_id)
    logger.info("llm_model_set_default", model_id=model_id)
    return _row_to_config(row) if row else None


async def migrate_env_model_if_empty() -> None:
    """On first run, seed the table from the current .env LLM config so
    existing deployments keep working without manual re-entry.

    Called lazily from the adapter the first time it needs a default model.
    Safe to call multiple times (no-op once a row exists)."""
    async with await _pg_conn() as conn:
        count = await conn.fetchval("SELECT COUNT(*) FROM llm_models")
        if count:
            return
        s = get_settings()
        provider = s.llm_provider
        if provider == "claude":
            name = "Claude (env)"
            model_name = "claude-sonnet-4-5"
            api_key = s.anthropic_api_key
            base_url = ""
        elif provider == "vllm":
            name = "vLLM (env)"
            model_name = s.vllm_model
            api_key = s.openai_api_key or "EMPTY"
            base_url = s.vllm_base_url
        else:  # openai (DeepSeek / etc.)
            name = f"{s.openai_model} (env)"
            model_name = s.openai_model
            api_key = s.openai_api_key
            base_url = s.openai_base_url
        await conn.execute(
            """INSERT INTO llm_models
               (name, provider, model_name, api_key, base_url, temperature,
                max_tokens, supports_structured, enabled, is_default)
               VALUES ($1,$2,$3,$4,$5,0.1,4096,TRUE,TRUE,TRUE)""",
            name,
            provider,
            model_name,
            api_key,
            base_url,
        )
    logger.info("llm_model_migrated_from_env", provider=provider, model=model_name)
