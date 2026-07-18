from typing import Literal

from pydantic import Field, model_validator
from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    model_config = SettingsConfigDict(
        env_file=".env",
        env_file_encoding="utf-8",
        case_sensitive=False,
        extra="ignore",
    )

    # LLM
    llm_provider: Literal["claude", "openai", "vllm"] = "claude"
    anthropic_api_key: str = ""
    openai_api_key: str = ""
    openai_base_url: str = ""
    openai_model: str = "gpt-4o"
    vllm_base_url: str = "http://192.168.80.101:8000"
    vllm_model: str = "qwen2.5-72b"

    # Kafka
    kafka_bootstrap_servers: str = "192.168.80.101:9092"
    kafka_topic_raw_alerts: str = "raw-alerts"
    kafka_topic_dlq: str = "dead-letter-queue"
    kafka_consumer_group: str = "security-agent-group"

    # Milvus
    milvus_host: str = "192.168.80.101"
    milvus_port: int = 19530
    milvus_collection: str = "threat_intel"
    milvus_score_threshold: float = 0.65

    # Neo4j
    neo4j_uri: str = "bolt://192.168.80.101:7687"
    neo4j_user: str = "neo4j"
    neo4j_password: str = "neo4j_password_2026"

    # Redis
    redis_url: str = "redis://:redis_password_2026@192.168.80.101:6379/0"
    redis_cache_ttl: int = 3600

    # Elasticsearch
    es_hosts: str = "http://192.168.80.101:9200"
    es_index_audit: str = "security-agent-audit"
    es_index_events: str = "security-agent-events"

    # Threat Intel APIs
    virustotal_api_key: str = ""
    alienvault_otx_api_key: str = ""

    # Notification webhooks
    wechat_work_webhook: str = ""
    dingtalk_webhook: str = ""

    # FastAPI —— 去掉 min_length，避免空值触发晦涩的 string_too_short
    api_secret_key: str = Field(
        default="",
        description="JWT signing key. 必须通过环境变量 API_SECRET_KEY 设置，≥16 位。",
    )
    api_access_token_expire_minutes: int = 120
    api_refresh_token_expire_days: int = 7
    api_host: str = "0.0.0.0"
    api_port: int = 8000

    # Sandbox
    sandbox_container_pool_size: int = 5
    sandbox_exec_timeout_sec: int = 60
    sandbox_network: str = "sandbox-net"

    # Logging
    log_level: Literal["DEBUG", "INFO", "WARNING", "ERROR"] = "INFO"

    # Action execution
    action_dry_run: bool = True

    # Pipeline
    pipeline_concurrency: int = 4

    # Event store backend: "es" (persistent, multi-worker) or "memory" (demo/test)
    store_backend: Literal["memory", "es", "pg"] = "es"

    # HITL approval wait timeout override (seconds); 0 = use per-level defaults (L3=300...)
    hitl_timeout_sec: int = 0

    # PostgreSQL (Phase 1 persistence: users/tokens/approvals)
    pg_host: str = "192.168.80.101"
    pg_port: int = 5432
    pg_database: str = "SecAgent"
    pg_user: str = "secagent"
    pg_password: str = "Ke615700"
    pg_pool_size: int = 10
    # -- Agent / Vulnscan subsystem --
    agent_console_external_url: str = "https://192.168.80.101:8000"
    agent_tls_cert: str = ""
    agent_tls_key: str = ""
    agent_ca_cert: str = ""
    agent_signing_key: str = ""
    agent_heartbeat_interval: int = 60
    agent_binary_dir: str = "deployments/agent/dist"
    rules_sync_source: str = "nvd"
    rules_sync_cron: str = "0 3 * * *"


    @model_validator(mode="after")
    def _validate_api_secret_key(self) -> "Settings":
        if len(self.api_secret_key) < 16:
            raise ValueError(
                "API_SECRET_KEY 未设置或不足 16 位，请通过环境变量或 .env 配置 "
                "(生产环境建议由 KMS 注入)。"
            )
        return self


_settings: Settings | None = None


def get_settings() -> Settings:
    global _settings
    if _settings is None:
        _settings = Settings()
    return _settings
