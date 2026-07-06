from typing import Literal

from pydantic import Field
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
    vllm_base_url: str = "http://localhost:8000"
    vllm_model: str = "qwen2.5-72b"

    # Kafka
    kafka_bootstrap_servers: str = "localhost:9092"
    kafka_topic_raw_alerts: str = "raw-alerts"
    kafka_topic_dlq: str = "dead-letter-queue"
    kafka_consumer_group: str = "security-agent-group"

    # Milvus
    milvus_host: str = "localhost"
    milvus_port: int = 19530
    milvus_collection: str = "threat_intel"

    # Neo4j
    neo4j_uri: str = "bolt://localhost:7687"
    neo4j_user: str = "neo4j"
    neo4j_password: str = "changeme"

    # Redis
    redis_url: str = "redis://localhost:6379/0"
    redis_cache_ttl: int = 3600

    # Elasticsearch
    es_hosts: str = "http://localhost:9200"
    es_index_audit: str = "security-agent-audit"
    es_index_events: str = "security-agent-events"

    # Threat Intel APIs
    virustotal_api_key: str = ""
    alienvault_otx_api_key: str = ""

    # Notification webhooks
    wechat_work_webhook: str = ""
    dingtalk_webhook: str = ""

    # FastAPI
    api_secret_key: str = Field(default="change-me", min_length=16)
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


_settings: Settings | None = None


def get_settings() -> Settings:
    global _settings
    if _settings is None:
        _settings = Settings()
    return _settings
