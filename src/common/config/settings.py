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
    # P1-API-03: comma-separated CORS allowlist. Empty falls back to
    # defaults (console URL + localhost dev origins). Set to "*" only
    # when also disabling credentials.
    allowed_origins: str = ""

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
    # P2-1 修复：Ed25519 私钥（64 hex），用于签 WS 敏感命令 + 规则包 body。
    agent_signing_key: str = ""
    # P2-1 修复：规则包 HMAC-SHA256 密钥（任意串），与 Ed25519 私钥分离。
    # 留空时回退到 agent_signing_key（向后兼容旧部署），但推荐单独配置。
    agent_hmac_key: str = ""
    # V4.1 (P0-2): agent-side debug toggle. Mirrors the Go-side
    # AGENT_DEBUG=1 env var -- when True, the Python signing layer
    # logs the canonical signed payload (otherwise silent so the
    # raw payload never lands in INFO-level journalctl / ES audit).
    agent_debug: bool = False
    agent_heartbeat_interval: int = 60
    agent_binary_dir: str = "deployments/agent/dist"
    rules_sync_source: str = "nvd"
    rules_sync_cron: str = "0 3 * * *"
    # 需求2.2：规则数据源。nvd=NVD API(国外,带key); github=GitHub advisory-database
    # (国内可访问 GitHub)。离线导入另支持 NVD json / advisory zip / rulepack。
    nvd_api_key: str = ""  # NVD API key，提升限速(50req/30s)，留空走匿名(5req/30s)
    nvd_proxy: str = ""  # NVD 代理(国内访问超时时配，如 http://192.168.254.121:7897)
    # GitHub Advisory 在线同步：拉取近 N 天的 reviewed advisory，避免全量 28530 条。
    advisory_lookback_days: int = 30

    # P1-SEC-05/06 (2026-07-20): env-driven seed passwords. Production
    # deployments MUST set all four to >=12 char non-trivial values; the
    # seeder refuses to start otherwise. ``dev_mode=true`` relaxes the
    # check and issues a random per-process password logged at startup.
    dev_mode: bool = False
    default_admin_password: str = ""
    default_analyst_password: str = ""
    default_viewer_password: str = ""
    default_responder_password: str = ""

    # === Nacos 配置中心 ===
    # Nacos 自身连接信息（环境变量，不进 Nacos -- 鸡生蛋问题）
    nacos_server: str = ""  # 如 http://192.168.80.101:8848
    nacos_data_id: str = "security-agent.yaml"
    nacos_group: str = "security"
    nacos_namespace: str = "prod"
    nacos_username: str = "nacos"
    nacos_password: str = "nacos"

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
    """返回单例 Settings。

    加载顺序：代码默认值 <- .env <- Nacos(注入env) <- 容器环境变量(最高优先级)
    Nacos 配置在 load_nacos_settings() 后注入 env 并重建单例。
    """
    global _settings
    if _settings is None:
        _settings = Settings()
    return _settings


def reload_settings() -> None:
    """重建 Settings 单例（Nacos 配置变更热更新时调用）。"""
    global _settings
    _settings = Settings()


async def load_nacos_settings() -> None:
    """从 Nacos 拉取全量配置注入 env，然后重建 Settings 单例。

    在 FastAPI lifespan 中调用（异步环境）。如果 nacos_server 未配置则跳过
    （使用 .env 文件 + 代码默认值）。
    容器显式注入的环境变量优先级最高，不被 Nacos 覆盖。
    """
    global _settings
    # 先用当前 settings 读 nacos 连接信息
    s = _settings or Settings()
    if not s.nacos_server:
        return  # 未配置 Nacos，用 .env + 默认值

    from src.common.config.nacos_loader import (
        apply_nacos_overrides,
        fetch_nacos_config,
        start_nacos_listener,
    )

    nacos_config = await fetch_nacos_config(
        server=s.nacos_server,
        data_id=s.nacos_data_id,
        group=s.nacos_group,
        namespace=s.nacos_namespace,
        username=s.nacos_username,
        password=s.nacos_password,
    )
    if nacos_config:
        apply_nacos_overrides(nacos_config)
        # 重建 Settings（env 已被 Nacos 填充，容器显式 env 保留最高优先级）
        reload_settings()
        from src.common.logging.logger import get_logger as _gl

        _gl(__name__).info("settings_reloaded_from_nacos", keys=len(nacos_config))
        # 启动配置变更监听（热更新）
        await start_nacos_listener()
