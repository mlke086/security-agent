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
    neo4j_password: str = ""  # V13 D0-1: no default credential; must come from env

    # Redis
    redis_url: str = ""  # V13 D0-1: no default credential; must come from env
    redis_cache_ttl: int = 3600

    # Elasticsearch
    es_hosts: str = "http://192.168.80.101:9200"
    es_index_audit: str = "security-agent-audit"
    es_index_events: str = "security-agent-events"

    # Threat Intel APIs
    virustotal_api_key: str = ""
    alienvault_otx_api_key: str = ""
    # V13: AI search-agent 实时检索。两个独立开关：哪个 enabled=true 就用哪个
    # （serper 优先）；都 false = 关闭搜索（回退 LLM 直答）。额度按次计费，
    # 仅实时性问题才触发，见 chat.py _needs_realtime 门控。
    serper_enabled: bool = False
    tavily_enabled: bool = False
    serper_api_key: str = ""
    tavily_api_key: str = ""

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
    pg_password: str = ""  # V13 D0-1: no default credential; must come from env
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
    # Default Agent version stamped onto freshly built binaries. The actual
    # upgrade payload reads deployments/agent/dist/VERSION first; this value
    # is the fallback when that file is missing.
    # Default Agent version stamped onto freshly built binaries. The actual
    # upgrade payload reads deployments/agent/dist/VERSION first; this value
    # is the fallback when that file is missing.
    agent_binary_version: str = "0.1.0"
    # -- 需求①: host_metrics 性能指标（2026-08-06）--
    # 保留天数；超期由 gateway 的 _purge_metrics_loop 每 6h 清扫
    # （ES secagent-hostmetrics）。>500 主机或保留 >90d 时迁移
    # ClickHouse（HostMetricsStore 是替换点，端点/前端零改动）。
    metrics_retention_days: int = 30
    # 7d 查询的降采样桶宽（date_histogram fixed_interval），默认 5m
    # 把 ~4 万原始点压到 ~2k 点。
    metrics_downsample_7d_interval: str = "5m"
    # -- 需求②: asset-scan 服务（2026-08-06）--
    # agentless 内网资产扫描的并发/限速/超时。masscan/nmap 是网络密集
    # 工具，rate 保守默认，防止误伤生产网络；上线前按目标网络评估。
    asset_scan_concurrency: int = 2        # 同时运行的扫描子图数
    asset_scan_masscan_rate: int = 2000    # masscan 发包速率 pps
    asset_scan_nmap_max_rate: int = 100    # nmap --max-rate
    asset_scan_task_timeout_sec: int = 3600  # 单任务总超时（大网段可数十分钟）
    asset_scan_nuclei_severity: str = "critical,high,medium"  # nuclei 默认等级
    # Nuclei CLI 版本控制：内网下载站 base URL + 版本号。包名按约定拼接为
    # {base}/nuclei_{version}_{os}_{arch}.zip。Nacos 可热更新；安装脚本生成时
    # 嵌入，心跳路径据此对比 agent 上报版本，不一致则下发 nuclei_upgrade。
    # V12 阶段 5.2: 默认空串。内网下载站 URL/版本由 Nacos 热更新注入；
    # 硬编码内网 IP 在出厂部署中必然失效且是信息泄漏。runtime 已处理空
    # base URL（trigger_nuclei_upgrade 返回 early，_nuclei_templates_url 返回 ""）。
    nuclei_download_base_url: str = ""
    nuclei_version: str = ""
    # nuclei-templates 模板库版本。包名约定 {base}/nuclei-templates-{version}.zip。
    # 由规则页「同步 Nuclei 模板」按钮触发，服务端推 nuclei_templates_update 命令
    # 给在线 agent，agent 从内网下载站拉取并解压到 /opt/secagent/templates。
    # 模板库浏览/编辑存 ES（nuclei-templates 索引），不走 Nacos。
    nuclei_templates_version: str = ""
    rules_sync_source: str = "nvd"
    rules_sync_cron: str = "0 3 * * *"
    # 2026-07-31 UX upgrade ("漏洞清单整理 + 自动更新修复时间"): when enabled the
    # aggregate node reconciles new findings against stored vulns (one record
    # per host+vuln with scan_history) and auto-marks disappeared vulns as
    # fixed. Flip to false to roll back to the legacy plain-save behaviour.
    vuln_merge_enabled: bool = True
    # 需求2.2：规则数据源。nvd=NVD API(国外,带key); github=GitHub advisory-database
    # (国内可访问 GitHub)。离线导入另支持 NVD json / advisory zip / rulepack。
    nvd_api_key: str = ""  # NVD API key，提升限速(50req/30s)，留空走匿名(5req/30s)
    nvd_proxy: str = ""  # NVD 代理(国内访问超时时配，如 http://192.168.254.121:7897)
    # NVD HTTP 请求超时(秒)。NVD 响应慢或网络差时可调大，默认 30。
    nvd_timeout_sec: int = Field(default=30, ge=5, le=300)
    # V12 5.9 (2026-08-02): LLM 请求超时(秒)。langchain 底层 httpx 默认 30s，
    # "详细介绍某主机漏洞情况"这类长上下文回答容易触顶报
    # "timeout of 30000ms exceeded"。默认 120s。
    llm_request_timeout_sec: int = Field(default=120, ge=10, le=600)
    # ---- 2026-08-06 LLM 分析监控:漏洞分析/报告生成的超时·失败·重试参数 ----
    # 第一层:即时重试(单批调用失败后立刻重试)
    llm_analysis_retry_attempts: int = Field(default=2, ge=0, le=5)      # 即时重试次数
    llm_analysis_retry_backoff_sec: float = Field(default=2.0, ge=0.0, le=60.0)  # 即时重试退避(指数)
    # 第二层:空闲补扫(失败批次进 Redis,队列空闲时重新分析)
    llm_analysis_rescan_enabled: bool = True                              # 是否启用空闲补扫
    llm_analysis_rescan_check_interval_sec: int = Field(default=30, ge=5, le=600)  # 空闲检测周期
    llm_analysis_max_total_attempts: int = Field(default=10, ge=1, le=50)  # 每个失败批次累计最高尝试次数
    llm_analysis_busy_threshold: int = Field(default=0, ge=0, le=50)      # 活跃 LLM 调用 ≤ 此值视为空闲
    # 指标保留窗口(分钟):llm:usage / llm:failures 在 Redis 的 TTL
    llm_analysis_metrics_ttl_sec: int = Field(default=86400, ge=60, le=604800)
    # NVD 拉取最近 N 小时更新的 CVE；0 = 兜底走 DEFAULT_LOOKBACK_HOURS(模块常量)。
    nvd_lookback_hours: int = Field(default=24, ge=0, le=8760)
    # NVD 每页条数；服务端硬上限 2000，超出会 400。
    nvd_results_per_page: int = Field(default=100, ge=1, le=2000)
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
    # 阶段 0 必加:多 dataId 拆分(见 docs/分布式架构拆分方案.md 5.3)
    # 逗号分隔,如 "security-agent-shared.yaml,security-agent-gateway.yaml";
    # 为空时回退到单 nacos_data_id(向后兼容旧部署)
    nacos_data_ids: str = ""
    # 阶段 0 必加:服务地址配置(2.3 / 第七节)
    ai_base_url: str = "http://127.0.0.1:8001"
    graphrag_base_url: str = "http://127.0.0.1:8002"

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
        _fetch_all_data_ids,
        _resolve_data_ids,
        apply_nacos_overrides,
        start_nacos_listener,
    )

    data_ids = _resolve_data_ids(s)
    nacos_config = await _fetch_all_data_ids(s)
    if nacos_config:
        apply_nacos_overrides(nacos_config)
        # 重建 Settings（env 已被 Nacos 填充，容器显式 env 保留最高优先级）
        reload_settings()
        from src.common.logging.logger import get_logger as _gl

        _gl(__name__).info(
            "settings_reloaded_from_nacos",
            data_ids=data_ids,
            keys=len(nacos_config),
        )
        # 启动配置变更监听（热更新）
        await start_nacos_listener()
