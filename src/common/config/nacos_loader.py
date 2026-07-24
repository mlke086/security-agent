"""Nacos 配置中心集成 -- 全量配置从 Nacos 拉取,env 覆盖 Nacos,Nacos 变更热更新。

加载优先级: 容器环境变量 > Nacos > .env 文件 > 代码默认值
- 容器 env(如 NACOS_SERVER)决定是否启用 Nacos
- 启用 Nacos 时,全量配置从 Nacos 拉取注入 env
- **白名单保护**:对凭据类(API_SECRET_KEY / AGENT_SIGNING_KEY /
  AGENT_HMAC_KEY / 各种密码),若容器或 CI 已经显式注入 env 值,Nacos
  不能覆盖它。对服务地址类(PG_HOST / REDIS_URL / ES_HOSTS 等),
  Nacos 可以覆盖 -- 这是部署到新机器的必需特性。
- Nacos 配置变更时,通过定时轮询监听,热更新 Settings 单例

历史 bug 修复记录(对比 v1):
- v1 用模块级 `_pre_existing_env = set(os.environ.keys())` 做"全量
  保护",导致 docker-compose 的 `x-bootstrap-env`(把 127.0.0.1 写死)
  反向压制 Nacos 里配置的新地址。改为下面的 PROTECTED_OVERRIDE_KEYS
  显式白名单。
- v1 强制 `key.upper()` 写 env,与 Settings `case_sensitive=False`
  不一致,nacos-config.yaml 里写 `pgHost` / `redis-url` 时会被静默
  丢弃。改为走 Settings 字段表归一化。
- v1 轮询 hash 用 `md5(str(sorted(items())))`,嵌套 dict 时 repr
  顺序不稳。改为 `sha256(json.dumps(..., sort_keys=True, default=str))`。
"""

import asyncio
import hashlib
import json
import os
import re
from typing import Any

import httpx

from src.common.logging.logger import get_logger

logger = get_logger(__name__)

# Nacos 长轮询监听任务句柄
_listener_task: asyncio.Task | None = None


# ---- 白名单:这些 key 即使 Nacos 配了,也不能覆盖容器/CI 显式注入的 env ----
# 原则:只保护"凭据类",不保护"地址类"。CI Secret / KMS 注入的才是
# 真正的签名材料;Nacos 全员可读写,不能让它静默替换。服务地址反过来
# -- 同一份 nacos-config.yaml 应该能驱动新机器,不必回头改 docker-compose。
PROTECTED_OVERRIDE_KEYS: frozenset[str] = frozenset({
    # JWT / 签名材料
    "API_SECRET_KEY",
    "AGENT_SIGNING_KEY",
    "AGENT_HMAC_KEY",
    # 数据库 / 中间件 凭据(注意 URL 本身不在此列)
    "PG_PASSWORD",
    "REDIS_PASSWORD",
    "NACOS_PASSWORD",
    # 种子用户口令
    "DEFAULT_ADMIN_PASSWORD",
    "DEFAULT_ANALYST_PASSWORD",
    "DEFAULT_VIEWER_PASSWORD",
    "DEFAULT_RESPONDER_PASSWORD",
    # 第三方 API 凭据
    "VIRUSTOTAL_API_KEY",
    "ALIENVAULT_OTX_API_KEY",
    "NVD_API_KEY",
    # LLM 凭据
    "ANTHROPIC_API_KEY",
    "OPENAI_API_KEY",
})


def _make_client(timeout: float = 10.0) -> httpx.AsyncClient:
    """Construct an httpx client that explicitly does NOT trust proxy env vars.

    Nacos is always reached via loopback (127.0.0.1) or an internal/private
    network. If the runtime container inherits HTTP_PROXY/HTTPS_PROXY from
    build args (e.g. `docker build --build-arg HTTPS_PROXY=...`), httpx with
    `trust_env=True` would route these connections through the proxy -- where
    127.0.0.1 is unreachable. The downstream symptom is `nacos_config_unavailable`
    with an empty `error=""` because httpx 0.27.x swallows the original
    message in that specific failure shape.

    Disabling trust_env is safe: we are talking to Nacos over a network
    namespace where the operator already controlled routing. If a future
    deployment genuinely needs an HTTP proxy for Nacos traffic, expose this
    via a dedicated NACOS_HTTP_PROXY config var instead of relying on the
    global env, so this bug cannot recur silently.
    """
    return httpx.AsyncClient(timeout=timeout, trust_env=False)


def _format_exception(exc: BaseException) -> dict:
    """Normalize an exception into a log-friendly dict.

    str(exc) can be empty for some httpx / stdlib exceptions; this fallback
    chain ensures we always emit something actionable: type name, then repr,
    then str, then a sentinel so operators can grep.
    """
    msg = str(exc)
    if not msg:
        msg = repr(exc)
    return {
        "error": msg or type(exc).__name__,
        "error_type": type(exc).__name__,
        "error_repr": repr(exc),
    }


async def _nacos_login(client: httpx.AsyncClient, base: str, username: str, password: str) -> str:
    """登录 Nacos 获取 accessToken。Nacos 未开鉴权时返回空。"""
    try:
        r = await client.post(
            f"{base}/nacos/v1/auth/login",
            data={"username": username, "password": password},
        )
        if r.status_code == 200:
            return r.json().get("accessToken", "")
    except Exception:
        pass
    return ""


async def fetch_nacos_config(
    server: str,
    data_id: str,
    group: str = "DEFAULT_GROUP",
    namespace: str = "public",
    username: str = "nacos",
    password: str = "nacos",
    timeout: float = 10.0,
) -> dict[str, Any]:
    """从 Nacos 拉取 YAML 配置并解析成 dict。失败时返回空 dict(不阻断启动)。"""
    if not server:
        return {}
    base = server.rstrip("/")
    try:
        async with _make_client(timeout=timeout) as client:
            token = await _nacos_login(client, base, username, password)
            headers = {"accessToken": token} if token else {}

            r = await client.get(
                f"{base}/nacos/v3/admin/cs/config",
                params={"dataId": data_id, "groupName": group, "namespaceId": namespace},
                headers=headers,
            )
            if r.status_code != 200:
                logger.warning("nacos_config_fetch_failed", status=r.status_code, body=r.text[:200])
                return {}

            data = r.json()
            if data.get("code") != 0:
                logger.warning("nacos_config_error", code=data.get("code"), msg=data.get("message"))
                return {}

            content = data.get("data", {}).get("content", "")
            if not content:
                return {}

            import yaml

            config = yaml.safe_load(content)
            if not isinstance(config, dict):
                return {}

            logger.info("nacos_config_loaded", keys=len(config), data_id=data_id)
            return {k: v for k, v in config.items() if v is not None}

    except Exception as exc:
        logger.warning("nacos_config_unavailable", **_format_exception(exc))
        return {}


def _normalize_env_key(raw_key: str, valid_keys: set[str]) -> str | None:
    """Map a Nacos yaml key to its canonical Settings field name.

    Returns None when the key does not correspond to any field. Caller is
    responsible for converting the returned canonical name to env-var form
    via `.upper()`.

    Settings uses lowercase_with_underscore field names internally; env vars
    are conventionally UPPERCASE. pydantic-settings with case_sensitive=False
    accepts either, but we need a single canonical form so that
    PROTECTED_OVERRIDE_KEYS membership checks and Settings field validation
    agree.

    Handles four styles, all normalized to the same canonical name:
        `pg_host`, `PG_HOST`, `pgHost`, `pg-host` -> `pg_host`
    """
    case_map = {k.lower(): k for k in valid_keys}
    lookup = raw_key.lower()
    if lookup in case_map:
        return case_map[lookup]
    snake = re.sub(r"(?<!^)(?=[A-Z])", "_", raw_key.replace("-", "_")).lower()
    if snake in case_map:
        return case_map[snake]
    return None

def apply_nacos_overrides(nacos_config: dict[str, Any]) -> dict[str, list[str]]:
    """把 Nacos 配置注入 os.environ。

    优先级:容器/CI 显式注入的 env(白名单内) > Nacos > .env 文件 > 代码默认值。

    返回一个 summary dict,便于测试和日志观察:
        {"applied": [...], "skipped_protected": [...], "unrecognized": [...]}
    """
    # 延迟导入:settings.py 也对 nacos_loader 做延迟 import,这里必须在
    # 调用时再 import settings.py,否则两个模块互锁。
    from src.common.config.settings import Settings

    valid_keys: set[str] = set(Settings.model_fields.keys())
    applied: list[str] = []
    skipped_protected: list[str] = []
    unrecognized: list[str] = []

    for raw_key, value in nacos_config.items():
        if value is None:
            continue  # YAML null is "comment this out"; do not blank env.
        canonical = _normalize_env_key(raw_key, valid_keys)
        if canonical is None:
            # Unknown key: still inject into env (so accidentally-correct
            # keys do work) but flag for the operator via `unrecognized`.
            unrecognized.append(raw_key)
            os.environ[raw_key.upper()] = str(value)
            continue
        # canonical is Settings.model_field name (lowercase). The env var
        # form is uppercase, which is what PROTECTED_OVERRIDE_KEYS uses
        # and what pydantic-settings case_sensitive=False matches.
        env_key = canonical.upper()
        if env_key in PROTECTED_OVERRIDE_KEYS and env_key in os.environ:
            skipped_protected.append(env_key)
            continue
        os.environ[env_key] = str(value)
        applied.append(env_key)

    summary = {
        "applied": applied,
        "skipped_protected": skipped_protected,
        "unrecognized": unrecognized,
    }
    logger.info(
        "nacos_overrides_applied",
        applied=len(applied),
        skipped_protected=len(skipped_protected),
        unrecognized=len(unrecognized),
    )
    if unrecognized:
        logger.warning(
            "nacos_overrides_unrecognized_keys",
            keys=unrecognized[:20],
            hint="检查 nacos-config.yaml 是否有拼错的 key,或 Settings 字段已重命名",
        )
    return summary


def _config_fingerprint(nacos_config: dict[str, Any]) -> str:
    """对 Nacos 配置内容做稳定 hash,用于变更检测。

    替换 v1 的 `md5(str(sorted(items())))` -- 嵌套 dict 现在能稳定散列,
    跟字段插入顺序无关。
    """
    return hashlib.sha256(
        json.dumps(nacos_config, sort_keys=True, default=str).encode()
    ).hexdigest()


async def start_nacos_listener() -> None:
    """启动 Nacos 配置变更监听(定时轮询模式),热更新 Settings。

    Nacos v3 的长轮询 API 路径与 v1 不兼容,改用定时轮询:每 30s 拉取
    配置内容,对比 hash,变更时重建 Settings 单例(无需重启)。

    多 worker 模型下,各 worker 进程独立持有一份 Settings 单例,
    hot reload 只影响发起 reload 的那个 worker。
    """
    global _listener_task
    from src.common.config.settings import get_settings

    s = get_settings()
    if not s.nacos_server:
        return

    async def _poll():
        last_fingerprint = ""
        while True:
            try:
                nacos_config = await fetch_nacos_config(
                    s.nacos_server,
                    s.nacos_data_id,
                    s.nacos_group,
                    s.nacos_namespace,
                    s.nacos_username,
                    s.nacos_password,
                )
                if nacos_config:
                    fp = _config_fingerprint(nacos_config)
                    if fp != last_fingerprint:
                        if last_fingerprint:  # 跳过首次(只是记录基线)
                            logger.info("nacos_config_changed_hot_reloading")
                            summary = apply_nacos_overrides(nacos_config)
                            from src.common.config.settings import reload_settings

                            reload_settings()
                            logger.info(
                                "nacos_config_reloaded",
                                keys=len(nacos_config),
                                applied=len(summary["applied"]),
                                skipped=len(summary["skipped_protected"]),
                            )
                        last_fingerprint = fp
                await asyncio.sleep(30)
            except asyncio.CancelledError:
                break
            except Exception as exc:
                logger.warning("nacos_poller_error", **_format_exception(exc))
                await asyncio.sleep(30)

    _listener_task = asyncio.create_task(_poll(), name="nacos-poller")
    logger.info("nacos_config_poller_started")


def stop_nacos_listener() -> None:
    """停止 Nacos 监听(lifespan shutdown 时调用)。"""
    global _listener_task
    if _listener_task:
        _listener_task.cancel()
        _listener_task = None
