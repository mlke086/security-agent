"""Nacos 配置中心集成 -- 全量配置从 Nacos 拉取，env 覆盖 Nacos，Nacos 变更热更新。

加载优先级: 容器环境变量 > Nacos > .env 文件 > 代码默认值
- 容器 env（如 NACOS_SERVER）决定是否启用 Nacos
- 启用 Nacos 时，全量配置从 Nacos 拉取注入 env
- 已有的容器 env（显式注入的）不被 Nacos 覆盖（env > Nacos）
- Nacos 配置变更时，通过长轮询监听，热更新 Settings 单例
"""

import asyncio
import os
from typing import Any

import httpx

from src.common.logging.logger import get_logger

logger = get_logger(__name__)

# Nacos 长轮询监听任务
_listener_task: asyncio.Task | None = None


async def _nacos_login(client: httpx.AsyncClient, base: str, username: str, password: str) -> str:
    """登录 Nacos 获取 accessToken。未开鉴权时返回空。"""
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
    """从 Nacos 拉取 YAML 配置并解析成 dict。失败时返回空 dict（不阻断启动）。"""
    if not server:
        return {}
    base = server.rstrip("/")
    try:
        async with httpx.AsyncClient(timeout=timeout) as client:
            token = await _nacos_login(client, base, username, password)
            headers = {"accessToken": token} if token else {}

            r = await client.get(
                f"{base}/nacos/v3/admin/cs/config",
                params={"dataId": data_id, "groupName": group, "namespaceId": namespace},
                headers=headers,
            )
            if r.status_code != 200:
                logger.warning("nacos_config_fetch_failed", status=r.status_code, body=r.text[:100])
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
        logger.warning("nacos_config_unavailable", error=str(exc))
        return {}


# 启动前 os.environ 的快照（区分"容器注入的 env"和"Nacos 注入的 env"）
_pre_existing_env: set[str] = set(os.environ.keys())


def apply_nacos_overrides(nacos_config: dict[str, Any]) -> None:
    """把 Nacos 配置注入 os.environ。

    容器显式注入的环境变量 > Nacos > .env 文件 > 代码默认值。
    不覆盖容器启动前已存在的 env（这些是容器/k8s 显式注入的，优先级最高）。
    """
    for key, value in nacos_config.items():
        env_key = key.upper()
        if env_key in _pre_existing_env:
            continue  # 容器/k8s 显式注入的 env，不被 Nacos 覆盖
        os.environ[env_key] = str(value)


async def start_nacos_listener() -> None:
    """启动 Nacos 配置变更监听（定时轮询模式），热更新 Settings。

    Nacos v3 的长轮询 API 路径与 v1 不兼容，改用定时轮询：每 30s 拉取配置
    内容，对比 hash，变更时重建 Settings 单例（无需重启）。
    """
    global _listener_task
    from src.common.config.settings import get_settings

    s = get_settings()
    if not s.nacos_server:
        return

    async def _poll():
        import hashlib

        last_hash = ""
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
                    current_hash = hashlib.md5(
                        str(sorted(nacos_config.items())).encode()
                    ).hexdigest()
                    if current_hash != last_hash:
                        if last_hash:  # 非首次
                            logger.info("nacos_config_changed, hot reloading")
                            apply_nacos_overrides(nacos_config)
                            from src.common.config.settings import reload_settings

                            reload_settings()
                            logger.info("nacos_config_reloaded", keys=len(nacos_config))
                        last_hash = current_hash
                await asyncio.sleep(30)
            except asyncio.CancelledError:
                break
            except Exception as exc:
                logger.warning("nacos_poller_error", error=str(exc))
                await asyncio.sleep(30)

    _listener_task = asyncio.create_task(_poll(), name="nacos-poller")
    logger.info("nacos_config_poller_started")


def stop_nacos_listener() -> None:
    """停止 Nacos 监听（lifespan shutdown 时调用）。"""
    global _listener_task
    if _listener_task:
        _listener_task.cancel()
        _listener_task = None
