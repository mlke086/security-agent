"""弱口令爆破模块（需求②: 可选, 默认关闭）。

v1 仅占位：`enabled` 为 False 时子图跳过本阶段。启用时需要外部
凭证字典与目标策略（SSH/Redis/MySQL 等常见服务探测），并配合
失败锁定保护——属高危操作，v2 再实现。
"""

from __future__ import annotations

from typing import Any


def enabled(modules: list[str] | None) -> bool:
    """modules 含 'brute' 且环境变量 SECAGENT_ASSET_BRUTE=1 才启用。"""
    import os

    return bool(modules and "brute" in modules) and os.environ.get("SECAGENT_ASSET_BRUTE") == "1"


async def run_brute(host_ports: dict[str, list[int]], **_: Any) -> list[dict[str, Any]]:
    """占位实现：永不返回结果（调用方在 enabled() 为 False 时不调用）。"""
    return []
