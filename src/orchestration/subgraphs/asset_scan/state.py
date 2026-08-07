"""Asset-scan subgraph state TypedDict (需求②)."""

from typing import TypedDict


class AssetScanState(TypedDict):
    """agentless 资产扫描子图状态。

    所有阶段产物必须显式声明（LangGraph 会静默丢弃未声明键），
    与 vulnscan 子图的教训一致。
    """

    task_id: str
    source: str
    targets: list[str]      # CIDR / IP 列表
    ports: list[int]        # 显式端口（空 = 引擎默认）
    engine: str             # fast / full / global
    modules: list[str]      # discovery / fingerprint / cve / nuclei / brute
    schedule: str
    actor: str

    # discover 阶段产物
    alive_hosts: list[str]
    host_ports: dict[str, list[int]]

    # fingerprint 阶段产物
    services: list[dict]

    # match_vulns 阶段产物
    vulns: list[dict]
    ai_results: list[dict]

    # report 阶段产物
    report: dict | None

    # 任务跟踪
    status: str
    error: str | None
    ai_processed: bool
