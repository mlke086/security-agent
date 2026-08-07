"""asset-scan 服务 (需求②: 内网资产扫描, agentless, fscan 类)。

独立第 7 个服务：消费 ``assetscan:queue:tasks`` 流，用 nmap/masscan/
nuclei 子进程做内网资产发现 → 指纹识别 → CVE 匹配 → AI 分析 → 报告。
镜像仅含本包 + orchestration/subgraphs/asset_scan（不拖入 vulnscan
的 agent 依赖），并依赖系统包 nmap/masscan/nuclei。
"""
