"""阶段 4-2:preprocessing 服务的事件入队包(裁剪版)。

独立路径 ``src/preprocessing/vulnscan_queue/`` 而非复用
``src.orchestration.task_queue/`` —— 后者会被 gateway 镜像携带,
PEP 562 lazy 化后仍可能有路径依赖风险。独立路径保证:

- preprocessing 镜像只 COPY 本目录 + preprocessing/ + common/
- 不依赖 orchestration/ 任何模块
- 跨服务契约唯一常量:EVENT_STREAM = "events:tasks"
"""
