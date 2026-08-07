"""graphrag 服务:唯一含 torch 的重镜像,暴露 /embed /vector-search /graph-query /memory/* HTTP API。

阶段 0-5 骨架:仅含 FastAPI app + /healthz,阶段 1 填充路由 + MemoryManager 迁入。
"""
