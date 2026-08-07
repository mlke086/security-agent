"""scan-engine 服务:启动 TaskWorker 消费 Redis Stream 跑 LangGraph 流水线。

阶段 0-5 骨架:仅含 FastAPI app + /healthz,阶段 2 填充 TaskWorker lifespan。
"""
