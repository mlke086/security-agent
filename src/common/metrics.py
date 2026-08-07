"""阶段 5:/metrics 端点(prometheus_client 接入)。

各服务在自己的 FastAPI app 里 include 这个 router 即可:
    from src.common.metrics import metrics_router
    app.include_router(metrics_router)

暴露 process_* 默认指标(内存/CPU/GIL)+ 阶段 5 业务指标:
- ai_unreachable_total:gateway_proxy 调 ai 失败计数
- graphrag_embed_latency_seconds:graphrag /embed 处理耗时直方图
- taskworker_lag:scan-engine TaskWorker 消费 Redis Stream 的 lag
- approval_expired_lag:celery approval_timeout_task 执行延迟
"""
from __future__ import annotations

from fastapi import APIRouter, Response

try:
    from prometheus_client import (
        CONTENT_TYPE_LATEST,
        Counter,
        Gauge,
        Histogram,
        generate_latest,
    )

    _PROM_AVAILABLE = True
except ImportError:  # pragma: no cover
    _PROM_AVAILABLE = False

router = APIRouter(tags=["meta"])


# 兼容别名(便于 from src.common.metrics import metrics_router)
metrics_router = router


# 阶段 5 业务指标定义(若 prometheus_client 可用)
if _PROM_AVAILABLE:
    # gateway_proxy:ai 服务不可达计数
    ai_unreachable_total = Counter(
        "ai_unreachable_total",
        "gateway_proxy 调用 ai 服务失败次数(RequestError/网络异常)",
        ["reason"],  # reason: connect_error / timeout / http_error
    )

    # graphrag:/embed 处理耗时(直方图,分位 p50/p95/p99)
    graphrag_embed_latency_seconds = Histogram(
        "graphrag_embed_latency_seconds",
        "graphrag /embed 端点处理耗时(秒)",
        buckets=(0.01, 0.05, 0.1, 0.25, 0.5, 1.0, 2.5, 5.0, 10.0),
    )

    # scan-engine:TaskWorker Redis Stream 消费 lag(消息从入队到消费的延迟)
    taskworker_lag = Gauge(
        "taskworker_lag",
        "scan-engine TaskWorker 消费 vulnscan:tasks 的延迟秒数(stream XADD→XREADGROUP 时间差)",
    )

    # celery:approval_timeout_task 触发时与创建时间的差(审批创建→celery 兜底)
    approval_expired_lag = Histogram(
        "approval_expired_lag_seconds",
        "celery approval_timeout_task 执行时审批已存在时长(秒)",
        buckets=(60, 300, 600, 1800, 3600, 7200),
    )

    # 导出 metrics 模块级符号(便于服务调用方按需 inc/observe)
    __all_metrics__ = [
        "ai_unreachable_total",
        "graphrag_embed_latency_seconds",
        "taskworker_lag",
        "approval_expired_lag",
    ]
else:
    # prometheus_client 缺失时的占位(避免 import 报错)
    class _Noop:
        def inc(self, *args, **kwargs): ...
        def observe(self, *args, **kwargs): ...
        def set(self, *args, **kwargs): ...
        def labels(self, *args, **kwargs):
            return self
        def time(self):  # context manager
            class _CM:
                def __enter__(self): return self
                def __exit__(self, *args): return False
            return _CM()

    ai_unreachable_total = _Noop()
    graphrag_embed_latency_seconds = _Noop()
    taskworker_lag = _Noop()
    approval_expired_lag = _Noop()


@router.get("/metrics", include_in_schema=False)
async def metrics() -> Response:
    """Prometheus 文本格式指标。"""
    if not _PROM_AVAILABLE:
        return Response(
            content=b"# prometheus_client not installed\n",
            media_type="text/plain; charset=utf-8",
        )
    return Response(
        content=generate_latest(),
        media_type=CONTENT_TYPE_LATEST,
    )
