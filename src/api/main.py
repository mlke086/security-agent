import uuid
from contextlib import asynccontextmanager

from fastapi import BackgroundTasks, Depends, FastAPI, Query, WebSocket
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel

from src.agents.ws_gateway import get_agent_gateway
from src.api.auth import auth_router
from src.api.auth.routes import require_role
from src.api.routers.agents import router as agents_router
from src.api.routers.chat import router as chat_router
from src.api.routers.demo import router as demo_router
from src.api.routers.models import router as models_router
from src.api.routers.operations import router as operations_router
from src.api.routers.rules import router as rules_router
from src.api.routers.scan_chat import router as scan_chat_router
from src.api.routers.stream import router as stream_router
from src.api.routers.vulnscan import router as vulnscan_router
from src.api.store import get_event_store
from src.common.audit.audit_logger import get_audit_logger
from src.common.config.settings import get_settings
from src.common.logging.logger import configure_logging, get_logger

configure_logging()
logger = get_logger(__name__)

_EVENTS_INDEX_MAPPING = {
    "settings": {"number_of_shards": 1, "number_of_replicas": 0},
    "mappings": {
        "properties": {
            "event_id": {"type": "keyword"},
            "status": {"type": "keyword"},
            "final_verdict": {"type": "keyword"},
            "priority": {"type": "keyword"},
            "source": {"type": "keyword"},
            "submitted_at": {"type": "date"},
            "finished_at": {"type": "date"},
            "confidence": {"type": "float"},
            "duration_ms": {"type": "integer"},
            "pending_approval_id": {"type": "keyword"},
            "approvals": {"type": "nested"},
            "mitre_ttps": {"type": "keyword"},
            "tags": {"type": "keyword"},
            "sanitized_text": {"type": "text"},
        }
    },
}


async def _ensure_es_indices():
    """Create ES indices with mappings if they don't exist."""
    try:
        from elasticsearch import AsyncElasticsearch

        s = get_settings()
        es = AsyncElasticsearch(hosts=[s.es_hosts])
        if not await es.indices.exists(index=s.es_index_events):
            await es.indices.create(index=s.es_index_events, body=_EVENTS_INDEX_MAPPING)
            logger.info("es_index_created", index=s.es_index_events)
        if not await es.indices.exists(index=s.es_index_audit):
            await es.indices.create(
                index=s.es_index_audit,
                body={
                    "settings": {"number_of_shards": 1, "number_of_replicas": 0},
                    "mappings": {
                        "properties": {
                            "event_id": {"type": "keyword"},
                            "node": {"type": "keyword"},
                            "action": {"type": "keyword"},
                            "actor": {"type": "keyword"},
                            "summary": {"type": "text"},
                            "details": {"type": "object", "enabled": False},
                            "timestamp": {"type": "date"},
                        }
                    },
                },
            )
            logger.info("es_index_created", index=s.es_index_audit)
        from src.agents.store import get_vulnscan_store

        vs = get_vulnscan_store()
        await vs.ensure_indices()
        # Do NOT close the singleton client here. Subsequent requests rely
        # on it being open; closing made every later ES write fail (P1-VS-4).
        # The lifespan shutdown closes it once at process exit.
        await es.close()
    except Exception as exc:
        logger.warning("es_index_setup_failed", error=str(exc))


# TaskWorker 鍙ユ焺锛坙ifespan shutdown 鏃堕渶瑕佸仠姝級
_task_worker_handle = None


@asynccontextmanager
async def lifespan(app: FastAPI):
    from src.agents.ws_gateway import _worker_id

    logger.info("startup", version="0.1.0", worker_id=_worker_id)
    # ---- Startup order is load-bearing (do not reorder) ----
    # 1) load_nacos_settings() must run FIRST so PG_HOST / ES_HOSTS /
    #    REDIS_URL etc. reflect whatever Nacos says for this environment.
    #    Otherwise _ensure_es_indices() and init_schema() fall back to
    #    the docker-compose `x-bootstrap-env` defaults (127.0.0.1) and
    #    silently connect to the wrong host on multi-host deployments.
    #    entrypoint.sh also calls load_nacos_settings() once before
    #    uvicorn starts (preload), so this is a defensive re-run for
    #    worker processes forked after preload.
    from src.common.config.settings import load_nacos_settings

    try:
        await load_nacos_settings()
        logger.info("nacos_settings_loaded_in_lifespan")
    except Exception as exc:  # noqa: BLE001
        # Nacos ?????????,????? env-only?
        logger.warning("nacos_settings_load_failed_in_lifespan", error=str(exc))
    # 2) ???????? ES indices (?? es_hosts) ? PG schema (?? pg_host)?
    await _ensure_es_indices()
    from src.common.db.pg import init_schema

    try:
        await init_schema()
        logger.info("pg_schema_initialized")
    except Exception as exc:
        logger.warning("pg_schema_init_failed", error=str(exc))
    from src.agents.scheduler import start_background_tasks

    start_background_tasks()

    # P1 (F4) -- subscribe to cross-worker revocation events so token revoke
    # also tears down any WS held by THIS worker.
    revocation_task: asyncio.Task | None = None
    try:
        from src.agents.revoke import listen_for_revocations
        from src.agents.ws_gateway import get_agent_gateway

        async def _drop(agent_id: str) -> None:
            await get_agent_gateway().drop_revoked_connection(agent_id)

        revocation_task = asyncio.create_task(listen_for_revocations(_drop))
    except Exception as exc:  # noqa: BLE001
        logger.warning("revocation_listener_failed", error=str(exc))

    # 鍚姩 Vulnscan TaskWorker锛堟秷璐?Redis Stream 寮傛鎵弿浠诲姟锛?
    global _task_worker_handle
    import os as _os
    if not _os.environ.get("DISABLE_TASK_WORKER"):
        try:
            from src.orchestration.task_queue import TaskWorker
            worker = TaskWorker()
            _task_worker_handle = worker.start()
            logger.info("vulnscan_task_worker_started",
                        consumer=worker.consumer)
        except Exception as exc:
            logger.warning("vulnscan_task_worker_start_failed", error=str(exc))

    yield
    # Shutdown: 鍏堝仠 TaskWorker锛屽啀鍋?Nacos 鐩戝惉 + 鍏抽棴寮傛鍗曚緥
    if _task_worker_handle is not None:
        try:
            await _task_worker_handle.stop(timeout=5.0)
        except Exception as exc:
            logger.warning("task_worker_shutdown_failed", error=str(exc))
        _task_worker_handle = None
    from src.common.config.nacos_loader import stop_nacos_listener

    stop_nacos_listener()

    if revocation_task is not None:
        revocation_task.cancel()
        try:
            await revocation_task
        except asyncio.CancelledError:
            pass
        except Exception as exc:  # noqa: BLE001
            logger.warning("revocation_listener_shutdown_failed", error=str(exc))
    from src.agents.scheduler import stop_background_tasks
    from src.agents.store import get_vulnscan_store
    from src.api.events_bus import get_event_bus
    from src.common.db.pg import close_pool
    from src.orchestration.subgraphs.responder.approval_store import get_approval_store

    for closer in (
        get_event_store().close,
        get_event_bus().close,
        get_approval_store().close,
        get_vulnscan_store().close,
        stop_background_tasks,
        get_audit_logger().close,
        close_pool,
    ):
        try:
            await closer()
        except Exception as exc:
            logger.warning("shutdown_close_failed", error=str(exc))
    logger.info("shutdown")


app = FastAPI(
    title="Security AI Agent",
    version="0.1.0",
    lifespan=lifespan,
)

app.add_middleware(
    CORSMiddleware,
    allow_origin_regex=".*",
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)


class EventSubmitRequest(BaseModel):
    sanitized_text: str
    iocs: dict[str, list[str]]
    source: str = "api"


class EventSubmitResponse(BaseModel):
    event_id: str
    status: str


async def _run_pipeline(event_id: str, text: str, iocs: dict, source: str):
    """Background task: thin wrapper around shared runner."""
    try:
        from src.orchestration.runner import run_pipeline

        await run_pipeline(event_id, text, iocs, source)
    except Exception as exc:
        await get_event_store().update_event(event_id, status="error")
        logger.error("pipeline_failed", event_id=event_id, error=str(exc))


@app.post("/api/v1/events", response_model=EventSubmitResponse)
async def submit_event(
    req: EventSubmitRequest,
    background_tasks: BackgroundTasks,
    sync: bool = Query(False, description="sync mode"),
    current_user=Depends(require_role("admin", "analyst")),
):
    event_id = str(uuid.uuid4())
    store = get_event_store()
    await store.create_event(event_id, req.sanitized_text, req.iocs, req.source)

    if sync:
        await _run_pipeline(event_id, req.sanitized_text, req.iocs, req.source)
    else:
        background_tasks.add_task(_run_pipeline, event_id, req.sanitized_text, req.iocs, req.source)

    return EventSubmitResponse(event_id=event_id, status="processing")


@app.websocket("/api/v1/agents/ws")
async def agents_ws(websocket: WebSocket):
    """WebSocket endpoint for agent connections.

    agent 绔妸 token 鏀惧湪 Authorization: Bearer header锛圥1-GO-4锛岄伩鍏?token
    钀?URL/proxy 鏃ュ織锛夛紝鍚庣闇€浼樺厛璇?header锛涘洖閫€ query token 鍏煎鏃?agent銆?
    """
    agent_id = websocket.query_params.get("agent_id", "")
    # 浼樺厛 Authorization header锛屽洖閫€ query token
    token = ""
    auth_header = websocket.headers.get("authorization", "")
    if auth_header.lower().startswith("bearer "):
        token = auth_header[7:].strip()
    if not token:
        token = websocket.query_params.get("token", "")
    gateway = get_agent_gateway()
    if not await gateway.authenticate(agent_id, token):
        await websocket.close(code=1008, reason="Authentication failed")
        return
    try:
        await gateway.connect(websocket, agent_id)
        while True:
            raw = await websocket.receive_text()
            await gateway.handle_message(websocket, raw)
    except Exception as exc:
        from src.common.logging.logger import get_logger

        get_logger(__name__).warning("agent_ws_error", error=str(exc))
    finally:
        await gateway.disconnect(websocket)


@app.get("/health")
async def health_check() -> dict[str, str]:
    return {"status": "ok"}


app.include_router(auth_router)
app.include_router(operations_router)
app.include_router(demo_router)
app.include_router(agents_router)
app.include_router(vulnscan_router)
app.include_router(rules_router)
app.include_router(models_router)
app.include_router(chat_router)
app.include_router(scan_chat_router)
app.include_router(stream_router)

if __name__ == "__main__":
    import uvicorn

    settings = get_settings()
    uvicorn.run(app, host=settings.api_host, port=settings.api_port)
