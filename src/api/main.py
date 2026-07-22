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
from src.api.routers.operations import router as operations_router
from src.api.routers.rules import router as rules_router
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


@asynccontextmanager
async def lifespan(app: FastAPI):
    from src.agents.ws_gateway import _worker_id

    logger.info("startup", version="0.1.0", worker_id=_worker_id)
    await _ensure_es_indices()
    from src.common.db.pg import init_schema

    try:
        await init_schema()
        logger.info("pg_schema_initialized")
    except Exception as exc:
        logger.warning("pg_schema_init_failed", error=str(exc))
    from src.agents.scheduler import start_background_tasks

    start_background_tasks()
    yield
    # Close async singletons so redis/ES connections don't leak or trigger
    # "Event loop is closed" warnings on shutdown.
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
    """WebSocket endpoint for agent connections."""
    agent_id = websocket.query_params.get("agent_id", "")
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
app.include_router(chat_router)
app.include_router(stream_router)

if __name__ == "__main__":
    import uvicorn

    settings = get_settings()
    uvicorn.run(app, host=settings.api_host, port=settings.api_port)
