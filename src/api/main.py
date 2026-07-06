import uuid
from contextlib import asynccontextmanager
from typing import Any

from fastapi import FastAPI, HTTPException
from pydantic import BaseModel

from src.common.audit.audit_logger import get_audit_logger
from src.common.config.settings import get_settings
from src.common.logging.logger import configure_logging, get_logger
from src.orchestration.main_graph.graph import get_compiled_graph

configure_logging()
logger = get_logger(__name__)


@asynccontextmanager
async def lifespan(app: FastAPI):  # type: ignore[no-untyped-def]
    logger.info("startup", version="0.1.0")
    yield
    audit = get_audit_logger()
    await audit.close()
    logger.info("shutdown")


app = FastAPI(
    title="Security AI Agent",
    version="0.1.0",
    lifespan=lifespan,
)


class EventSubmitRequest(BaseModel):
    sanitized_text: str
    iocs: dict[str, list[str]]
    source: str = "api"


class EventSubmitResponse(BaseModel):
    event_id: str
    status: str


@app.post("/api/v1/events", response_model=EventSubmitResponse)
async def submit_event(req: EventSubmitRequest) -> EventSubmitResponse:
    event_id = str(uuid.uuid4())
    raw_event = {
        "event_id": event_id,
        "sanitized_text": req.sanitized_text,
        "iocs": req.iocs,
        "source": req.source,
    }

    graph = get_compiled_graph()
    try:
        result = await graph.ainvoke({"event_id": event_id, "raw_event": raw_event, "audit_log": []})
        verdict = result.get("final_verdict", "unknown")
        logger.info("event_processed", event_id=event_id, verdict=verdict)
        return EventSubmitResponse(event_id=event_id, status="processed")
    except Exception as exc:
        logger.error("event_processing_failed", event_id=event_id, error=str(exc))
        raise HTTPException(status_code=500, detail=str(exc))


@app.get("/api/v1/events/{event_id}")
async def get_event_status(event_id: str) -> dict[str, Any]:
    # Stub: would query audit log or state store
    return {"event_id": event_id, "status": "completed", "verdict": "true_positive"}


@app.get("/health")
async def health_check() -> dict[str, str]:
    return {"status": "ok"}


if __name__ == "__main__":
    import uvicorn
    settings = get_settings()
    uvicorn.run(app, host=settings.api_host, port=settings.api_port)
