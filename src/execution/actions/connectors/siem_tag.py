"""SiemTagConnector — tag an event in Elasticsearch."""
from elasticsearch import AsyncElasticsearch

from src.common.config.settings import get_settings
from src.common.logging.logger import get_logger
from src.execution.actions.base import ActionContext, ActionResult

logger = get_logger(__name__)


class SiemTagConnector:
    op_types = ["siem_tag", "tag"]

    async def execute(self, op: dict, ctx: ActionContext) -> ActionResult:
        import hashlib
        raw = f"{ctx.event_id}:{op.get('type','')}:{str(op.get('params',{}))}"
        op_id = hashlib.sha256(raw.encode()).hexdigest()[:16]
        tag = op.get("params", {}).get("tag", op.get("params", {}).get("channel", "security"))

        try:
            settings = get_settings()
            es = AsyncElasticsearch(hosts=[settings.es_hosts])
            await es.update(  # type: ignore[call-arg]
                index=settings.es_index_events,
                id=ctx.event_id,
                body={"script": {
                    "source": "if (!ctx._source.tags.contains(params.tag)) ctx._source.tags.add(params.tag)",
                    "params": {"tag": tag},
                    "lang": "painless",
                }},
                ignore=[404],
            )
            await es.close()
            return ActionResult(op_id=op_id, op_type=op.get("type", "siem_tag"), status="success",
                                output=f"Tagged event with '{tag}'")
        except Exception as exc:
            logger.warning("siem_tag_failed", event_id=ctx.event_id, error=str(exc))
            return ActionResult(op_id=op_id, op_type=op.get("type", "siem_tag"), status="failed", error=str(exc))

    async def rollback(self, op: dict, ctx: ActionContext) -> None:
        logger.info("siem_tag_rollback", event_id=ctx.event_id, op_type=op.get("type"))
