from neo4j import AsyncDriver, AsyncGraphDatabase

from src.common.config.settings import get_settings
from src.common.logging.logger import get_logger

logger = get_logger(__name__)

_NEIGHBOUR_QUERY = """
MATCH (start)-[%rel_var%]-(related)
WHERE start.value IN $ioc_values OR start.name IN $ioc_values
RETURN DISTINCT
    labels(related)[0] AS node_type,
    related.name AS name,
    related.value AS value,
    related.cve_id AS cve_id,
    related.cvss AS cvss
LIMIT 50
"""


class Neo4jGraphClient:
    def __init__(self) -> None:
        settings = get_settings()
        self._driver: AsyncDriver = AsyncGraphDatabase.driver(
            settings.neo4j_uri,
            auth=(settings.neo4j_user, settings.neo4j_password),
        )

    async def query_neighbours(self, ioc_values: list[str], hops: int = 2) -> list[dict]:
        rel_pattern = f"*1..{hops}"
        query = _NEIGHBOUR_QUERY.replace("%rel_var%", rel_pattern)
        async with self._driver.session() as session:
            try:
                result = await session.run(
                    query,
                    ioc_values=ioc_values,
                )
                return [dict(record) async for record in result]
            except Exception as exc:
                logger.error("neo4j_query_failed", error=str(exc))
                return []

    async def delete_by_event(self, event_id: str) -> int:
        """Delete every Evidence node linked to ``Event {event_id}`` (and the
        HAS_EVIDENCE relationship). Returns rows deleted.

        P1-CORE-2: MemoryManager.cleanup() now calls this so Neo4j does not
        grow forever with orphan evidence nodes from old sessions.
        """
        query = (
            "MATCH (e:Event {event_id: $event_id})-[r:HAS_EVIDENCE]->(ev:Evidence) " "DELETE r, ev"
        )
        try:
            async with self._driver.session() as session:
                result = await session.run(query, event_id=event_id)
                # result.consume() drains the cursor; counters are on summary
                summary = await result.consume()
                deleted = summary.counters.relationships_deleted + summary.counters.nodes_deleted
                logger.info("neo4j_event_deleted", event_id=event_id, deleted=deleted)
                return deleted
        except Exception as exc:
            logger.warning("neo4j_event_delete_failed", event_id=event_id, error=str(exc))
            return 0

    async def close(self) -> None:
        await self._driver.close()
