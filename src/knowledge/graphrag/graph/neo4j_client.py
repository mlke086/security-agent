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

    async def query_neighbours(
        self, ioc_values: list[str], hops: int = 2
    ) -> list[dict]:
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

    async def close(self) -> None:
        await self._driver.close()
