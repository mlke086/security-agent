from neo4j import AsyncGraphDatabase, AsyncDriver

from src.common.config.settings import get_settings
from src.common.logging.logger import get_logger

logger = get_logger(__name__)

_NEIGHBOUR_QUERY = """
MATCH (start)
WHERE start.value IN $ioc_values OR start.name IN $ioc_values
CALL apoc.path.spanningTree(start, {maxLevel: $hops, relationshipFilter: ">"})
YIELD path
WITH nodes(path) AS ns, relationships(path) AS rels
UNWIND ns AS n
RETURN DISTINCT
    labels(n)[0] AS node_type,
    n.name AS name,
    n.value AS value,
    n.cve_id AS cve_id,
    n.cvss AS cvss
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
        async with self._driver.session() as session:
            try:
                result = await session.run(
                    _NEIGHBOUR_QUERY,
                    ioc_values=ioc_values,
                    hops=hops,
                )
                return [dict(record) async for record in result]
            except Exception as exc:
                logger.error("neo4j_query_failed", error=str(exc))
                return []

    async def close(self) -> None:
        await self._driver.close()
