import asyncio
from collections import defaultdict

import redis.asyncio as aioredis

from src.common.config.settings import get_settings
from src.common.logging.logger import get_logger
from src.knowledge.graphrag.graph.neo4j_client import Neo4jGraphClient
from src.knowledge.graphrag.vector.milvus_client import MilvusVectorClient

logger = get_logger(__name__)


def _rrf_fusion(results_lists: list[list[str]], k: int = 60) -> list[str]:
    scores: dict[str, float] = defaultdict(float)
    for results in results_lists:
        for rank, doc_id in enumerate(results, start=1):
            scores[doc_id] += 1.0 / (k + rank)
    return sorted(scores.keys(), key=lambda x: scores[x], reverse=True)


class GraphRAGEngine:
    """Hybrid retrieval: Milvus vector search + Neo4j graph traversal, fused via RRF."""

    def __init__(self) -> None:
        settings = get_settings()
        self._milvus = MilvusVectorClient()
        self._neo4j = Neo4jGraphClient()
        self._redis = aioredis.from_url(settings.redis_url, decode_responses=True)
        self._cache_ttl = settings.redis_cache_ttl

    async def search(
        self,
        query_vector: list[float],
        ioc_values: list[str],
        top_k: int = 10,
    ) -> dict:
        cache_key = f"graphrag:{':'.join(sorted(ioc_values))}"
        cached = await self._redis.get(cache_key)
        if cached:
            import json
            return json.loads(cached)

        vector_hits, graph_hits = await asyncio.gather(
            asyncio.to_thread(self._milvus.search, query_vector, top_k),
            self._neo4j.query_neighbours(ioc_values, hops=2),
        )

        vector_ids = [h["doc_id"] for h in vector_hits]
        graph_ids = [str(h.get("name") or h.get("value") or "") for h in graph_hits]
        fused_ids = _rrf_fusion([vector_ids, graph_ids])

        result = {
            "fused_ids": fused_ids[:top_k],
            "vector_hits": vector_hits,
            "graph_relations": graph_hits,
        }

        import json
        await self._redis.setex(cache_key, self._cache_ttl, json.dumps(result))
        return result

    async def close(self) -> None:
        await self._neo4j.close()
        await self._redis.aclose()
        # P1-KNOW-1: also close the Milvus gRPC connection -- previously the
        # pymilvus client leaked one connection per search() call.
        try:
            self._milvus.close()
        except Exception:
            pass
