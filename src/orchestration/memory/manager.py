"""MemoryManager — Milvus + Neo4j dual-write session memory with dedup and TTL.

Pattern:
store_evidence(event_id, node, content, metadata)  → Milvus (vector) + Neo4j (graph)
get_evidence_by_event(event_id)                     → list[dict]
query_similar(query_text, embedding, top_k)          → vector-similar evidence
cleanup(max_age_hours)                               → remove stale data
"""

import hashlib
import json
import time
from datetime import UTC, datetime
from typing import Any

import redis.asyncio as aioredis

from src.common.config.settings import get_settings
from src.common.logging.logger import get_logger
from src.knowledge.graphrag.graph.neo4j_client import Neo4jGraphClient
from src.knowledge.graphrag.vector.milvus_client import MilvusVectorClient

logger = get_logger(__name__)

_DEFAULT_TTL_HOURS = 24  # 3 days


class MemoryManager:
    """Session-level evidence memory with dual-write to Milvus and Neo4j."""

    def __init__(self) -> None:
        settings = get_settings()
        self._milvus = MilvusVectorClient()
        self._neo4j = Neo4jGraphClient()
        self._redis = aioredis.from_url(settings.redis_url, decode_responses=True)
        self._dedup_ttl = 86400  # 24h dedup window

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    async def store_evidence(
        self,
        event_id: str,
        node: str,
        content: str,
        metadata: dict[str, Any] | None = None,
        embedding: list[float] | None = None,
    ) -> str:
        """Store a piece of evidence. Deduplicates by SHA-256 of content."""
        doc_id = f"{event_id}:{node}:{self._content_hash(content)}"

        if await self._is_duplicate(doc_id):
            logger.debug("evidence_dup_skipped", doc_id=doc_id)
            return doc_id

        metadata = metadata or {}
        metadata.update({"event_id": event_id, "node": node, "ts": datetime.now(UTC).isoformat()})

        # Milvus vector store
        if embedding:
            self._milvus.insert([{"doc_id": doc_id, "content": content, "source": node, "embedding": embedding}])

        # Neo4j graph store
        await self._store_in_graph(event_id, node, doc_id, content, metadata)

        # Dedup marker
        await self._redis.setex(f"dedup:{doc_id}", self._dedup_ttl, "1")

        logger.info("evidence_stored", event_id=event_id, node=node, doc_id=doc_id)
        return doc_id

    async def get_evidence_by_event(self, event_id: str) -> list[dict[str, Any]]:
        """Retrieve all evidence for a given event from Neo4j."""
        return await self._neo4j.query_neighbours([event_id], hops=3)

    async def query_similar(
        self,
        embedding: list[float],
        top_k: int = 5,
    ) -> list[dict[str, Any]]:
        """Vector similarity search across all evidence."""
        return self._milvus.search(embedding, top_k)

    async def cleanup(self, max_age_hours: int = _DEFAULT_TTL_HOURS) -> int:
        """Remove evidence older than max_age_hours. Returns count removed."""
        cutoff = int(time.time()) - max_age_hours * 3600
        removed = 0
        # Redis keys with event timestamps for tracking
        cursor = 0
        while True:
            cursor, keys = await self._redis.scan(cursor=cursor, match="event:ts:*", count=100)
            for key in keys:
                ts = int(await self._redis.get(key) or 0)
                if ts < cutoff:
                    event_id = key.split(":", 2)[2]
                    await self._redis.delete(key)
                    removed += 1
                    logger.info("evidence_cleaned", event_id=event_id)
            if cursor == 0:
                break
        return removed

    async def close(self) -> None:
        await self._neo4j.close()
        await self._redis.aclose()

    # ------------------------------------------------------------------
    # Internal helpers
    # ------------------------------------------------------------------

    @staticmethod
    def _content_hash(content: str) -> str:
        return hashlib.sha256(content.encode("utf-8")).hexdigest()[:16]

    async def _is_duplicate(self, doc_id: str) -> bool:
        return bool(await self._redis.exists(f"dedup:{doc_id}"))

    async def _store_in_graph(
        self,
        event_id: str,
        node: str,
        doc_id: str,
        content: str,
        metadata: dict[str, Any],
    ) -> None:
        """Insert evidence as a Neo4j node linked to the event."""
        from neo4j import AsyncGraphDatabase
        settings = get_settings()
        driver = AsyncGraphDatabase.driver(
            settings.neo4j_uri,
            auth=(settings.neo4j_user, settings.neo4j_password),
        )
        try:
            async with driver.session() as session:
                await session.run(
                    """
                    MERGE (e:Event {event_id: $event_id})
                    MERGE (ev:Evidence {doc_id: $doc_id})
                    SET ev.node = $node,
                        ev.content = $content,
                        ev.metadata = $metadata,
                        ev.ts = $ts
                    MERGE (e)-[:HAS_EVIDENCE]->(ev)
                    """,
                    event_id=event_id,
                    doc_id=doc_id,
                    node=node,
                    content=content[:2000],
                    metadata=json.dumps(metadata),
                    ts=metadata.get("ts", datetime.now(UTC).isoformat()),
                )
        finally:
            await driver.close()


_memory: MemoryManager | None = None


def get_memory_manager() -> MemoryManager:
    global _memory
    if _memory is None:
        _memory = MemoryManager()
    return _memory
