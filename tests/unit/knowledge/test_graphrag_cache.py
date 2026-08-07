"""V13 P2-2: GraphRAG cache key must include the query vector.

Two different queries over the same IOC set (different embeddings) used
to share one Redis cache entry and return the wrong retrieval results;
empty IOC sets shared a single global key. All mocked -- no Milvus/Neo4j
needed.
"""

import json
import sys
import types
from unittest.mock import AsyncMock, MagicMock

import pytest

# The local venv's pymilvus/numpy C extensions are broken; stub the
# pymilvus module surface so importing the engine does not need them.
_pymilvus = types.ModuleType("pymilvus")
for _name in ("Collection", "CollectionSchema", "DataType", "FieldSchema", "MilvusClient", "connections"):
    setattr(_pymilvus, _name, object)
sys.modules.setdefault("pymilvus", _pymilvus)

from src.knowledge.graphrag.engine import GraphRAGEngine  # noqa: E402


def _make_engine(redis: MagicMock):
    engine = GraphRAGEngine.__new__(GraphRAGEngine)
    engine._redis = redis
    engine._cache_ttl = 60
    engine._milvus = MagicMock()
    engine._milvus.search = MagicMock(return_value=[])
    engine._neo4j = MagicMock()
    engine._neo4j.query_neighbours = AsyncMock(return_value=[])
    return engine


@pytest.mark.asyncio
async def test_cache_key_differs_for_different_query_vectors():
    redis = MagicMock()
    redis.get = AsyncMock(return_value=None)
    redis.setex = AsyncMock()
    engine = _make_engine(redis)

    iocs = ["8.8.8.8", "evil.com"]
    await engine.search([0.1, 0.2, 0.3], iocs)
    await engine.search([0.9, 0.8, 0.7], iocs)

    keys = [call.args[0] for call in redis.setex.call_args_list]
    assert len(set(keys)) == 2, "different query vectors must not share a cache key"


@pytest.mark.asyncio
async def test_cache_key_same_vector_reuses_entry():
    redis = MagicMock()
    redis.get = AsyncMock(side_effect=[None, '{"fused_ids": ["d1"]}'])
    redis.setex = AsyncMock()
    engine = _make_engine(redis)

    await engine.search([0.1, 0.2], ["a.com"])
    result = await engine.search([0.1, 0.2], ["a.com"])
    assert result["fused_ids"] == ["d1"]  # served from cache
    assert redis.setex.await_count == 1


@pytest.mark.asyncio
async def test_empty_iocs_get_vector_scoped_key():
    redis = MagicMock()
    redis.get = AsyncMock(return_value=None)
    redis.setex = AsyncMock()
    engine = _make_engine(redis)

    await engine.search([0.5, 0.5], [])
    await engine.search([0.6, 0.6], [])
    keys = [call.args[0] for call in redis.setex.call_args_list]
    assert len(set(keys)) == 2, "empty-IOC queries must not share a global key"
    # The key is deterministic and includes the vector hash.
    import hashlib

    vec_hash = hashlib.sha256(json.dumps([0.5, 0.5]).encode()).hexdigest()[:16]
    assert keys[0] == f"graphrag:{vec_hash}:"
