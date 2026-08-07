"""graphrag 服务入口(阶段 1)。

唯一含 torch 的重镜像。HTTP API:
- POST /embed             BGE-large-zh-v1.5 单文本向量化
- POST /vector-search     Milvus 向量检索(输入已是向量,不做 embed)
- POST /graph-query       Neo4j 图谱邻居查询
- POST /memory/add        MemoryManager.store_evidence
- POST /memory/search     MemoryManager.query_similar
- POST /memory/by-event   MemoryManager.get_evidence_by_event
- POST /engine/search     GraphRAGEngine 综合检索(embed + milvus + neo4j + RRF)
- GET  /healthz           健康检查

阶段 1 接入:scan-engine 的 cti_analyst.py 通过 httpx 调本服务的 /engine/search、
/embed、/memory/add,不再直连 Milvus/Neo4j/torch(详 docs/分布式架构拆分方案.md 阶段 1)。
"""
from __future__ import annotations

import asyncio
from contextlib import asynccontextmanager
from typing import Any

import httpx
from fastapi import FastAPI, HTTPException
from pydantic import BaseModel, Field

from src.common.logging.logger import get_logger
from src.graphrag.memory_manager import get_memory_manager
from src.knowledge.graphrag.engine import GraphRAGEngine
from src.knowledge.graphrag.vector.embedding import EMBEDDING_DIM

logger = get_logger(__name__)


# ---------------------------------------------------------------------------
# Lifespan:启动期连接 probe,失败 fail-fast
# ---------------------------------------------------------------------------
@asynccontextmanager
async def lifespan(app: FastAPI):
    """启动期做最小健康 probe;embed 模型延迟到首次 /embed 请求加载。

    阶段 1 故意不做 eager connect(Milvus/Neo4j/Redis 启动时可能未就绪,
    懒加载避免启动失败级联)。
    """
    logger.info("graphrag_starting")
    yield
    logger.info("graphrag_stopping")


app = FastAPI(
    title="secagent-graphrag",
    version="0.1.0",
    description="向量嵌入 + Milvus 检索 + Neo4j 图谱 + 会话记忆(唯一带 torch 的重镜像)",
    lifespan=lifespan,
)


# ---------------------------------------------------------------------------
# Pydantic schemas
# ---------------------------------------------------------------------------
class EmbedRequest(BaseModel):
    text: str = Field(..., min_length=1, max_length=8192)


class EmbedResponse(BaseModel):
    vector: list[float]
    dim: int


class VectorSearchRequest(BaseModel):
    vector: list[float]
    ioc_values: list[str] = Field(default_factory=list)
    top_k: int = 10


class GraphQueryRequest(BaseModel):
    ioc_values: list[str]
    hops: int = 2


class MemoryAddRequest(BaseModel):
    event_id: str
    node: str
    content: str
    metadata: dict[str, Any] | None = None
    embedding: list[float] | None = None


class MemorySearchRequest(BaseModel):
    embedding: list[float]
    top_k: int = 5


class MemoryByEventRequest(BaseModel):
    event_id: str


class EngineSearchRequest(BaseModel):
    ioc_values: list[str]
    top_k: int = 5


# ---------------------------------------------------------------------------
# 路由
# ---------------------------------------------------------------------------
@app.get("/healthz", tags=["meta"])
async def healthz() -> dict[str, str]:
    """基础健康检查;阶段 1 末尾可加 Milvus/Neo4j ping。"""
    return {"status": "ok", "service": "graphrag", "embedding_dim": str(EMBEDDING_DIM)}


@app.post("/embed", response_model=EmbedResponse, tags=["embed"])
async def embed(req: EmbedRequest) -> EmbedResponse:
    """BGE-large-zh-v1.5 单文本向量化。"""
    from src.common.metrics import graphrag_embed_latency_seconds

    with graphrag_embed_latency_seconds.time():
        try:
            from src.knowledge.graphrag.vector.embedding import embed as _embed

            vec = _embed(req.text)
        except Exception as exc:
            logger.exception("embed_failed")
            raise HTTPException(status_code=503, detail=f"embed failed: {exc!s}") from exc
    return EmbedResponse(vector=vec, dim=EMBEDDING_DIM)


@app.post("/vector-search", tags=["retrieval"])
async def vector_search(req: VectorSearchRequest) -> dict[str, Any]:
    """Milvus 向量检索(向量由调用方已计算好,本服务不再 embed)。"""
    engine = GraphRAGEngine()
    try:
        # 复用 engine.search 走 Milvus + 缓存路径
        result = await engine.search(
            query_vector=req.vector,
            ioc_values=req.ioc_values,
            top_k=req.top_k,
        )
        return {
            "fused_ids": result.get("fused_ids", []),
            "vector_hits": result.get("vector_hits", []),
        }
    except Exception as exc:
        logger.exception("vector_search_failed")
        raise HTTPException(status_code=503, detail=f"vector_search failed: {exc!s}") from exc
    finally:
        try:
            await engine.close()
        except Exception:
            pass


@app.post("/graph-query", tags=["retrieval"])
async def graph_query(req: GraphQueryRequest) -> dict[str, Any]:
    """Neo4j 图谱邻居查询。"""
    try:
        from src.knowledge.graphrag.graph.neo4j_client import Neo4jGraphClient

        client = Neo4jGraphClient()
        try:
            relations = await client.query_neighbours(req.ioc_values, hops=req.hops)
            return {"graph_relations": relations}
        finally:
            await client.close()
    except Exception as exc:
        logger.exception("graph_query_failed")
        raise HTTPException(status_code=503, detail=f"graph_query failed: {exc!s}") from exc


@app.post("/memory/add", tags=["memory"])
async def memory_add(req: MemoryAddRequest) -> dict[str, str]:
    """MemoryManager.store_evidence"""
    try:
        mm = get_memory_manager()
        doc_id = await mm.store_evidence(
            event_id=req.event_id,
            node=req.node,
            content=req.content,
            metadata=req.metadata,
            embedding=req.embedding,
        )
        return {"doc_id": doc_id}
    except Exception as exc:
        logger.exception("memory_add_failed")
        raise HTTPException(status_code=503, detail=f"memory_add failed: {exc!s}") from exc


@app.post("/memory/search", tags=["memory"])
async def memory_search(req: MemorySearchRequest) -> dict[str, Any]:
    """MemoryManager.query_similar(向量已由调用方算好)。"""
    try:
        mm = get_memory_manager()
        hits = await mm.query_similar(embedding=req.embedding, top_k=req.top_k)
        return {"hits": hits}
    except Exception as exc:
        logger.exception("memory_search_failed")
        raise HTTPException(status_code=503, detail=f"memory_search failed: {exc!s}") from exc


@app.post("/memory/by-event", tags=["memory"])
async def memory_by_event(req: MemoryByEventRequest) -> dict[str, Any]:
    """MemoryManager.get_evidence_by_event"""
    try:
        mm = get_memory_manager()
        rows = await mm.get_evidence_by_event(req.event_id)
        return {"rows": rows}
    except Exception as exc:
        logger.exception("memory_by_event_failed")
        raise HTTPException(status_code=503, detail=f"memory_by_event failed: {exc!s}") from exc


@app.post("/engine/search", tags=["retrieval"])
async def engine_search(req: EngineSearchRequest) -> dict[str, Any]:
    """GraphRAGEngine 综合检索(自动 embed + milvus + neo4j + RRF)。

    cti_analyst 拆分迁移主入口:scan-engine 调用方只需传 ioc_values,
    由本服务内部完成 embed + 向量检索 + 图谱查询 + RRF 融合 + 缓存。
    """
    try:
        from src.knowledge.graphrag.vector.embedding import embed as _embed

        engine = GraphRAGEngine()
        try:
            mock_embedding = _embed(" ".join(req.ioc_values))
            result = await engine.search(
                query_vector=mock_embedding,
                ioc_values=req.ioc_values,
                top_k=req.top_k,
            )
            # 与 cti_analyst 原 _query_graphrag 输出格式对齐
            parts: list[str] = []
            vector_hits = result.get("vector_hits", [])
            graph_hits = result.get("graph_relations", [])
            if vector_hits:
                parts.append(
                    "Vector matches:\n"
                    + "\n".join(
                        f"  [{h['source']}] {h['content'][:200]}" for h in vector_hits
                    )
                )
            if graph_hits:
                parts.append(
                    "Graph relations:\n"
                    + "\n".join(
                        f"  [{r.get('node_type', '?')}] {r.get('name', '')} {r.get('cve_id', '')}"
                        for r in graph_hits[:10]
                    )
                )
            context = "\n\n".join(parts) if parts else ""
            return {
                "context": context,
                "fused_ids": result.get("fused_ids", []),
                "vector_hits": vector_hits,
                "graph_relations": graph_hits,
            }
        finally:
            try:
                await engine.close()
            except Exception:
                pass
    except Exception as exc:
        logger.exception("engine_search_failed")
        raise HTTPException(status_code=503, detail=f"engine_search failed: {exc!s}") from exc


# ---------------------------------------------------------------------------
# 客户端便捷函数(供 scan-engine 在同进程调用,例如 e2e 测试)
# ---------------------------------------------------------------------------
class GraphRAGClient:
    """scan-engine 侧 httpx 封装(不在 graphrag 镜像内)。

    阶段 1 提供的客户端 API 与原 cti_analyst._query_graphrag 一一对应。
    """

    def __init__(self, base_url: str | None = None, timeout: float = 30.0) -> None:
        from src.common.config.settings import get_settings

        self.base_url = (base_url or get_settings().graphrag_base_url).rstrip("/")
        self.timeout = timeout

    async def engine_search(self, ioc_values: list[str], top_k: int = 5) -> dict[str, Any]:
        async with httpx.AsyncClient(timeout=self.timeout) as client:
            resp = await client.post(
                f"{self.base_url}/engine/search",
                json={"ioc_values": ioc_values, "top_k": top_k},
            )
            resp.raise_for_status()
            return resp.json()

    async def embed(self, text: str) -> list[float]:
        async with httpx.AsyncClient(timeout=self.timeout) as client:
            resp = await client.post(f"{self.base_url}/embed", json={"text": text})
            resp.raise_for_status()
            return resp.json()["vector"]

    async def memory_add(
        self,
        event_id: str,
        node: str,
        content: str,
        metadata: dict[str, Any] | None = None,
        embedding: list[float] | None = None,
    ) -> str:
        async with httpx.AsyncClient(timeout=self.timeout) as client:
            resp = await client.post(
                f"{self.base_url}/memory/add",
                json={
                    "event_id": event_id,
                    "node": node,
                    "content": content,
                    "metadata": metadata,
                    "embedding": embedding,
                },
            )
            resp.raise_for_status()
            return resp.json()["doc_id"]

    async def close(self) -> None:
        return None  # 无状态


# 暴露给 e2e 测试使用
_ = asyncio  # noqa: F401  防止 lint 删 asyncio import

# 阶段 5:/metrics 端点(prometheus_client)
from src.common.metrics import metrics_router  # noqa: E402

app.include_router(metrics_router)
