from pymilvus import Collection, CollectionSchema, DataType, FieldSchema, MilvusClient, connections

from src.common.config.settings import get_settings
from src.common.logging.logger import get_logger
from src.knowledge.graphrag.vector.embedding import EMBEDDING_DIM as VECTOR_DIM

logger = get_logger(__name__)


class MilvusVectorClient:
    """Thin wrapper around Milvus for threat-intel vector search."""

    def __init__(self) -> None:
        settings = get_settings()
        connections.connect(host=settings.milvus_host, port=settings.milvus_port)
        self._collection_name = settings.milvus_collection
        self._ensure_collection()

    def search(self, query_vector: list[float], top_k: int = 10) -> list[dict]:
        collection = Collection(self._collection_name)
        collection.load()
        results = collection.search(
            data=[query_vector],
            anns_field="embedding",
            param={"metric_type": "IP", "params": {"nprobe": 16}},
            limit=top_k,
            output_fields=["doc_id", "content", "source"],
        )
        hits = []
        for hit in results[0]:
            if hit.score >= get_settings().milvus_score_threshold:
                hits.append({
                    "doc_id": hit.entity.get("doc_id"),
                    "content": hit.entity.get("content"),
                    "source": hit.entity.get("source"),
                    "similarity": hit.score,
                })
        return hits

    def insert(self, docs: list[dict]) -> None:
        collection = Collection(self._collection_name)
        data = [
            [d["doc_id"] for d in docs],
            [d["content"] for d in docs],
            [d["source"] for d in docs],
            [d["embedding"] for d in docs],
        ]
        collection.insert(data)
        collection.flush()

    def close(self) -> None:
        """Disconnect the pymilvus gRPC connection (P1-KNOW-1).

        Without this every GraphRAGEngine() leaks a Milvus connection that
        only closes when the process exits.
        """
        try:
            from pymilvus import connections
            connections.disconnect("default")
        except Exception as exc:
            logger.debug("milvus_disconnect_failed", error=str(exc))

    def _ensure_collection(self) -> None:
        client = MilvusClient(
            uri=f"http://{get_settings().milvus_host}:{get_settings().milvus_port}"
        )
        if self._collection_name not in client.list_collections():
            fields = [
                FieldSchema("id", DataType.INT64, is_primary=True, auto_id=True),
                FieldSchema("doc_id", DataType.VARCHAR, max_length=128),
                FieldSchema("content", DataType.VARCHAR, max_length=8192),
                FieldSchema("source", DataType.VARCHAR, max_length=64),
                FieldSchema("embedding", DataType.FLOAT_VECTOR, dim=VECTOR_DIM),
            ]
            schema = CollectionSchema(fields, description="Threat Intel")
            coll = Collection(self._collection_name, schema)
            logger.info("milvus_collection_created", name=self._collection_name)
            # Create IVF_FLAT index for efficient vector search
            index_params = {
                "metric_type": "IP",
                "index_type": "IVF_FLAT",
                "params": {"nlist": 128},
            }
            coll.create_index(field_name="embedding", index_params=index_params)
            coll.load()
            logger.info("milvus_index_created", name=self._collection_name, index_type="IVF_FLAT")
