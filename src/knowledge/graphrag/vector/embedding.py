from functools import lru_cache

EMBEDDING_DIM = 1024  # BGE-large-zh-v1.5 输出 1024 维（此前误写 768）


@lru_cache(maxsize=1)
def _get_model():
    from sentence_transformers import SentenceTransformer
    return SentenceTransformer("BAAI/bge-large-zh-v1.5", local_files_only=True)


def embed(text: str) -> list[float]:
    """Generate embedding vector for a query string using BGE-large-zh-v1.5."""
    vec = _get_model().encode(
        "为这个句子生成表示以用于检索相关文章：" + text,
        normalize_embeddings=True,
    )
    return vec.tolist()


def embed_dim() -> int:
    """供 Milvus 建集合等处引用，避免常量分散。"""
    return EMBEDDING_DIM
