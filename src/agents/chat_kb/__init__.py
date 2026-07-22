"""Project-doc knowledge base for the chat assistant.

Indexes the project documentation under docs/ and serves a lightweight
keyword-overlap retrieval. Kept dependency-free (no embeddings required) so
it works on any deployment -- the LLM does the final re-ranking.
"""

from src.agents.chat_kb.engine import DocChunk, DocSearchEngine, get_doc_search

__all__ = ["DocChunk", "DocSearchEngine", "get_doc_search"]
