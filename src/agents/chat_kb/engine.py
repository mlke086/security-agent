"""Lightweight keyword-overlap retriever over project docs.

Scans ``docs/*.md``, splits each file into paragraph-level chunks, scores
them by Chinese-aware keyword overlap with the query, and returns the
top-K. The downstream LLM does the final answer composition.

Design notes
------------
- We deliberately do **not** depend on an embedding model or vector DB here.
  Operators run this on air-gapped boxes where pulling a 400 MB BGE model is
  not an option, and the docs corpus is small (a few dozen markdown files).
- Scoring combines:
  - bag-of-words overlap (Chinese bigram-aware via 2-gram shingles)
  - a small synonym map so common ask phrases map to the same docs
- Results are cached in-process; call ``invalidate()`` after editing docs.
- The LLM receives the chunk as ``[path] title >> text`` so it can cite.
"""

from __future__ import annotations

import math
import os
import re
from collections.abc import Iterable
from dataclasses import dataclass
from functools import lru_cache

from src.common.logging.logger import get_logger

logger = get_logger(__name__)

# Where to look for project docs. Resolved relative to the repo root so the
# engine works regardless of where the API process is launched from.
_DEFAULT_DOC_ROOTS = ("docs",)

# Synonyms that should be counted as the same token when scoring overlap.
# Keys are the canonical form, values are alternative spellings operators
# typically use in chat. Match is case-insensitive and substring-based.
_SYNONYMS: dict[str, tuple[str, ...]] = {
    "架构": ("架构", "组成", "整体", "结构", "框架", "架构图", "系统架构"),
    "模块": ("模块", "组件", "子系统", "功能模块"),
    "漏洞扫描": ("漏洞扫描", "扫描", "vulnscan", "scan", "漏洞"),
    "对话": ("对话", "聊天", "chat", "助手", "ai助手"),
    "主机": ("主机", "host", "agent", "节点", "资产"),
    "事件": ("事件", "event", "告警", "alert"),
    "编排": ("编排", "orchestration", "langgraph", "主图", "工作流"),
    "知识库": ("知识库", "知识", "graphrag", "知识图谱", "rag"),
    "规则": ("规则", "rule", "rules", "cve", "漏洞库"),
    "告警": ("告警", "alert", "kafka", "原始告警"),
    "审批": ("审批", "hitl", "人工审批", "审批流程", "approval"),
    "响应": ("响应", "respond", "response", "处置", "执行"),
    "前端": ("前端", "frontend", "ui", "界面", "web"),
    "后端": ("后端", "backend", "api", "fastapi", "服务"),
}


@dataclass
class DocChunk:
    path: str
    title: str
    text: str
    score: float = 0.0


def _tokenize(text: str) -> list[str]:
    """Tokenize a chunk of text. Lower-case + ASCII-alnum + 2-gram shingles.

    For Chinese we fall back to bigram shingles on the raw string so a short
    query like 架构 still matches the surrounding characters in a paragraph.
    Stopwords are intentionally not removed -- the corpus is domain-specific
    and stop-lists tend to swallow meaningful tokens here.
    """
    text = text.lower()
    text = re.sub(r"\s+", " ", text)
    tokens: list[str] = []
    for tok in re.findall(r"[a-z0-9_\-]+|[\u4e00-\u9fff]", text):
        if len(tok) > 1:
            tokens.append(tok)
    cjk = re.findall(r"[\u4e00-\u9fff]+", text)
    for s in cjk:
        if len(s) >= 2:
            tokens.extend(s[i : i + 2] for i in range(len(s) - 1))
    return tokens


def _expand_synonyms(tokens: Iterable[str]) -> set[str]:
    """Expand query tokens via the synonym map so a query about 架构 also
    matches docs that use 组成 / 整体."""
    out: set[str] = set()
    for t in tokens:
        out.add(t)
        for canonical, alts in _SYNONYMS.items():
            if t in alts or t == canonical:
                out.update(alts)
                out.add(canonical)
    return out


def _resolve_doc_roots() -> list[str]:
    """Find docs/ relative to the repo root."""
    here = os.path.dirname(os.path.abspath(__file__))
    for ancestor in (
        here,
        os.path.dirname(here),
        os.path.dirname(os.path.dirname(here)),
        os.path.dirname(os.path.dirname(os.path.dirname(here))),
    ):
        for root in _DEFAULT_DOC_ROOTS:
            candidate = os.path.join(ancestor, root)
            if os.path.isdir(candidate):
                return [candidate]
    return []


def _split_paragraphs(text: str) -> list[tuple[str, str]]:
    """Split a markdown file into (heading-or-empty, paragraph) tuples."""
    out: list[tuple[str, str]] = []
    current_heading = ""
    buf: list[str] = []
    for line in text.splitlines():
        s = line.strip()
        if s.startswith("#"):
            if buf:
                out.append((current_heading, "\n".join(buf).strip()))
                buf = []
            current_heading = re.sub(r"^#+\s*", "", s).strip()
            continue
        if not s:
            if buf:
                out.append((current_heading, "\n".join(buf).strip()))
                buf = []
            continue
        buf.append(line)
    if buf:
        out.append((current_heading, "\n".join(buf).strip()))
    return [(h, p) for h, p in out if len(p) >= 40]


class DocSearchEngine:
    """In-memory index of project docs with keyword-overlap retrieval."""

    def __init__(self, roots: list[str] | None = None) -> None:
        self._roots = roots or _resolve_doc_roots()
        self._chunks: list[DocChunk] = []
        self._loaded = False

    def invalidate(self) -> None:
        self._chunks = []
        self._loaded = False

    def _ensure_loaded(self) -> None:
        if self._loaded:
            return
        chunks: list[DocChunk] = []
        for root in self._roots:
            for dirpath, _dirs, files in os.walk(root):
                for name in files:
                    if not name.endswith((".md", ".markdown")):
                        continue
                    full = os.path.join(dirpath, name)
                    try:
                        with open(full, encoding="utf-8") as f:
                            text = f.read()
                    except OSError as exc:
                        logger.warning("doc_read_failed", path=full, error=str(exc))
                        continue
                    rel = os.path.relpath(full, start=root)
                    for heading, para in _split_paragraphs(text):
                        chunks.append(DocChunk(path=rel, title=heading, text=para))
        self._chunks = chunks
        self._loaded = True
        logger.info("doc_index_loaded", chunks=len(chunks), roots=self._roots)

    def search(self, query: str, top_k: int = 6) -> list[DocChunk]:
        """Return the top-K chunks most relevant to ``query``."""
        self._ensure_loaded()
        if not query.strip():
            return []
        q_tokens = _expand_synonyms(_tokenize(query))
        if not q_tokens:
            return []

        scored: list[DocChunk] = []
        for chunk in self._chunks:
            chunk_tokens = set(_tokenize(chunk.text + " " + chunk.title))
            if not chunk_tokens:
                continue
            overlap = len(q_tokens & chunk_tokens)
            if overlap == 0:
                continue
            length_factor = 1.0 / math.log(max(len(chunk_tokens), 2), 10)
            chunk.score = overlap * length_factor
            scored.append(chunk)
        scored.sort(key=lambda c: c.score, reverse=True)
        return scored[:top_k]


@lru_cache(maxsize=1)
def _singleton() -> DocSearchEngine:
    return DocSearchEngine()


def get_doc_search() -> DocSearchEngine:
    return _singleton()
