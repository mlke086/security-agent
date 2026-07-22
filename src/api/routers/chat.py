"""General-purpose chat assistant.

Unlike ``scan_chat`` (which only handles scan-intent flow), this router
classifies the user's message into one of four routes and dispatches:

  - scan     → ScanIntent parser, returns a structured intent (frontend
              decides whether to call /vulnscan/tasks)
  - project  → answers questions about this system's architecture / features
              via the in-process doc retriever (chat_kb)
  - web      → answers questions about recent CVEs / breaches / incidents
              via DuckDuckGo HTML search (chat_search)
  - chat     → free-form chat with no retrieval

The router keeps multi-turn state per conversation_id so the LLM can use
prior context. Intent classification itself is a single LLM call that
returns a tiny Pydantic model.
"""

from __future__ import annotations

import json
from typing import Literal

from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel, ConfigDict, Field

from src.agents.chat_kb.engine import get_doc_search
from src.agents.chat_search.web_search import hits_to_context, search_web
from src.api.auth.routes import require_role
from src.common.logging.logger import get_logger
from src.knowledge.models.adapter import ModelNotFoundError, get_model_adapter

logger = get_logger(__name__)

router = APIRouter(prefix="/api/v1/chat", tags=["chat"])

SYSTEM_PROMPT = (
    '你是安全 AI Agent 的内置助手，名为 "SecAgent 助手"。\n'
    "你可以回答三类问题：\n"
    "  1. 系统功能、架构、操作方法（基于项目文档）\n"
    "  2. 最新的安全漏洞、事件、新闻（基于联网搜索）\n"
    "  3. 用户想发起扫描任务（返回结构化 ScanIntent）\n"
    "回答用中文。回答中引用文档/搜索结果时标注来源（文件名或 URL）。"
)

INTENT_SYSTEM = (
    "You are an intent router. Given the latest user message (and optionally "
    "the recent turns of the conversation), classify it into one of:\n"
    "  - 'scan':     user wants to start / configure / execute a vulnerability scan\n"
    "  - 'project':  user asks about this system's architecture / features / how to use it\n"
    "  - 'web':      user asks about a recent CVE / exploit / breach / security news\n"
    "  - 'chat':     general chit-chat, greeting, or anything else\n"
    'Return JSON {"intent": one of the four, "confidence": 0-1, "query": '
    "the rewritten search query if intent is 'project' or 'web' (omit for "
    'scan/chat), "reason": one short sentence}. No prose, no markdown.'
)

ROUTE = Literal["scan", "project", "web", "chat"]


class IntentDecision(BaseModel):
    model_config = ConfigDict(protected_namespaces=())
    intent: ROUTE
    confidence: float = Field(ge=0, le=1)
    query: str = ""
    reason: str = ""


class ChatRequest(BaseModel):
    model_config = ConfigDict(protected_namespaces=())
    message: str
    history: list[dict] = []  # [{role, content}, ...] prior turns (without system)
    model_id: int | None = None
    conversation_id: str | None = None  # optional, for client-side grouping


class SourceRef(BaseModel):
    title: str
    url: str | None = None
    snippet: str = ""


class ChatResponse(BaseModel):
    model_config = ConfigDict(protected_namespaces=())
    intent: ROUTE
    confidence: float
    reply: str
    sources: list[SourceRef] = []


async def _classify(message: str, history: list[dict], model_id: int | None) -> IntentDecision:
    """Single LLM call to classify intent."""
    adapter = get_model_adapter()
    msgs: list[dict] = [{"role": "system", "content": INTENT_SYSTEM}]
    # only feed the last 4 turns -- intent rarely depends on more context
    for m in history[-4:]:
        if m.get("role") in ("user", "assistant"):
            msgs.append({"role": m["role"], "content": m["content"]})
    msgs.append({"role": "user", "content": message})
    try:
        result = await adapter.chat_completion(
            messages=msgs, schema=IntentDecision, model_id=model_id
        )
        return result
    except Exception as exc:  # noqa: BLE001
        # If classification fails, fall back to chat. Don't surface the error
        # to the user -- they typed a normal question and want an answer.
        logger.warning("intent_classify_failed", error=str(exc))
        return IntentDecision(intent="chat", confidence=0.0, query="", reason=str(exc))


async def _answer_with_docs(
    query: str, model_id: int | None, history: list[dict]
) -> tuple[str, list[SourceRef]]:
    """Project Q&A: retrieve from docs/, then ask LLM to compose."""
    docs = get_doc_search().search(query, top_k=5)
    if not docs:
        return (
            "没有在项目文档里找到相关内容。你可以问我漏洞扫描、主机接入、"
            "审批流程、Kafka 告警接入、LangGraph 编排、GraphRAG 等。",
            [],
        )
    context = "\n\n".join(f"[{d.path}] {d.title}\n{d.text[:600]}" for d in docs)
    sources = [
        SourceRef(title=f"{d.path} - {d.title}", url=None, snippet=d.text[:200]) for d in docs[:5]
    ]

    adapter = get_model_adapter()
    msgs: list[dict] = [
        {
            "role": "system",
            "content": (
                "你是 SecAgent 助手。基于下面的项目文档片段回答用户问题，"
                "回答中引用具体文件名。如果文档不包含答案就明说，不要编造。\n\n"
                f"=== 文档片段 ===\n{context}"
            ),
        },
    ]
    for m in history[-4:]:
        if m.get("role") in ("user", "assistant"):
            msgs.append({"role": m["role"], "content": m["content"]})
    msgs.append({"role": "user", "content": query})
    reply = await adapter.chat_completion(messages=msgs, model_id=model_id)
    return str(reply), sources


async def _answer_with_web(
    query: str, model_id: int | None, history: list[dict]
) -> tuple[str, list[SourceRef]]:
    """Web Q&A: search via DDG HTML, then summarize."""
    hits = await search_web(query, limit=6)
    if not hits:
        return (
            "联网搜索暂时没有拿到结果（可能被防火墙拦了，或者关键词太泛）。"
            '你可以换个更具体的词，比如 "CVE-2024-3094 xz 后门" 这种。',
            [],
        )
    ctx = hits_to_context(hits)
    sources = [SourceRef(title=h.title, url=h.url, snippet=h.snippet[:200]) for h in hits]

    adapter = get_model_adapter()
    msgs: list[dict] = [
        {
            "role": "system",
            "content": (
                "你是 SecAgent 助手。基于下面的联网搜索结果回答用户的最新漏洞/事件问题。"
                "只引用搜索结果里出现的事实，不要编造；用 [1]/[2] 这样的角标标注来源，"
                '最后单独给一个 "参考资料：" 列表列出对应 URL。\n\n'
                f"=== 搜索结果 ===\n{ctx}"
            ),
        },
    ]
    for m in history[-4:]:
        if m.get("role") in ("user", "assistant"):
            msgs.append({"role": m["role"], "content": m["content"]})
    msgs.append({"role": "user", "content": query})
    reply = await adapter.chat_completion(messages=msgs, model_id=model_id)
    return str(reply), sources


async def _answer_freeform(
    message: str, model_id: int | None, history: list[dict]
) -> tuple[str, list[SourceRef]]:
    """Generic chat: just call the LLM with system prompt + history."""
    adapter = get_model_adapter()
    msgs: list[dict] = [{"role": "system", "content": SYSTEM_PROMPT}]
    for m in history:
        if m.get("role") in ("user", "assistant"):
            msgs.append({"role": m["role"], "content": m["content"]})
    msgs.append({"role": "user", "content": message})
    reply = await adapter.chat_completion(messages=msgs, model_id=model_id)
    return str(reply), []


@router.post("", response_model=ChatResponse)
async def api_chat(
    req: ChatRequest,
    current_user=Depends(require_role("admin", "analyst")),
):
    """Single-shot chat: classify + dispatch + answer."""
    if not req.message.strip():
        raise HTTPException(status_code=422, detail="message 不能为空")

    decision = await _classify(req.message, req.history, req.model_id)
    logger.info(
        "chat_routed",
        intent=decision.intent,
        confidence=decision.confidence,
        reason=decision.reason,
    )

    try:
        if decision.intent == "scan":
            # Hand back to the scan-intent endpoint -- the LLM might as well
            # parse the intent here so the UI can show the parsed card.
            from src.agents.models import ScanIntent

            adapter = get_model_adapter()
            msgs = [
                {
                    "role": "system",
                    "content": (
                        "你是漏洞扫描助手。用户会用自然语言描述扫描需求。"
                        "从对话中提取目标主机/组、扫描模块（sys_vuln/baseline）、"
                        "资源限制等信息。如果信息不全，留空让前端追问。"
                    ),
                }
            ]
            for m in req.history[-4:]:
                if m.get("role") in ("user", "assistant"):
                    msgs.append({"role": m["role"], "content": m["content"]})
            msgs.append({"role": "user", "content": req.message})
            intent = await adapter.chat_completion(
                messages=msgs,
                schema=ScanIntent,
                model_id=req.model_id,
            )
            # Reply text guides the user; the actual intent lives in sources.
            scan = intent.model_dump()
            targets = scan.get("targets") or []
            modules = scan.get("modules") or []
            mod_names = {"sys_vuln": "系统漏洞", "baseline": "安全基线"}
            mod_text = "、".join(mod_names.get(m, m) for m in modules) or "默认"
            tgt_text = "、".join(targets) or "未指定"
            reply = (
                f"已识别扫描意图：\n\n"
                f"- 🎯 目标：{tgt_text}\n"
                f"- 🔍 模块：{mod_text}\n\n"
                f"如果以上信息无误，点击「执行扫描」即可创建任务。"
            )
            sources = [
                SourceRef(title="intent", url=None, snippet=json.dumps(scan, ensure_ascii=False))
            ]
            return ChatResponse(
                intent="scan", confidence=decision.confidence, reply=reply, sources=sources
            )

        if decision.intent == "project":
            reply, sources = await _answer_with_docs(
                decision.query or req.message, req.model_id, req.history
            )
            return ChatResponse(
                intent="project", confidence=decision.confidence, reply=reply, sources=sources
            )

        if decision.intent == "web":
            reply, sources = await _answer_with_web(
                decision.query or req.message, req.model_id, req.history
            )
            return ChatResponse(
                intent="web", confidence=decision.confidence, reply=reply, sources=sources
            )

        # chat
        reply, sources = await _answer_freeform(req.message, req.model_id, req.history)
        return ChatResponse(
            intent="chat", confidence=decision.confidence, reply=reply, sources=sources
        )

    except ModelNotFoundError as exc:
        raise HTTPException(status_code=404, detail=str(exc))
    except Exception as exc:  # noqa: BLE001
        logger.exception("chat_dispatch_failed")
        raise HTTPException(status_code=502, detail=f"助手调用失败: {exc}")
