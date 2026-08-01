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

import asyncio
import json
import re
from typing import Literal, cast

from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel, ConfigDict, Field

from src.agents import conversation as conv_store
from src.agents.chat_kb.engine import get_doc_search
from src.agents.chat_search.web_search import hits_to_context, search_with_fallback
from src.agents.conversation import maybe_generate_title
from src.agents.models import ScanIntent, VulnFilter
from src.agents.store import get_vulnscan_store
from src.api.auth.routes import require_role
from src.common.audit.audit_logger import get_audit_logger
from src.common.logging.logger import get_logger
from src.knowledge.models.adapter import ModelNotFoundError, get_model_adapter

logger = get_logger(__name__)

# V12 5.10: fire-and-forget title-generation tasks. asyncio.create_task()
# returns a Task that may be garbage-collected mid-execution without a
# strong reference; we keep a module-level set (same pattern as
# scan_chat._BG_TASKS) and discard entries when they finish.
_BG_TASKS: set = set()


def _spawn_title_task(conv_id: str | None, model_id: int | None) -> None:
    """Background-auto-title a conversation (V12 5.10).

    The unified /api/v1/chat router used to skip the auto-title step that
    the legacy scan-chat route performed, so conversations stayed "新对话"
    forever. Spawned fire-and-forget after the turns are persisted.
    """
    if not conv_id:
        return
    t = asyncio.create_task(maybe_generate_title(conv_id, model_id))
    _BG_TASKS.add(t)
    t.add_done_callback(_BG_TASKS.discard)


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
    'scan/chat), "reason": one short sentence, "scan_intent": if and only if '
    "intent is 'scan', extract the structured scan intent here (targets, "
    "modules, engine, resource_limit, schedule) so the caller does not need a "
    "second LLM call to parse it. For `targets` use the BARE name only -- "
    "the hostname, the IP, or the business-group name. Examples that "
    "should round-trip cleanly: user `\u626b\u63cf test \u7ec4\u7684\u4e3b\u673a` -> targets [`test`]; "
    "user `\u626b\u63cf rocky-01 \u548c web-02` -> targets [`rocky-01`, `web-02`]; "
    "user `\u626b\u63cf 10.0.0.5` -> targets [`10.0.0.5`]; "
    "user `\u626b\u63cf prod \u7ec4 + test \u7ec4` -> targets [`prod`, `test`]. "
    "Do NOT add type tags like `group:` / `host:` / `ip:` -- the frontend "
    "auto-fills business groups by exact string match, so any prefix "
    "silently breaks the workflow. If you are not sure of a target's "
    "exact form, OMIT it (do not invent a value) -- the frontend will "
    "ask the operator to clarify. No prose, no markdown."
)

ROUTE = Literal["scan", "project", "web", "chat", "host"]


class IntentDecision(BaseModel):
    model_config = ConfigDict(protected_namespaces=())
    intent: ROUTE
    confidence: float = Field(ge=0, le=1)
    query: str = ""
    reason: str = ""
    # S-P1-F2: when the classifier detects a scan request it can extract the
    # structured ScanIntent in the same call, so the scan route does not need
    # a second LLM round-trip. None for non-scan intents (or if the model did
    # not populate it; the scan branch falls back to a dedicated parse call).
    scan_intent: ScanIntent | None = None
    # S-P1-4 (V12): True when the classifier itself failed (model call
    # raised) and the request was force-degraded to a free-form chat route.
    # The router responds 503 + audit so the operator knows the scan-route
    # gate was NOT evaluated -- a high-risk instruction was not actioned.
    degraded: bool = False


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
    # The PG-persisted `ts` of the assistant turn we just wrote. The
    # frontend adopts this verbatim for its in-memory message so a later
    # patchMessage(task_id) -- which matches by `ts` -- is guaranteed to
    # hit the same row. Optional for backward compat with older clients.
    assistant_ts: str | None = None


# Type-tag prefixes the LLM occasionally tacks on ("group:" / "host:" /
# "ip:") even though the prompt explicitly forbids them. We strip them on
# the way out so the frontend's exact-string group lookup keeps working.
_TARGET_PREFIX_RE = re.compile(r"^(group|host|ip|hostname|grp):", re.IGNORECASE)


def _fallback_extract_targets(user_message: str) -> list[str]:
    """Best-effort extraction when the LLM returns an empty targets list.

    The classifier prompt tells the LLM to OMIT a target when it is not
    sure of its exact form. The operator usually wrote something like
    "扫描 test 组" / "扫描 rocky-01" / "扫描 10.0.0.5" though, and we
    would rather not bounce them back to the chat to re-type. This
    extractor runs only when the LLM's structured `targets` is empty AND
    the route is `scan` -- it is a safety net, never a replacement for
    proper LLM extraction. Returns the list of bare names it found (may
    be empty).
    """
    if not user_message:
        return []
    out: list[str] = []
    # IPv4 addresses (with optional /cidr)
    out.extend(re.findall(r"\b\d{1,3}(?:\.\d{1,3}){3}(?:/\d{1,2})?\b", user_message))
    # Business-group name: Chinese "X 组" pattern. Captures the bare name only,
    # then we strip whitespace and run the prefix-stripper so any type
    # tag the operator accidentally wrote also gets cleaned.
    for m in re.finditer(r"([A-Za-z0-9_\-]+)[\s\u3000]*组", user_message):
        out.append(m.group(1).strip())
    # Hostname-like tokens: lowercase letters / digits / hyphens. We
    # only take tokens that are at least 2 chars long to avoid grabbing
    # single-letter words like `“a”` / `“1”`. Skip tokens immediately
    # followed by `:` (a type tag) or `组` (a Chinese group name) --
    # those are handled by the regexes above so we would just be
    # adding noise like `group` from `扫描 group:test 组`.
    for m in re.finditer(r"\b([a-z][a-z0-9\-]{1,30})\b(?![组:])", user_message):
        out.append(m.group(1))
    cleaned = _strip_target_prefixes(out)
    # Dedupe while preserving order.
    seen: set[str] = set()
    deduped: list[str] = []
    for t in cleaned:
        if t and t not in seen:
            seen.add(t)
            deduped.append(t)
    return deduped


def _strip_target_prefixes(targets: list[str]) -> list[str]:
    """Drop type-tag prefixes from LLM-extracted scan targets.

    The classifier prompt tells the LLM to use bare names, but in practice
    it sometimes emits "group:test" / "host:rocky-01" because the operator
    phrased the request as "扫描 test 组" and the LLM mirrors that structure. The
    frontend matches business-group names by exact string equality, so any
    prefix silently breaks the auto-fill (the operator then has to re-pick
    the group from the dropdown). We normalize here so the prompt's intent
    is enforced regardless of LLM obedience.
    """
    out: list[str] = []
    for t in targets:
        if not isinstance(t, str):
            continue
        cleaned = _TARGET_PREFIX_RE.sub("", t).strip()
        if cleaned:
            out.append(cleaned)
    return out


def _with_history(msgs: list[dict], history: list[dict], n: int = 4) -> list[dict]:
    """Append the last ``n`` user/assistant turns to ``msgs`` (S-P2-7).

    Five call sites used to repeat this loop; intent rarely depends on more
    than the last 4 turns, and system prompts must not leak into the LLM.
    """
    for m in history[-n:]:
        if m.get("role") in ("user", "assistant"):
            msgs.append({"role": m["role"], "content": m["content"]})
    return msgs


async def _classify(message: str, history: list[dict], model_id: int | None) -> IntentDecision:
    """Single LLM call to classify intent."""
    adapter = get_model_adapter()
    msgs: list[dict] = [{"role": "system", "content": INTENT_SYSTEM}]
    # only feed the last 4 turns -- intent rarely depends on more context
    _with_history(msgs, history)
    msgs.append({"role": "user", "content": message})
    try:
        result = await adapter.chat_completion(
            messages=msgs, schema=IntentDecision, model_id=model_id
        )
    except ModelNotFoundError:
        # S-P1-4 (V12): the requested model does not exist -- a config
        # problem the operator must fix, not a transient failure. Re-raise
        # so the router answers 404 instead of silently downgrading a
        # high-risk instruction to free-form chat.
        raise
    except Exception as exc:  # noqa: BLE001
        # If classification fails, fall back to chat with the degraded flag
        # set. The router turns that into 503 + audit -- the user's message
        # must NOT silently lose its scan/approval semantics.
        logger.warning("intent_classify_failed", error=str(exc))
        return IntentDecision(
            intent="chat", confidence=0.0, query="", reason=str(exc), degraded=True
        )
    # V9 follow-up: some LLM adapters (notably empty / streaming-cancelled
    # responses in the deepseek-chat path) return None instead of raising.
    # A `None` here used to crash the router 500 lines later when the
    # code blindly read `decision.intent`. We now treat the absent
    # structured response as a classification failure with a clear
    # reason so the operator can see what went wrong in the logs.
    if result is None or not isinstance(result, IntentDecision):
        logger.warning(
            "intent_classify_empty_result",
            result_type=type(result).__name__,
        )
        return IntentDecision(
            intent="chat",
            confidence=0.0,
            query="",
            reason="classifier returned no structured decision",
            degraded=True,
        )
    return result


_SCAN_KEYWORDS = (
    "扫描",
    "扫一下",
    "跑一下",
    "发起扫描",
    "开始扫描",
    "执行扫描",
    "入队扫描",
    "创建任务",
    "创建扫描任务",
    "让它扫",
    "帮我扫",
    "帮它扫",
    "scan",
    "scanner",
    "scanning",
)
_WEB_KEYWORDS = (
    "CVE",
    "cve",
    "0day",
    "0-day",
    "漏洞",
    "被公开",
    "安全事件",
    "企业被入侵",
    "数据泄露",
    "黑产",
    "赛宝上门",
    "APT",
    "apt",
    "最近",
    "行业",
    "新闻",
)
_PROJECT_KEYWORDS = (
    "架构",
    "模块",
    "项目",
    "代码",
    "文档",
    "怎么用",
    "怎么配置",
    "怎么安装",
    "如何使用",
    "怎样",
    "什么是",
    "接入",
    "部署",
    "调试",
    "出错",
    "查看代码",
    "查看文档",
)


_HOST_KEYWORDS = (
    "主机的漏洞",
    "主机漏洞情况",
    "详细介绍某个主机",
    "某台主机的漏洞",
    "某个主机的漏洞",
    "详细介绍",
    "某个主机",
    "某台主机",
    "某主机上",
    "某台服务器",
    "某个 IP",
    "host vulns",
    "host vulnerabilities",
    "vulnerabilities on",
)


_HOSTNAME_RE = re.compile(
    r"(?P<ip>\b\d{1,3}(?:\.\d{1,3}){3}\b)"
    r"|(?P<host>[a-zA-Z][a-zA-Z0-9\-]{1,30}(?:\.[a-zA-Z][a-zA-Z0-9\-]+)*)\b"
)


_HOST_TOKEN_BLACKLIST = frozenset(
    {
        # acronyms / product names that match the hostname regex but
        # are never the operator's intended target
        "cve",
        "apt",
        "api",
        "ssh",
        "vpn",
        "ssl",
        "tls",
        "dns",
        "ipsec",
        "http",
        "https",
        "tcp",
        "udp",
        "icmp",
        "smb",
        "web",
        "app",
        "api",
        "db",
        "os",
        "ui",
        "qa",
        "dev",
        "host",
        "hosts",
        "scan",
        "scanner",
        "scanning",
        "hosts",
        "server",
        "client",
        "master",
        "slave",
        "worker",
        "sys",
        "tcp",
        "udp",
        "nat",
        "lan",
        "wan",
        "vlan",
        "vps",
        "redis",
        "mysql",
        "pgsql",
        "mongo",
        "kafka",
        "docker",
        "k8s",
        "k8",
        "linux",
        "windows",
        "macos",
        "android",
        "ios",
        "x86",
        "x64",
        "arm64",
        "amd64",
        "vlan",
        "vpc",
        "vpn",
    }
)


def _extract_host_candidate(message: str) -> str | None:
    """Best-effort hostname extraction from a free-form question.

    We look for any IP or hostname-shaped token. To avoid false
    positives like `host` / `scan` / `web` / `api` (very common
    English / Chinese-API words), the caller must validate the
    candidate against the actual list of known hosts in the vuln
    store -- only candidates that match a real hostname survive.
    If no real hostname is found the caller can decide whether to
    fall back to a "list all hosts with findings" view.
    """
    if not message:
        return None
    candidates: list[str] = []
    for m in _HOSTNAME_RE.finditer(message):
        if m.group("ip"):
            candidates.append(m.group("ip"))
        elif m.group("host"):
            # Filter out common false-positive tokens (CVE, APT,
            # web, api, ...) that match the regex but are never the
            # operator's intended target. The blacklist is
            # case-insensitive on the lowercased candidate.
            tok = m.group("host")
            if tok.lower() in _HOST_TOKEN_BLACKLIST:
                continue
            # Real hostnames in this system always include a digit
            # (Rocky001) or a hyphen (web-02) or a dot (fqdn). A
            # pure lowercase word without any of those is almost
            # certainly an English / Chinese-API word, not a host.
            if not any(c.isdigit() or c in "-." for c in tok):
                continue
            candidates.append(tok)
    if not candidates:
        return None
    seen: set[str] = set()
    unique: list[str] = []
    for c in candidates:
        if c not in seen:
            seen.add(c)
            unique.append(c)
    return unique[0]


def _format_finding_brief(finding) -> str:
    """One-line summary of a VulnFinding for the LLM context."""
    sev = (finding.ai_severity or finding.severity or "info").upper()
    cve = finding.cve or ""
    cve_part = f" [{cve}]" if cve else ""
    return f"- [{sev}] {finding.name}{cve_part} (status={finding.status})"


def _format_host_brief(host) -> str:
    """One-line summary of a Host for the LLM context."""
    parts = [host.hostname, f"ip={host.ip}", f"os={host.os}"]
    if host.group:
        parts.append(f"group={host.group}")
    parts.append(f"status={host.status}")
    return " ".join(parts)


async def _answer_with_hosts(
    message: str, model_id: int | None, history: list[dict]
) -> tuple[str, list[SourceRef]]:
    """Host vulnerability Q&A: extract a hostname / IP from the user
    message (or fall back to a top-N view), query the vuln store,
    then ask the LLM to summarize. Mirrors `_answer_with_docs` /
    `_answer_with_web` for the chat layer.

    Why this handler: '详细介绍某个主机的漏洞情况' is the kind of
    question an operator asks many times a day. Without a host-
    specific handler we used to dump them into free-form chat
    where the LLM has to admit it has no data. Now we look up
    the real findings, give the LLM a concrete context block, and
    produce an answer grounded in the vuln store.
    """
    adapter = get_model_adapter()
    store = get_vulnscan_store()
    candidate = _extract_host_candidate(message)

    if candidate:
        # Validate against the actual host list so we don't pass
        # nonsense strings (e.g. the user types 'Rocky-001' but
        # the system only has 'Rocky001'). A typo there should fall
        # through to the free-form fallback, not produce a fake
        # "no findings" answer.
        try:
            hosts = await store.list_hosts(hostname=candidate, limit=1)
        except Exception as exc:  # noqa: BLE001
            logger.warning("host_vuln_list_hosts_failed", error=str(exc))
            return (
                f"未能查询主机。{candidate}、：{str(exc)[:200]}",
                [],
            )
        if not hosts:
            return (
                f"没有找到主机。{candidate}、，请检查名禰是否正确。",
                [
                    SourceRef(
                        title="主机不存在",
                        url=None,
                        snippet=f"未在 vulnstore 中找到主机。{candidate}、",
                    )
                ],
            )
        host = hosts[0]
        try:
            findings = await store.list_vulns(VulnFilter(hostname=host.hostname, limit=200))
        except Exception as exc:  # noqa: BLE001
            logger.warning("host_vuln_list_vulns_failed", error=str(exc))
            findings = []
        if not findings:
            return (
                f"主机。{host.hostname}、（{host.ip}）目前没有已知漏洞。",
                [SourceRef(title=host.hostname, url=None, snippet=_format_host_brief(host))],
            )
        brief = "\n".join(_format_finding_brief(f) for f in findings[:30])
        sev_buckets = {
            sev: sum(1 for f in findings if (f.ai_severity or f.severity) == sev)
            for sev in ("critical", "high", "medium", "low", "info")
        }
        sev_str = ", ".join(f"{k}={v}" for k, v in sev_buckets.items() if v)
        ctx = (
            f"主机详情：{_format_host_brief(host)}\n"
            f"漏洞总数：{len(findings)}（仅呈现前 30 条）\n"
            f"严重级别分布：{sev_str}\n\n" + brief
        )
        sources = [
            SourceRef(title=f.hostname, url=None, snippet=_format_finding_brief(f))
            for f in findings[:10]
        ]
    else:
        # No specific host named: show a top-N view so the operator
        # can at least pick one and ask a more specific question.
        try:
            findings = await store.list_vulns(VulnFilter(limit=500))
        except Exception as exc:  # noqa: BLE001
            logger.warning("host_vuln_list_all_failed", error=str(exc))
            findings = []
        if not findings:
            return (
                "当前没有任何主机的漏洞记录。请先在扫描任务里跑一走。",
                [],
            )
        # Bucket by hostname and rank by finding count.
        buckets: dict[str, list] = {}
        for f in findings:
            buckets.setdefault(f.hostname, []).append(f)
        ranked = sorted(buckets.items(), key=lambda kv: (-len(kv[1]), kv[0]))[:5]
        ctx_lines = ["当前有漏洞记录的主机 Top 5（按漏洞数排序）："]
        for host_name, items in ranked:
            sev_counts: dict[str, int] = {}
            for f in items:
                sev = (f.ai_severity or f.severity or "info").lower()
                sev_counts[sev] = sev_counts.get(sev, 0) + 1
            sev_str = ", ".join(
                f"{k}={v}" for k, v in sorted(sev_counts.items(), key=lambda kv: -kv[1])
            )
            ctx_lines.append(f"- {host_name}: {len(items)} 个漏洞 ({sev_str})")
        ctx = "\n".join(ctx_lines)
        sources = []

    msgs: list[dict] = [
        {
            "role": "system",
            "content": (
                "你是 SecAgent 助手。基于下面的主机/漏洞数据回答用户问题。"
                "只引用数据里出现的事实，不要编造；"
                "如果数据为空请明确说。\n\n"
                f"=== 主机/漏洞数据 ===\n{ctx}"
            ),
        },
    ]
    _with_history(msgs, history)
    msgs.append({"role": "user", "content": message})
    try:
        reply = await adapter.chat_completion(messages=msgs, model_id=model_id)
    except Exception as exc:  # noqa: BLE001
        logger.warning("host_vuln_compose_failed", error=str(exc))
        return (
            f"主机漏洞检索完成，但答案生成失败：{str(exc)[:160]}",
            sources,
        )
    return str(reply), sources


def _looks_like_scan_intent(message: str) -> bool:
    """Heuristic: is the user asking to *create* a scan task?

    The LLM classifier is the source of truth for the scan route, but
    when the classifier drops the ball (degraded=True) we still need a
    safety net so an un-routed request can never reach the scan
    executor. We err on the side of "yes this is a scan" -- if a
    keyword fires, the user gets a 503 (safe) instead of a silent
    free-form answer (unsafe).
    """
    if not message:
        return False
    text = message.lower()
    return any(kw in text for kw in _SCAN_KEYWORDS)


async def _degraded_best_effort(
    message: str,
    history: list[dict],
    model_id: int | None,
    classify_reason: str,
) -> tuple[str, list[SourceRef], str]:
    """Pick a handler from lightweight keyword cues and answer the
    user. Returns ``(reply, sources, route)``. Called only when the
    structured classifier has already failed -- the response will be
    flagged as `degraded` upstream so the operator knows the scan
    gate was not evaluated.

    Keyword order is `web > project > freeform` -- web-shaped
    questions (CVE / industry news) need fresh data so we should try
    the search backend first; project questions are LLM-only over a
    small in-process doc index; everything else falls through to a
    plain LLM chat call.
    """
    text = (message or "").lower()
    note = (
        f"⚠️ 意图分类服务未可用（{classify_reason}），"
        "以下回复是根据关键词预估路由后调用的最佳走路。\n\n"
    )
    # Host-shaped questions win over web whenever the message
    # mentions a hostname-shaped token AND a host/web keyword. This
    # catches questions like "web-02 有哪些漏洞" -- the host
    # handler queries the real vuln store, a web search would not.
    # We use the cheap hostname regex (not the validated list) so a
    # typo still falls through -- _answer_with_hosts validates the
    # candidate against the actual host list itself.
    has_host_token = _extract_host_candidate(message) is not None
    if has_host_token and any(kw in text for kw in (_HOST_KEYWORDS + _WEB_KEYWORDS)):
        try:
            reply, sources = await _answer_with_hosts(message, model_id, history)
            return note + reply, sources, "host"
        except Exception:
            pass  # fall through to web
    if any(kw in text for kw in _HOST_KEYWORDS):
        try:
            reply, sources = await _answer_with_hosts(message, model_id, history)
            return note + reply, sources, "host"
        except Exception:
            pass  # fall through to web
    if any(kw in text for kw in _WEB_KEYWORDS):
        try:
            reply, sources = await _answer_with_web(message, model_id, history)
            return note + reply, sources, "web"
        except Exception:
            pass  # fall through to freeform
    if any(kw in text for kw in _PROJECT_KEYWORDS):
        try:
            reply, sources = await _answer_with_docs(message, model_id, history)
            if reply.strip() and not reply.startswith("没有"):
                return note + reply, sources, "project"
        except Exception:
            pass  # fall through to freeform
    reply, sources = await _answer_freeform(message, model_id, history)
    return note + reply, sources, "chat"


async def _degraded_response(
    req: ChatRequest,
    reply: str,
    sources: list[SourceRef],
    route: str,
    spawn_title,
) -> ChatResponse:
    """Persist the degraded turn and build the response (V12 5.9/5.10).

    Kept as a helper so its local variables (assistant_ts / assistant_meta)
    don't clash with the normal path's scope in api_chat, and so the
    degraded path also benefits from conversation persistence + auto-title
    (previously it returned early and the turns vanished on reload).
    """
    assistant_ts: str | None = None
    if req.conversation_id:
        try:
            sources_payload = [s.model_dump() for s in sources]
            assistant_meta: dict = {"route": route, "sources": sources_payload}
            await conv_store.append_message(req.conversation_id, "user", req.message)
            _, persisted = await conv_store.append_message(
                req.conversation_id, "assistant", reply, meta=assistant_meta
            )
            if persisted and isinstance(persisted.get("ts"), str):
                assistant_ts = persisted["ts"]
        except Exception as exc:  # noqa: BLE001
            logger.warning("chat_degraded_persist_failed", error=str(exc))
    spawn_title(req.conversation_id, req.model_id)
    return ChatResponse(
        # route comes from _degraded_best_effort, which only ever returns
        # members of ROUTE ("host"/"web"/"project"/"chat"); cast keeps mypy
        # happy without narrowing the str contract.
        intent=cast(ROUTE, route),
        confidence=0.0,
        reply=reply,
        sources=sources,
        assistant_ts=assistant_ts,
    )


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
    _with_history(msgs, history)
    msgs.append({"role": "user", "content": query})
    reply = await adapter.chat_completion(messages=msgs, model_id=model_id)
    return str(reply), sources


async def _answer_with_web(
    query: str, model_id: int | None, history: list[dict]
) -> tuple[str, list[SourceRef]]:
    """Web Q&A: try multiple search backends, fall back to LLM.

    2026-07-29: the original design only used DuckDuckGo HTML,
    which is blocked in most corporate networks. We now run a 3-tier
    chain:
      1. NVD API (authoritative for CVE ids / recent security data)
      2. DuckDuckGo HTML (general web; blocked in this env)
      3. Bing HTML (general web; reachable in this env)
    Each backend's failure is logged with a distinct prefix. If ALL
    backends return 0 hits we fall through to a direct LLM call so
    the operator still gets a useful response, with a clear note that
    the LLM is answering from its training data (not real-time).
    """
    hits, source = await search_with_fallback(query, limit=6)
    sources: list[SourceRef] = [
        SourceRef(title=h.title, url=h.url, snippet=h.snippet[:200]) for h in hits
    ]

    if not hits:
        # All search backends returned nothing. Be explicit with the
        # operator about what happened and let the LLM answer from
        # its training data (clearly marked as such).
        adapter = get_model_adapter()
        msgs: list[dict] = [
            {
                "role": "system",
                "content": (
                    "你是 SecAgent 助手，专注于安全运营和漏洞情报。\n"
                    "用户问的是实时性较强的问题。\n"
                    "你的训练数据有时间截止；联网搜索全部失败。\n"
                    "请基于训练数据里你确定的内容直接回答，并明确标注你的知识截止时间；"
                    "如果不确定就明确说明你不掌握最新数据，建议用户用更具体的 CVE 编号去 NVD / 官方公告查询。"
                    "不要编造具体 CVE 编号、日期或参考链接。"
                ),
            },
        ]
        _with_history(msgs, history)
        msgs.append({"role": "user", "content": query})
        reply = await adapter.chat_completion(messages=msgs, model_id=model_id)
        note = (
            "（注：所有联网搜索后端在本轮均不可用，以下回答基于模型训练数据，"
            "不是实时漏洞情报。建议对关键决策再查 NVD / 厂商公告二次确认。）\n\n"
        )
        return note + str(reply), []

    # Got hits: send to the LLM with the search context.
    ctx = hits_to_context(hits)
    adapter = get_model_adapter()
    source_label = {
        "nvd": "NVD (美国国家漏洞数据库)",
        "ddg": "DuckDuckGo",
        "bing": "Bing",
    }.get(source, source)
    msgs = [
        {
            "role": "system",
            "content": (
                f"你是 SecAgent 助手。基于下面的 {source_label} 搜索结果回答用户问题。"
                "只引用搜索结果里出现的事实，不要编造；用 [1]/[2] 这样的角标标注来源，"
                '最后单独给一个 "参考资料：" 列表列出对应 URL。\n\n'
                f"=== 搜索结果 ===\n{ctx}"
            ),
        },
    ]
    _with_history(msgs, history)
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

    try:
        decision = await _classify(req.message, req.history, req.model_id)
    except ModelNotFoundError as exc:
        # S-P1-4 (V12): model deleted/missing is a config problem the
        # operator must fix -- explicit 404, not a degraded chat.
        raise HTTPException(status_code=404, detail=str(exc))
    logger.info(
        "chat_routed",
        intent=decision.intent,
        confidence=decision.confidence,
        reason=decision.reason,
    )

    if decision.degraded:
        # S-P1-4 (V12): the classifier failed, so this message was never
        # routed through the scan/approval gates. For free-form
        # questions (CVE lookup, project Q&A, general chat) we still
        # try to answer via the corresponding handler -- the LLM is
        # up, we just could not parse the structured envelope. The
        # scan-route gate is the property we MUST protect (we must
        # not silently create a scan task on an un-routed message),
        # so scan-shaped requests still get 503.
        await get_audit_logger().log(
            event_id=req.conversation_id or "",
            node="api.chat",
            action="chat_classify_degraded",
            actor=current_user.username,
            details={"message": req.message, "reason": decision.reason},
        )
        if _looks_like_scan_intent(req.message):
            # High-risk: the operator typed a scan request but we could
            # not run the gate. Lock it out rather than risk an
            # un-routed task.
            raise HTTPException(
                status_code=503,
                detail="意图分类服务暂不可用，请稍后重试或直接使用具体功能页面",
            )
        # Best-effort answer via the right handler (web / project /
        # freeform). We pick the handler from lightweight keyword cues
        # in the user message so the operator at least gets a useful
        # reply while the classifier is being fixed.
        try:
            deg_reply, deg_sources, deg_route = await _degraded_best_effort(
                req.message,
                req.history,
                req.model_id,
                decision.reason,
            )
            # V12 5.9 (2026-08-02, 问题2 修复): the degraded path used to
            # `return` here, SKIPPING the persistence block below -- the
            # user + assistant turns were never written to the
            # conversation, so reloading the history silently lost them.
            # _degraded_response persists (same shape as the normal path)
            # and builds the ChatResponse -- kept in a helper with distinct
            # variable names so mypy doesn't conflate the degraded str
            # route with the normal path's ROUTE literal below.
            return await _degraded_response(
                req, deg_reply, deg_sources, deg_route, _spawn_title_task
            )
        except Exception as exc:  # noqa: BLE001
            # Even the fallback handler blew up -- the only honest
            # answer is to admit the failure.
            logger.warning("chat_degraded_fallback_failed", error=str(exc))
            raise HTTPException(
                status_code=503,
                detail="意图分类服务暂不可用，请稍后重试或直接使用具体功能页面",
            )

    route: ROUTE = decision.intent
    reply = ""
    sources: list[SourceRef] = []
    try:
        if decision.intent == "scan":
            # S-P1-F2: reuse the ScanIntent the classifier already extracted
            # (one LLM call). Fall back to a dedicated parse call only if the
            # model did not populate scan_intent.
            intent = decision.scan_intent
            if intent is None:
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
                _with_history(msgs, req.history)
                msgs.append({"role": "user", "content": req.message})
                intent = await adapter.chat_completion(
                    messages=msgs,
                    schema=ScanIntent,
                    model_id=req.model_id,
                )
            # Reply text guides the user; the actual intent lives in sources.
            # S-P1-F2-extended: strip LLM-emitted type prefixes (e.g.
            # "group:test" -> "test") so the frontend auto-fill keeps
            # working even if the model ignores the prompt instruction.
            intent.targets = _strip_target_prefixes(list(intent.targets or []))
            # Safety net: the prompt asks the LLM to OMIT a target when
            # it is not 100% sure of the exact form. The operator usually
            # typed something like "扫描 test 组" though, and we would rather
            # not bounce them back. When the structured `targets` is
            # empty, regex-extract the group / IP / hostname from the
            # user message and feed it back into the intent.
            if not intent.targets:
                fallback = _fallback_extract_targets(req.message)
                if fallback:
                    logger.info("chat_targets_fallback", user=req.message[:120], extracted=fallback)
                    intent.targets = fallback
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
        elif decision.intent == "project":
            reply, sources = await _answer_with_docs(
                decision.query or req.message, req.model_id, req.history
            )
        elif decision.intent == "web":
            reply, sources = await _answer_with_web(
                decision.query or req.message, req.model_id, req.history
            )
        else:
            reply, sources = await _answer_freeform(req.message, req.model_id, req.history)
    except ModelNotFoundError as exc:
        raise HTTPException(status_code=404, detail=str(exc))
    except Exception as exc:  # noqa: BLE001
        logger.exception("chat_dispatch_failed")
        raise HTTPException(status_code=502, detail=f"助手调用失败: {exc}")

    # S-P1-F2: persist the user + assistant turn so what the operator sees is
    # exactly what is stored. Previously /chat was stateless, so normal turns
    # vanished on reload and the scan-execute path persisted a *different*
    # reply from a second LLM call. Best-effort: a persist failure must not
    # break the chat response.
    assistant_ts: str | None = None
    if req.conversation_id:
        try:
            # Meta attached to the assistant turn:
            #   route  -- "scan"/"project"/"web"/"chat" so the route tag
            #             re-renders on history reload.
            #   intent -- the structured ScanIntent for the scan route so
            #             the intent card re-renders without a 2nd LLM call.
            #   sources-- the ChatSource list (used by the project/web route
            #             to show references).
            # The frontend already knew the route/intent on the live turn via
            # the response payload, but the historical view only has the
            # persisted message, so we have to write them here.
            sources_payload = [s.model_dump() for s in sources]
            assistant_meta: dict = {"route": route, "sources": sources_payload}
            if route == "scan":
                # `scan` is the ScanIntent model dump from the scan branch above.
                assistant_meta["intent"] = scan
            # Persist user + assistant. The assistant turn returns the
            # actual `ts` PG wrote (microsecond tick + timezone suffix
            # we can't reproduce on the client) -- we hand that back
            # to the frontend in `assistant_ts` so a later
            # patchMessage(task_id) is guaranteed to hit.
            # (assistant_ts declared once above the if; assigning here.)
            await conv_store.append_message(req.conversation_id, "user", req.message)
            _, persisted = await conv_store.append_message(
                req.conversation_id, "assistant", reply, meta=assistant_meta
            )
            if persisted and isinstance(persisted.get("ts"), str):
                assistant_ts = persisted["ts"]
        except Exception as exc:  # noqa: BLE001
            logger.warning("chat_persist_failed", error=str(exc))
        # V12 5.10: auto-title the conversation in the background (the
        # legacy scan-chat route did this; /chat did not, so titles stayed
        # "新对话" forever).
        _spawn_title_task(req.conversation_id, req.model_id)

    return ChatResponse(
        intent=route,
        confidence=decision.confidence,
        reply=reply,
        sources=sources,
        assistant_ts=assistant_ts,
    )
