"""Web search for the chat assistant.

We use DuckDuckGo's HTML endpoint because it needs no API key and works in
most environments without proxy headaches. Operators behind corporate firewalls
should set ``web_search_proxy`` in ``.env`` (already supported via the existing
HTTP_PROXY env var).

The HTML parser is intentionally hand-rolled -- the page structure has been
stable since 2018 and writing 50 lines of regex keeps the dependency surface
to ``httpx`` only.
"""

from __future__ import annotations

import html
import re
from dataclasses import dataclass

import httpx

from src.common.config.settings import get_settings
from src.common.logging.logger import get_logger

logger = get_logger(__name__)

_DDG_HTML = "https://html.duckduckgo.com/html/"
_USER_AGENT = (
    "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 "
    "(KHTML, like Gecko) Chrome/124.0 Safari/537.36"
)

# Result-quality filters: skip results whose URL host matches any of these.
# These either never load (rate-limit / block bots), or are pure SEO noise.
_BLOCK_HOSTS = (
    "facebook.com",
    "twitter.com",
    "youtube.com",
    "tiktok.com",
    "instagram.com",
    "linkedin.com",
    "pinterest.com",
    "reddit.com",  # reddit aggressively blocks
)


@dataclass
class WebSearchHit:
    title: str
    url: str
    snippet: str
    source: str = "duckduckgo"


def _is_safe_host(url: str) -> bool:
    host = url.lower()
    return not any(b in host for b in _BLOCK_HOSTS)


def _parse_html(html_text: str, limit: int) -> list[WebSearchHit]:
    """Pull (title, url, snippet) out of the DDG HTML page.

    DDG HTML wraps each result in a <div class="result ..."> with:
      - <a class="result__a" href="...">TITLE</a>
      - <a class="result__snippet">SNIPPET</a>
    We do a non-greedy match per result block, then URL-decode the DDG
    redirect wrapper (//duckduckgo.com/l/?uddg=<encoded>) so the LLM gets a
    real URL it can cite.
    """
    out: list[WebSearchHit] = []
    # Block-level split. Matches the start of each result.
    blocks = re.split(r'<div[^>]*class="[^"]*\bresult\b[^"]*"', html_text)
    for block in blocks[1:]:
        if len(out) >= limit:
            break
        # Title + URL
        m_title = re.search(
            r'<a[^>]*class="[^"]*\bresult__a\b[^"]*"[^>]*href="([^"]+)"[^>]*>(.*?)</a>',
            block,
            re.IGNORECASE | re.DOTALL,
        )
        if not m_title:
            continue
        url = _unwrap_ddg_url(m_title.group(1))
        if not _is_safe_host(url):
            continue
        title = _strip_tags(m_title.group(2)).strip()
        # Snippet
        m_snippet = re.search(
            r'<a[^>]*class="[^"]*\bresult__snippet\b[^"]*"[^>]*>(.*?)</a>',
            block,
            re.IGNORECASE | re.DOTALL,
        )
        snippet = _strip_tags(m_snippet.group(1)).strip() if m_snippet else ""
        if not title or not url:
            continue
        out.append(WebSearchHit(title=title, url=url, snippet=snippet))
    return out


def _strip_tags(s: str) -> str:
    """Remove HTML tags and decode entities."""
    s = re.sub(r"<[^>]+>", "", s)
    return html.unescape(s).strip()


def _unwrap_ddg_url(url: str) -> str:
    """DDG wraps every result in a redirect; extract the real URL."""
    if "uddg=" in url:
        from urllib.parse import parse_qs, urlparse

        try:
            qs = parse_qs(urlparse(url).query)
            if "uddg" in qs:
                return qs["uddg"][0]
        except Exception:  # noqa: BLE001
            return url
    return url


async def search_web(query: str, limit: int = 6, timeout_sec: float = 8.0) -> list[WebSearchHit]:
    """Search the web via DDG HTML.

    Returns [] on any error (network, parse, rate-limit) -- chat callers must
    treat web search as best-effort. The caller decides whether to surface
    "no results" or fall back to other answers.
    """
    if not query.strip():
        return []
    settings = get_settings()
    proxy = settings.nvd_proxy or None  # NVD proxy also works for general egress
    try:
        async with httpx.AsyncClient(
            timeout=timeout_sec,
            headers={"User-Agent": _USER_AGENT},
            follow_redirects=True,
            proxy=proxy,
        ) as client:
            resp = await client.post(
                _DDG_HTML,
                data={"q": query, "kl": "us-en"},
            )
        if resp.status_code != 200:
            logger.warning("web_search_status", code=resp.status_code)
            return []
        hits = _parse_html(resp.text, limit=limit)
        logger.info("web_search_done", query=query, hits=len(hits))
        return hits
    except Exception as exc:  # noqa: BLE001
        logger.warning("web_search_failed", query=query, error=str(exc))
        return []


async def search_security_news(query: str, limit: int = 5) -> list[WebSearchHit]:
    """Search web restricted to authoritative security domains.

    Used when the LLM detects the user is asking about a CVE / vulnerability
    / exploit / breach -- we restrict to well-known security feeds so we get
    signal not SEO spam.
    """
    full_query = (
        f"{query} site:nvd.nist.gov OR site:exploit-db.com OR site:cve.mitre.org "
        "OR site:securityweek.com OR site:krebsonsecurity.com OR site:theregister.com"
    )
    return await search_web(full_query, limit=limit)


def hits_to_context(hits: list[WebSearchHit]) -> str:
    """Format hits for inclusion in the LLM prompt."""
    if not hits:
        return "(no web results)"
    lines = []
    for i, h in enumerate(hits, 1):
        snip = h.snippet[:300] + ("..." if len(h.snippet) > 300 else "")
        lines.append(f"[{i}] {h.title}\nURL: {h.url}\n{snip}")
    return "\n\n".join(lines)
