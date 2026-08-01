"""Web search for the chat assistant.

We use DuckDuckGo's HTML endpoint because it needs no API key and works in
most environments without proxy headaches. Operators behind corporate firewalls
should set ``web_search_proxy`` in ``.env`` (already supported via the existing
HTTP_PROXY env var).

The HTML parser is intentionally hand-rolled -- the page structure has been
stable since 2018 and writing 50 lines of regex keeps the dependency surface
to ``httpx`` only.

2026-07-29: added an NVD API backend (authoritative for CVE queries) and a
Bing HTML fallback, exposed through :func:`search_with_fallback`. The chain
is NVD -> DuckDuckGo -> Bing -> (caller LLM fallback). This keeps the chat
assistant from hallucinating CVE details when DDG is blocked by egress.
"""

from __future__ import annotations

import html
import json
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


# V9 3.5 (2026-07-30): when DDG returns 0 hits consistently we
# remember it for DDG_DEAD_TTL_SEC so the next query doesn't wait
# 8 seconds on a dead egress. Cleared automatically on TTL expiry.
_DDG_DEAD_TTL_SEC = 300.0
_ddg_unreachable_since: float | None = None


def _ddg_likely_dead() -> bool:
    return _ddg_unreachable_since is not None


def _mark_ddg_dead() -> None:
    import time as _time_ddg

    global _ddg_unreachable_since
    _ddg_unreachable_since = _time_ddg.monotonic()


def _maybe_clear_ddg_dead() -> None:
    import time as _time_ddg

    global _ddg_unreachable_since
    if _ddg_unreachable_since is None:
        return
    if _time_ddg.monotonic() - _ddg_unreachable_since > _DDG_DEAD_TTL_SEC:
        _ddg_unreachable_since = None


# ---------------------------------------------------------------------------
# NVD API -- authoritative source for CVE / vulnerability queries.
# Structured JSON (CVE id, description, CVSS, references), no anti-bot, and
# the anonymous tier (5 req/30s) is plenty for chat volume. Honors the
# ``nvd_proxy`` setting.
# ---------------------------------------------------------------------------

_NVD_API = "https://services.nvd.nist.gov/rest/json/cves/2.0"
_CVE_ID_RE = re.compile(r"CVE-\d{4}-\d{4,7}", re.IGNORECASE)


def looks_like_cve_query(query: str) -> str | None:
    """Return the explicit CVE id if the user typed one, else None.

    Used to short-circuit straight to the NVD API. Matches forms like
    'CVE-2024-3094', 'cve-2024-3094', or 'CVE-2024-3094 xz backdoor'.
    """
    if not query:
        return None
    m = _CVE_ID_RE.search(query)
    return m.group(0).upper() if m else None


async def search_nvd(
    query: str, limit: int = 5, timeout_sec: float | None = None
) -> list[WebSearchHit]:
    """Look up a specific CVE id (or run a keyword search) via the NVD API.

    If the query contains a CVE id we hit /cves/2.0 with cveId=... (exact
    match, max 1 record). Otherwise we run a keywordSearch, which NVD
    returns sorted by publish date desc. (Date-range params like
    lastModStartDate require a matching lastModEndDate or NVD 404s, so we
    omit them.)
    """
    if not query.strip():
        return []
    settings = get_settings()
    proxy = settings.nvd_proxy or None
    # V9 3.5 (2026-07-30): honour settings.nvd_timeout_sec (rules_sync.py
    # already reads it) so operators can tune the network budget in one
    # place. Falls back to the legacy 8s default.
    if timeout_sec is None:
        timeout_sec = float(getattr(settings, "nvd_timeout_sec", 30) or 30)
    cve_id = looks_like_cve_query(query)
    params: dict[str, str | int] = {"resultsPerPage": max(1, min(limit, 20))}
    if cve_id:
        params["cveId"] = cve_id
    else:
        # keywordSearch alone -- NVD returns results sorted by publish date
        # desc by default. Do NOT add lastModStartDate without lastModEndDate:
        # an unpaired date range makes NVD return 404.
        params["keywordSearch"] = query[:200]
    try:
        async with httpx.AsyncClient(
            timeout=timeout_sec,
            headers={"User-Agent": _USER_AGENT},
            proxy=proxy,
        ) as client:
            resp = await client.get(_NVD_API, params=params)
        if resp.status_code != 200:
            logger.warning("nvd_search_status", code=resp.status_code)
            return []
        data = json.loads(resp.text)
        hits: list[WebSearchHit] = []
        for item in (data.get("vulnerabilities") or [])[:limit]:
            cve = item.get("cve") or {}
            cid = cve.get("id", "")
            descs = cve.get("descriptions") or []
            desc_en = next((d.get("value", "") for d in descs if d.get("lang") == "en"), "")
            metrics = (
                cve.get("metrics", {}).get("cvssMetricV31")
                or cve.get("metrics", {}).get("cvssMetricV30")
                or cve.get("metrics", {}).get("cvssMetricV2")
                or []
            )
            score = ""
            severity = ""
            for m in metrics:
                cvss = m.get("cvssData") or {}
                if cvss.get("baseScore") is not None:
                    score = str(cvss["baseScore"])
                    severity = cvss.get("baseSeverity") or m.get("baseSeverity") or ""
                    break
            refs = [r.get("url") for r in cve.get("references") or [] if r.get("url")]
            snippet = desc_en[:300]
            if score:
                snippet = f"[CVSS {score}{(' ' + severity) if severity else ''}] {snippet}"
            hits.append(
                WebSearchHit(
                    title=f"{cid} - {severity or 'NVD entry'}",
                    url=refs[0] if refs else f"https://nvd.nist.gov/vuln/detail/{cid}",
                    snippet=snippet,
                    source="nvd",
                )
            )
        logger.info("nvd_search_done", query=query, cve_id=cve_id, hits=len(hits))
        return hits
    except Exception as exc:  # noqa: BLE001
        logger.warning("nvd_search_failed", query=query, error=str(exc) or type(exc).__name__)
        return []


# ---------------------------------------------------------------------------
# Bing HTML search -- general-web fallback.
# The current egress blocks html.duckduckgo.com but lets www.bing.com
# through, so Bing becomes our general-web fallback. The HTML is messier than
# DDG but the ``b_algo`` <li><h2><a> pattern is stable.
# ---------------------------------------------------------------------------

_BING_HTML = "https://www.bing.com/search"
_BING_UA = (
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 "
    "(KHTML, like Gecko) Chrome/124.0 Safari/537.36"
)


def _parse_bing_html(html_text: str, limit: int) -> list[WebSearchHit]:
    """Extract (title, url, snippet) from Bing's HTML results page."""
    out: list[WebSearchHit] = []
    # Bing wraps each organic result in <li class="b_algo" ...> (with extra
    # attrs like data-id/iid after the class), so match the whole <li ...> tag
    # containing b_algo rather than requiring class="...b_algo..." right
    # before the closing >.
    blocks = re.split(r"<li[^>]*\bb_algo\b[^>]*>", html_text)
    for block in blocks[1:]:
        if len(out) >= limit:
            break
        m_title = re.search(
            r"<h2[^>]*>\s*<a[^>]*href=\"([^\"]+)\"[^>]*>(.*?)</a>",
            block,
            re.IGNORECASE | re.DOTALL,
        )
        if not m_title:
            continue
        url = html.unescape(m_title.group(1))
        if not _is_safe_host(url):
            continue
        title = _strip_tags(m_title.group(2)).strip()
        m_snippet = re.search(r"<p[^>]*>(.*?)</p>", block, re.IGNORECASE | re.DOTALL)
        snippet = _strip_tags(m_snippet.group(1)).strip()[:400] if m_snippet else ""
        if not title or not url:
            continue
        out.append(WebSearchHit(title=title, url=url, snippet=snippet, source="bing"))
    return out


async def search_bing(query: str, limit: int = 6, timeout_sec: float = 8.0) -> list[WebSearchHit]:
    """Search the web via Bing HTML. Returns [] on any failure."""
    if not query.strip():
        return []
    try:
        async with httpx.AsyncClient(
            timeout=timeout_sec,
            headers={"User-Agent": _BING_UA, "Accept-Language": "en-US,en;q=0.9"},
            follow_redirects=True,
        ) as client:
            resp = await client.get(_BING_HTML, params={"q": query, "setlang": "en"})
        if resp.status_code != 200:
            logger.warning("bing_search_status", code=resp.status_code)
            return []
        hits = _parse_bing_html(resp.text, limit=limit)
        logger.info("bing_search_done", query=query, hits=len(hits))
        return hits
    except Exception as exc:  # noqa: BLE001
        logger.warning("bing_search_failed", query=query, error=str(exc) or type(exc).__name__)
        return []


async def search_with_fallback(
    query: str, limit: int = 6, timeout_sec: float = 8.0
) -> tuple[list[WebSearchHit], str]:
    """Try multiple search backends in order; return first non-empty result.

    Order (2026-07-29):
      1. NVD API -- authoritative for CVE ids / recent advisories; only
         tried when the query looks like a CVE.
      2. DuckDuckGo HTML -- general web (blocked in this environment).
      3. Bing HTML -- general web (reachable here, noisier than DDG).
      4. Last-ditch NVD keyword search for general security terms.
      5. Returns ``([], "none")`` so the caller can fall back to the LLM
         direct-answer path.
    """
    if looks_like_cve_query(query):
        hits = await search_nvd(query, limit=limit, timeout_sec=timeout_sec)
        if hits:
            return hits, "nvd"

    _maybe_clear_ddg_dead()
    if _ddg_likely_dead():
        # Skip the wasted 8s timeout; jump to Bing.
        hits = await search_bing(query, limit=limit, timeout_sec=timeout_sec)
        if hits:
            return hits, "bing"
    else:
        hits = await search_web(query, limit=limit, timeout_sec=timeout_sec)
        if hits:
            return hits, "ddg"
        # V9 3.5: DDG returned 0 hits -- likely unreachable in this
        # egress. Mark it so subsequent calls skip the timeout.
        _mark_ddg_dead()

    hits = await search_bing(query, limit=limit, timeout_sec=timeout_sec)
    if hits:
        return hits, "bing"

    if not looks_like_cve_query(query):
        # Last-ditch NVD keyword search for general security terms.
        hits = await search_nvd(query, limit=limit, timeout_sec=timeout_sec)
        if hits:
            return hits, "nvd"

    return [], "none"


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
