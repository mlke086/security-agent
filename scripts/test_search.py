"""Direct test of the search backends in web_search.py (no HTTP/auth).

V10 4.7 (2026-07-30): OPERATIONAL NOTES
  - This script calls the live search providers (Bing / NVD / DDG)
    directly -- it does NOT mock anything, so it needs outbound
    internet access and may be rate-limited or blocked in some
    networks.
  - Some providers (Bing, DDG) are subject to bot detection and
    may return an empty / captcha response from a CI runner.
    Treat an empty hit list as "provider is angry", not a bug.
  - NOT a unit test. Do NOT add it to CI -- it is a manual
    smoke probe the operator runs after touching
    ``src.agents.chat_search.web_search``. CI runs the pytest
    suite under ``tests/`` only.
  - Exit code 0 == at least one provider returned hits for the
    test query; non-zero == all providers failed (see the printed
    counts to identify which).
"""

import asyncio
import sys

sys.stdout.reconfigure(encoding="utf-8")
sys.path.insert(0, ".")

from src.agents.chat_search.web_search import (  # noqa: E402
    looks_like_cve_query,
    search_bing,
    search_nvd,
    search_web,
    search_with_fallback,
)


def show(hits, label):
    print(f"  --- {label}: {len(hits)} hits ---")
    for h in hits[:3]:
        print(f"    [{h.source}] {h.title[:70]}")
        print(f"        {h.url[:90]}")
        print(f"        {h.snippet[:110]}")


async def main():
    print("=== looks_like_cve_query ===")
    for q in ["CVE-2024-3094", "cve-2021-44228 log4j", "今天天气"]:
        print(f"  {q!r:30} -> {looks_like_cve_query(q)}")

    print("\n=== search_nvd(CVE-2024-3094) [cveId path] ===")
    show(await search_nvd("CVE-2024-3094", limit=3), "nvd-cve")

    print("\n=== search_nvd(keyword: log4j) [keyword path, date-param fixed] ===")
    show(await search_nvd("log4j rce", limit=3), "nvd-keyword")

    print("\n=== search_web(DDG: python asyncio) [expected blocked] ===")
    show(await search_web("python asyncio tutorial", limit=3), "ddg")

    print("\n=== search_bing(python asyncio) ===")
    show(await search_bing("python asyncio tutorial", limit=3), "bing")

    print("\n=== search_with_fallback(CVE-2024-3094) ===")
    hits, src = await search_with_fallback("CVE-2024-3094", limit=3)
    show(hits, f"fallback-cve (source={src})")

    print("\n=== search_with_fallback(log4j 漏洞) ===")
    hits, src = await search_with_fallback("log4j 漏洞", limit=3)
    show(hits, f"fallback-general (source={src})")


asyncio.run(main())
