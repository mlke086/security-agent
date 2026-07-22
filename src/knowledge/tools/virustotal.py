"""VirusTotal threat intelligence query tool."""

import urllib.parse

import httpx

from src.common.config.settings import get_settings
from src.common.logging.logger import get_logger
from src.knowledge.tools.registry import tool

logger = get_logger(__name__)


@tool(
    name="virustotal",
    description="Query VirusTotal for IOC threat intelligence",
    category="threat_intel",
)
async def query_virustotal(ioc: str, ioc_type: str = "ip") -> dict:
    """Query VirusTotal for a given IOC (IP, domain, hash, URL)."""
    api_key = get_settings().virustotal_api_key
    if not api_key:
        return {"error": "virustotal_api_key not configured"}

    # P1-KNOW-04 (2026-07-20): map ioc_type to the correct VT endpoint.
    # The previous version only handled "ip"; everything else (domain /
    # hash / url) fell through to /search?query=... which 400s on bare
    # indicators and never returns analysis_stats.
    base_urls = {
        "ip": "https://www.virustotal.com/api/v3/ip_addresses/",
        "domain": "https://www.virustotal.com/api/v3/domains/",
        "sha256": "https://www.virustotal.com/api/v3/files/",
        "md5": "https://www.virustotal.com/api/v3/files/",
        "sha1": "https://www.virustotal.com/api/v3/files/",
    }
    base = base_urls.get(ioc_type)
    if base:
        url = base + ioc
    else:
        # Unknown type: URL-encode the query to avoid injection.
        url = "https://www.virustotal.com/api/v3/search?query=" + urllib.parse.quote(ioc, safe="")
    try:
        async with httpx.AsyncClient(timeout=15) as client:
            resp = await client.get(url, headers={"x-apikey": api_key})
            if resp.status_code == 200:
                data = resp.json()
                stats = data.get("data", {}).get("attributes", {}).get("last_analysis_stats", {})
                return {
                    "malicious": stats.get("malicious", 0),
                    "suspicious": stats.get("suspicious", 0),
                    "harmless": stats.get("harmless", 0),
                    "undetected": stats.get("undetected", 0),
                    "reputation": data.get("data", {}).get("attributes", {}).get("reputation", 0),
                }
            return {"error": f"HTTP {resp.status_code}"}
    except Exception as exc:
        logger.warning("virustotal_error", ioc=ioc, error=str(exc))
        return {"error": str(exc)}
