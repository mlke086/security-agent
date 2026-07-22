"""AlienVault OTX threat intelligence query tool."""

import urllib.parse

import httpx

from src.common.config.settings import get_settings
from src.common.logging.logger import get_logger
from src.knowledge.tools.registry import tool

logger = get_logger(__name__)


@tool(
    name="otx",
    description="Query AlienVault OTX for IOC threat intelligence",
    category="threat_intel",
)
async def query_otx(ioc: str) -> dict:
    """Query AlienVault OTX for a given IOC."""
    api_key = get_settings().alienvault_otx_api_key
    if not api_key:
        return {"error": "alienvault_otx_api_key not configured"}

    # P1-KNOW-04 (2026-07-20): pick the OTX endpoint by IOC type so
    # domains/hashes hit the right path. Previously every IOC went to
    # /indicators/ip/... which 404s on anything non-IP.
    ioc_lc = ioc.strip().lower()
    if _looks_like_sha256(ioc_lc):
        endpoint = f"https://otx.alienvault.com/api/v1/indicators/file/{ioc_lc}/general"
    elif _looks_like_domain(ioc_lc):
        endpoint = f"https://otx.alienvault.com/api/v1/indicators/domain/{ioc_lc}/general"
    elif _looks_like_url(ioc_lc):
        endpoint = f"https://otx.alienvault.com/api/v1/indicators/url/{urllib.parse.quote(ioc_lc, safe='')}/general"
    else:
        # default to IPv4 path
        endpoint = f"https://otx.alienvault.com/api/v1/indicators/ipv4/{ioc_lc}/general"
    url = endpoint
    try:
        async with httpx.AsyncClient(timeout=15) as client:
            resp = await client.get(url, headers={"X-OTX-API-KEY": api_key})
            if resp.status_code == 200:
                data = resp.json()
                return {
                    "pulse_count": data.get("pulse_info", {}).get("count", 0),
                    "pulses": [
                        p.get("name") for p in data.get("pulse_info", {}).get("pulses", [])[:5]
                    ],
                    "reputation": data.get("reputation", 0),
                    "base_indicator": data.get("base_indicator", {}).get("indicator", ""),
                }
            return {"error": f"HTTP {resp.status_code}"}
    except Exception as exc:
        logger.warning("otx_query_error", ioc=ioc, error=str(exc))
        return {"error": str(exc)}


def _looks_like_sha256(s: str) -> bool:
    return len(s) == 64 and all(c in "0123456789abcdef" for c in s)


def _looks_like_domain(s: str) -> bool:
    return "." in s and "/" not in s and ":" not in s


def _looks_like_url(s: str) -> bool:
    return s.startswith(("http://", "https://"))
