"""AlienVault OTX threat intelligence query tool."""
import httpx

from src.common.config.settings import get_settings
from src.common.logging.logger import get_logger
from src.knowledge.tools.registry import tool

logger = get_logger(__name__)


@tool(name="otx", description="Query AlienVault OTX for IOC threat intelligence", category="threat_intel")
async def query_otx(ioc: str) -> dict:
    """Query AlienVault OTX for a given IOC."""
    api_key = get_settings().alienvault_otx_api_key
    if not api_key:
        return {"error": "alienvault_otx_api_key not configured"}

    url = f"https://otx.alienvault.com/api/v1/indicators/ip/{ioc}/general"
    try:
        async with httpx.AsyncClient(timeout=15) as client:
            resp = await client.get(url, headers={"X-OTX-API-KEY": api_key})
            if resp.status_code == 200:
                data = resp.json()
                return {
                    "pulse_count": data.get("pulse_info", {}).get("count", 0),
                    "pulses": [p.get("name") for p in data.get("pulse_info", {}).get("pulses", [])[:5]],
                    "reputation": data.get("reputation", 0),
                    "base_indicator": data.get("base_indicator", {}).get("indicator", ""),
                }
            return {"error": f"HTTP {resp.status_code}"}
    except Exception as exc:
        logger.warning("otx_query_error", ioc=ioc, error=str(exc))
        return {"error": str(exc)}

