"""Tools — unified tool registry with VirusTotal, OTX, and notification tools."""
import src.knowledge.tools.notifier  # noqa: F401 — register tool
import src.knowledge.tools.otx  # noqa: F401 — register tool
import src.knowledge.tools.virustotal  # noqa: F401 — register tool
from src.knowledge.tools.registry import (
    _TOOL_REGISTRY,
    call_tool,
    call_tool_sync,
    get_tool,
    list_tools,
    tool,
)

__all__ = [
    "tool", "get_tool", "list_tools", "call_tool", "call_tool_sync",
    "_TOOL_REGISTRY",
]
