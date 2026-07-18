"""Tool registry — decorator-based registration and lookup."""
from __future__ import annotations

from collections.abc import Callable
from typing import Any

_TOOL_REGISTRY: dict[str, dict[str, Any]] = {}


def tool(
    name: str | None = None,
    description: str = "",
    category: str = "general",
) -> Callable:
    """Decorator: register a callable as a tool in the global registry.

    Usage:
        @tool(name="virustotal", category="threat_intel")
        async def query_virustotal(ioc: str) -> dict: ...
    """
    def wrapper(func: Callable) -> Callable:
        tool_name = name or func.__name__
        _TOOL_REGISTRY[tool_name] = {
            "fn": func,
            "description": description or func.__doc__ or "",
            "category": category,
        }
        return func
    return wrapper


def get_tool(name: str) -> Callable | None:
    entry = _TOOL_REGISTRY.get(name)
    return entry["fn"] if entry else None


def list_tools(category: str | None = None) -> list[dict[str, str]]:
    results = []
    for name, entry in _TOOL_REGISTRY.items():
        if category is None or entry["category"] == category:
            results.append({
                "name": name,
                "description": entry["description"],
                "category": entry["category"],
            })
    return results


def call_tool_sync(name: str, *args: Any, **kwargs: Any) -> Any:
    """Synchronously call a registered tool (for non-async contexts)."""
    fn = get_tool(name)
    if fn is None:
        raise KeyError(f"Tool '{name}' not registered")
    return fn(*args, **kwargs)


async def call_tool(name: str, *args: Any, **kwargs: Any) -> Any:
    """Call a registered tool (supports both sync and async functions)."""
    fn = get_tool(name)
    if fn is None:
        raise KeyError(f"Tool '{name}' not registered")
    result = fn(*args, **kwargs)
    if hasattr(result, "__await__"):
        return await result
    return result

