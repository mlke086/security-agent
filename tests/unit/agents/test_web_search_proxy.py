"""S-P2-20 (V12): httpx proxy kwarg smoke test.

The web_search backends call ``httpx.AsyncClient(proxy=...)``. The
``proxy=`` kwarg is the httpx>=0.28 API name (0.27 already carried both
``proxy`` and deprecated ``proxies``). pyproject.toml pins ``httpx>=0.28,<0.29``
so the constructor must accept ``proxy=`` -- this test fails loudly if the
pin and the code ever drift apart again (a new install would otherwise
silently TypeError -> all search backends fall back to LLM-only).
"""

from unittest.mock import AsyncMock, patch

import httpx

from src.agents.chat_search import web_search


def test_async_client_accepts_proxy_kwarg():
    """The installed httpx (per pyproject pin) must accept proxy=."""
    client = httpx.AsyncClient(proxy="http://localhost:8888")
    assert client is not None
    # no TypeError raised above is the whole point of the smoke test


async def test_search_nvd_passes_proxy_setting():
    """search_nvd must construct the client with the configured proxy."""
    with (
        patch(
            "src.agents.chat_search.web_search.get_settings",
            return_value=type(
                "S",
                (),
                {"nvd_proxy": "http://proxy:3128", "nvd_timeout_sec": 5},
            )(),
        ),
        patch("httpx.AsyncClient") as mock_client,
    ):
        # Mock the async-context-manager plumbing with a fake client whose
        # get() raises immediately; we only care about the constructor args.
        fake_client = AsyncMock()
        fake_client.get = AsyncMock(side_effect=RuntimeError("network down"))
        mock_client.return_value.__aenter__ = AsyncMock(return_value=fake_client)
        mock_client.return_value.__aexit__ = AsyncMock(return_value=False)
        # search_nvd swallows network errors and returns [] -- the proxy
        # kwarg is what we assert on the constructor.
        hits = await web_search.search_nvd("CVE-2024-0001", limit=3)
        assert hits == []
        kwargs = mock_client.call_args.kwargs
        assert kwargs.get("proxy") == "http://proxy:3128", kwargs
