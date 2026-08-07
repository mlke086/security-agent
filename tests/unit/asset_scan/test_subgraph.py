"""Unit tests for asset-scan subgraph (需求②, mock scanner/LLM/store)."""

from unittest.mock import AsyncMock, patch

import pytest

from src.orchestration.subgraphs.asset_scan.nodes import _parse_ai_json


def _envelope(**over):
    from src.orchestration.task_queue.enqueue import AssetScanEnvelope

    base = dict(
        task_id="t-asset-1",
        source="manual",
        targets=["10.0.0.0/24"],
        engine="fast",
        modules=["discovery", "fingerprint", "cve", "nuclei"],
    )
    base.update(over)
    return AssetScanEnvelope(**base)


@pytest.fixture
def mock_store():
    store = AsyncMock()
    store.save_vulns = AsyncMock()
    store.update_vuln = AsyncMock()
    store.save_report = AsyncMock()
    store.update_task = AsyncMock()
    return store


class _FakeRunner:
    """子进程执行器替身：不真跑 nmap/masscan。"""

    async def run(self, *args, **kwargs):
        return (0, "", "")

    async def close(self):
        return None


@pytest.mark.asyncio
async def test_run_asset_scan_end_to_end(mock_store):
    """完整子图：发现→指纹→匹配→LLM→报告。"""
    from src.orchestration.subgraphs.asset_scan.graph import run_asset_scan

    with (
        patch("src.asset_scan.scanner.discovery.discover_hosts",
              AsyncMock(return_value=["10.0.0.1", "10.0.0.2"])),
        patch("src.asset_scan.scanner.discovery.scan_ports",
              AsyncMock(return_value={"10.0.0.1": [80, 443]})),
        patch("src.orchestration.subgraphs.asset_scan.nodes.get_runner",
              return_value=_FakeRunner()),
        patch("src.orchestration.subgraphs.asset_scan.nodes.parse_nmap_services",
              return_value=[{"port": 80, "name": "http", "product": "nginx",
                             "version": "1.18.0", "cpe": "cpe:/a:nginx:nginx:1.18.0"}]),
        patch("src.orchestration.subgraphs.asset_scan.nodes.load_cve_rules",
              AsyncMock(return_value=[{
                  "id": "CVE-2021-23017", "cve": "CVE-2021-23017",
                  "name": "nginx: vuln", "severity": "high",
                  "check": {"type": "package_version", "name": "nginx", "op": "lt", "value": "1.22.0"},
                  "fix": "upgrade nginx",
              }])),
        patch("src.orchestration.subgraphs.asset_scan.nodes.run_nuclei",
              AsyncMock(return_value=[{
                  "ip": "10.0.0.1", "port": 443, "template_id": "tpl-x",
                  "name": "TLS vuln", "severity": "medium", "cve": None,
              }])),
        patch("src.asset_scan.store.get_asset_store",
              return_value=mock_store),
        patch("src.orchestration.subgraphs.asset_scan.nodes._confirm_cancellation",
              AsyncMock(return_value=False)),
        patch("src.orchestration.subgraphs.asset_scan.nodes._pub_progress", AsyncMock()),
    ):
        result = await run_asset_scan(_envelope())

    assert result["status"] == "completed"
    assert result["alive_hosts"] == ["10.0.0.1", "10.0.0.2"]
    assert result["host_ports"] == {"10.0.0.1": [80, 443]}
    # CPE 匹配 1 条 + nuclei 1 条
    assert len(result["vulns"]) == 2
    assert result["report"] is not None
    assert result["report"]["stats"]["vulns"] == 2
    # 写库：vulns + report + task completed
    mock_store.save_vulns.assert_awaited_once()
    mock_store.save_report.assert_awaited_once()
    mock_store.update_task.assert_awaited_once()
    assert mock_store.update_task.await_args.kwargs["status"] == "completed"


@pytest.mark.asyncio
async def test_parse_intent_rejects_empty_targets():
    from src.orchestration.subgraphs.asset_scan.nodes import parse_intent

    with patch("src.orchestration.subgraphs.asset_scan.nodes._confirm_cancellation",
               AsyncMock(return_value=False)):
        with pytest.raises(ValueError, match="at least one target"):
            await parse_intent({"task_id": "t", "targets": [" ", ""], "engine": "fast"})


@pytest.mark.asyncio
async def test_parse_intent_rejects_bad_engine():
    from src.orchestration.subgraphs.asset_scan.nodes import parse_intent

    with patch("src.orchestration.subgraphs.asset_scan.nodes._confirm_cancellation",
               AsyncMock(return_value=False)):
        with pytest.raises(ValueError, match="unsupported engine"):
            await parse_intent({"task_id": "t", "targets": ["10.0.0.1"], "engine": "quantum"})


@pytest.mark.asyncio
async def test_cancellation_short_circuits(mock_store):
    """取消墓碑存在时各节点返回 cancelled。"""
    from src.orchestration.subgraphs.asset_scan.graph import run_asset_scan

    with (
        patch("src.orchestration.subgraphs.asset_scan.nodes._confirm_cancellation",
              AsyncMock(return_value=True)),
        patch("src.orchestration.subgraphs.asset_scan.nodes._pub_progress", AsyncMock()),
        patch("src.asset_scan.store.get_asset_store",
              return_value=mock_store),
    ):
        result = await run_asset_scan(_envelope())
    assert result["status"] == "cancelled"
    mock_store.save_vulns.assert_not_awaited()


@pytest.mark.asyncio
async def test_llm_unavailable_fallback(mock_store):
    """adapter 不可用时写 fallback（ai_processed=False），流程不中断。"""
    from src.orchestration.subgraphs.asset_scan.nodes import llm_analysis

    state = {
        "task_id": "t-llm",
        "vulns": [{"vuln_id": "v1", "ip": "10.0.0.1", "severity": "high", "name": "x"}],
    }
    with (
        patch("src.orchestration.subgraphs.asset_scan.nodes._confirm_cancellation",
              AsyncMock(return_value=False)),
        patch("src.asset_scan.store.get_asset_store",
              return_value=mock_store),
        patch("src.knowledge.models.adapter.get_model_adapter",
              side_effect=RuntimeError("no adapter")),
    ):
        out = await llm_analysis(state)
    assert out["ai_processed"] is True  # fallback 也标记为已处理（保留原等级）
    assert out["ai_results"][0]["ai_severity"] == "high"
    assert out["ai_results"][0]["ai_processed"] is False
    mock_store.update_vuln.assert_awaited_once()


class TestAiJsonParse:
    def test_plain_json_array(self):
        raw = '[{"vuln_id": "v1", "ai_severity": "critical", "ai_reason": "rce"}]'
        out = _parse_ai_json(raw)
        assert len(out) == 1
        assert out[0]["ai_severity"] == "critical"
        assert out[0]["ai_processed"] is True

    def test_fenced_json(self):
        raw = '```json\n[{"vuln_id": "v2", "ai_severity": "high"}]\n```'
        out = _parse_ai_json(raw)
        assert out[0]["vuln_id"] == "v2"

    def test_garbage(self):
        assert _parse_ai_json("not json at all") == []
        assert _parse_ai_json("") == []
        assert _parse_ai_json("[]") == []
