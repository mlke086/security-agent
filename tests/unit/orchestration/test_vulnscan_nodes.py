"""Unit tests for vulnscan subgraph nodes."""
from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from src.agents.models import (
    ScanModule,
    ScanPolicy,
    ScanReport,
    ScanResult,
    ScanTask,
    VulnFinding,
)
from src.orchestration.subgraphs.vulnscan.nodes import (
    _build_analysis_prompt,
    _default_state,
    _pub_progress,
    _resolve_targets,
    aggregate,
    collect,
    dispatch,
    generate_report,
    llm_analysis,
    parse_intent,
)


def _vuln(**kw):
    defaults = {
        "finding_id": "f-1", "task_id": "task-1", "agent_id": "agent-a",
        "hostname": "web-01", "category": ScanModule.SYS_VULN,
        "name": "CVE-2024-0001", "cve": "CVE-2024-0001",
        "severity": "high", "ai_severity": "high", "ai_filtered": False,
        "evidence": "...", "fix_advice": "patch", "status": "open",
        "detected_at": "2026-01-01T00:00:00",
    }
    defaults.update(kw)
    return VulnFinding(**defaults)


def _result(task_id="task-1", agent_id="agent-a", is_final=False, batch=1):
    return ScanResult(
        task_id=task_id, agent_id=agent_id, hostname="web-01",
        findings=[_vuln().model_dump()], batch=batch, is_final=is_final,
        ts="2026-01-01T00:00:00",
    )


class TestDefaultState:
    def test_dialog_source(self):
        state = _default_state("dialog", "scan web")
        assert state["source"] == "dialog"
        assert state["intent_text"] == "scan web"
        assert state["targets"] == []
        assert state["status"] == "queued"

    def test_manual_source_with_targets(self):
        state = _default_state("manual", targets=["host-a", "host-b"], modules=["sys_vuln"])
        assert state["source"] == "manual"
        assert state["targets"] == ["host-a", "host-b"]
        assert state["modules"] == ["sys_vuln"]

    def test_manual_source_default_modules(self):
        state = _default_state("manual", targets=["host-a"])
        assert state["modules"] == ["sys_vuln", "baseline"]


class TestParseIntent:
    @pytest.mark.asyncio
    async def test_manual_source_passes_through(self):
        state = _default_state("manual", targets=["host-a"])
        result = await parse_intent(state)
        assert result["status"] == "dispatching"

    @pytest.mark.asyncio
    async def test_dialog_no_intent_text(self):
        state = _default_state("dialog", intent_text=None)
        result = await parse_intent(state)
        assert result["error"] is not None
        assert result["status"] == "failed"

    @pytest.mark.asyncio
    async def test_dialog_empty_intent_text(self):
        state = _default_state("dialog", intent_text="")
        result = await parse_intent(state)
        assert result["error"] is not None
        assert result["status"] == "failed"

    @pytest.mark.asyncio
    async def test_dialog_llm_parses_intent(self):
        from src.agents.models import ScanIntent

        state = _default_state("dialog", intent_text="scan web servers for vulns")
        mock_adapter = AsyncMock()
        mock_intent = ScanIntent(targets=["web-01", "web-02"], modules=[ScanModule.SYS_VULN])
        mock_adapter.chat_completion.return_value = mock_intent

        with patch("src.knowledge.models.adapter.get_model_adapter", return_value=mock_adapter):
            result = await parse_intent(state)
            assert result["status"] == "dispatching"
            assert result["targets"] == ["web-01", "web-02"]
            assert result["modules"] == ["ScanModule.SYS_VULN"]

    @pytest.mark.asyncio
    async def test_dialog_llm_fails_gracefully(self):
        state = _default_state("dialog", intent_text="scan")
        mock_adapter = AsyncMock()
        mock_adapter.chat_completion.side_effect = RuntimeError("LLM down")

        with patch("src.knowledge.models.adapter.get_model_adapter", return_value=mock_adapter):
            result = await parse_intent(state)
            assert result["status"] == "failed"
            assert "LLM down" in result["error"]


class TestDispatch:
    @pytest.mark.asyncio
    async def test_dispatch_no_agents_found(self):
        state = _default_state("manual", targets=["host-a"])
        mock_store = AsyncMock()
        mock_store.save_task = AsyncMock()
        mock_gateway = MagicMock()

        with (
            patch("src.orchestration.subgraphs.vulnscan.nodes.get_vulnscan_store", return_value=mock_store),
            patch("src.orchestration.subgraphs.vulnscan.nodes.get_agent_gateway", return_value=mock_gateway),
            patch("src.orchestration.subgraphs.vulnscan.nodes._resolve_targets", return_value=[]),
            patch("redis.asyncio.from_url", return_value=AsyncMock()),
            patch("src.common.config.settings.get_settings", return_value=MagicMock(redis_url="redis://x")),
        ):
            result = await dispatch(state)
            assert result["status"] == "failed"
            assert "No target agents" in result["error"]


class TestCollect:
    @pytest.mark.asyncio
    async def test_collect_with_final_result(self):
        state = _default_state("manual", targets=["host-a"])
        state["total_targets"] = 1
        state["task"] = ScanTask(
            task_id=state["task_id"], source="manual", targets=["agent-a"],
            policy=ScanPolicy(), status="scanning",
            stats={"total": 1, "done": 0, "failed": 0},
        )
        result = _result(task_id=state["task_id"], is_final=True)
        mock_store = AsyncMock()
        mock_store.list_results.return_value = [result]
        mock_store.update_task = AsyncMock()

        with (
            patch("src.orchestration.subgraphs.vulnscan.nodes.get_vulnscan_store", return_value=mock_store),
            patch("redis.asyncio.from_url", return_value=AsyncMock()),
            patch("src.common.config.settings.get_settings", return_value=MagicMock(redis_url="redis://x")),
        ):
            new_state = await collect(state)
            assert new_state["status"] == "analyzing"
            assert new_state["received_results"] == 1

    @pytest.mark.asyncio
    async def test_collect_not_all_done_yet(self):
        state = _default_state("manual", targets=["host-a"])
        state["total_targets"] = 2  # waiting for 2 agents, only 1 done
        state["task"] = ScanTask(
            task_id=state["task_id"], source="manual", targets=["agent-a", "agent-b"],
            policy=ScanPolicy(), status="scanning",
            stats={"total": 2, "done": 0, "failed": 0},
        )
        result = _result(task_id=state["task_id"], is_final=True)
        mock_store = AsyncMock()
        mock_store.list_results.return_value = [result]
        mock_store.update_task = AsyncMock()

        with (
            patch("src.orchestration.subgraphs.vulnscan.nodes.get_vulnscan_store", return_value=mock_store),
            patch("redis.asyncio.from_url", return_value=AsyncMock()),
            patch("src.common.config.settings.get_settings", return_value=MagicMock(redis_url="redis://x")),
        ):
            new_state = await collect(state)
            assert new_state["status"] == "scanning"
            assert new_state["received_results"] == 1


class TestAggregate:
    @pytest.mark.asyncio
    async def test_aggregate_dedup_by_cve(self):
        state = _default_state("manual", targets=["host-a"])
        # aggregate reads from store.list_results(), not from collected_findings
        f1 = _vuln(finding_id="f-1", cve="CVE-2024-0001")
        f2 = _vuln(finding_id="f-2", cve="CVE-2024-0001")  # same cve+name -> dedup
        f3 = _vuln(finding_id="f-3", cve="CVE-2024-0002")
        mock_store = AsyncMock()
        mock_store.list_results.return_value = [
            ScanResult(task_id=state["task_id"], agent_id="a", hostname="h1",
                       findings=[f1.model_dump(), f2.model_dump()], batch=1, is_final=True, ts=""),
            ScanResult(task_id=state["task_id"], agent_id="b", hostname="h2",
                       findings=[f3.model_dump()], batch=2, is_final=True, ts=""),
        ]
        mock_store.save_vulns = AsyncMock()

        with patch("src.orchestration.subgraphs.vulnscan.nodes.get_vulnscan_store", return_value=mock_store):
            new_state = await aggregate(state)
            assert len(new_state["collected_findings"]) == 2

    @pytest.mark.asyncio
    async def test_aggregate_no_findings(self):
        state = _default_state("manual", targets=["host-a"])
        mock_store = AsyncMock()
        mock_store.list_results.return_value = []
        mock_store.save_vulns = AsyncMock()

        with patch("src.orchestration.subgraphs.vulnscan.nodes.get_vulnscan_store", return_value=mock_store):
            new_state = await aggregate(state)
            assert new_state["collected_findings"] == []


class TestBuildAnalysisPrompt:
    def test_builds_prompt_with_findings(self):
        findings = [
            _vuln(finding_id="f-1").model_dump(),
            _vuln(
                finding_id="f-2", cve=None,
                name="Weak SSH config", category=ScanModule.BASELINE, severity="medium",
            ).model_dump(),
        ]
        prompt = _build_analysis_prompt(findings)
        assert "f-1" in prompt
        assert "f-2" in prompt
        assert "high" in prompt

    def test_builds_prompt_empty(self):
        prompt = _build_analysis_prompt([])
        # Empty findings just produces the prompt template with empty array
        assert "Findings:" in prompt
        assert "[]" in prompt


class TestLLMAnalysis:
    @pytest.mark.asyncio
    async def test_llm_analysis_with_findings_calls_llm(self):
        state = _default_state("manual", targets=["host-a"])
        f1 = _vuln(finding_id="f-1", cve="CVE-2024-0001", severity="critical").model_dump()
        state["collected_findings"] = [f1]

        mock_adapter = AsyncMock()
        from pydantic import BaseModel
        class AF(BaseModel):
            finding_id: str = "f-1"
            ai_severity: str = "critical"
            ai_filtered: bool = False
            reason: str = "real vuln"
            fix_advice: str = "patch now"
        class AR(BaseModel):
            analyzed: list[AF]
        mock_adapter.chat_completion.return_value = AR(analyzed=[AF()])
        mock_store = AsyncMock()
        mock_store.update_vuln = AsyncMock()

        with (
            patch("src.knowledge.models.adapter.get_model_adapter", return_value=mock_adapter),
            patch("src.orchestration.subgraphs.vulnscan.nodes.get_vulnscan_store", return_value=mock_store),
            patch("src.orchestration.subgraphs.vulnscan.nodes._pub_progress", AsyncMock()),
        ):
            result = await llm_analysis(state)
            assert result["status"] == "reporting"
            mock_store.update_vuln.assert_called()

    @pytest.mark.asyncio
    async def test_llm_analysis_no_findings_skips(self):
        state = _default_state("manual", targets=["host-a"])
        state["collected_findings"] = []
        result = await llm_analysis(state)
        assert result["status"] == "reporting"

    @pytest.mark.asyncio
    async def test_llm_analysis_llm_fails_gracefully(self):
        state = _default_state("manual", targets=["host-a"])
        f1 = _vuln(finding_id="f-1", cve="CVE-2024-0001", severity="high").model_dump()
        state["collected_findings"] = [f1]

        mock_adapter = AsyncMock()
        mock_adapter.chat_completion.side_effect = RuntimeError("timeout")

        with (
            patch("src.knowledge.models.adapter.get_model_adapter", return_value=mock_adapter),
            patch("src.orchestration.subgraphs.vulnscan.nodes._pub_progress", AsyncMock()),
        ):
            result = await llm_analysis(state)
            assert result["status"] == "reporting"


class TestPubProgress:
    @pytest.mark.asyncio
    async def test_pub_progress_publishes(self):
        mock_redis = AsyncMock()
        mock_redis.publish = AsyncMock()

        with patch("src.common.config.settings.get_settings", return_value=MagicMock(redis_url="redis://x")):
            with patch("redis.asyncio.from_url", return_value=mock_redis):
                await _pub_progress("task-1", "scan", "running", "step 1 of 3")
                mock_redis.publish.assert_called_once()

    @pytest.mark.asyncio
    async def test_pub_progress_handles_redis_failure(self):
        mock_redis = AsyncMock()
        mock_redis.publish.side_effect = RuntimeError("redis down")

        with patch("src.common.config.settings.get_settings", return_value=MagicMock(redis_url="redis://x")):
            with patch("redis.asyncio.from_url", return_value=mock_redis):
                await _pub_progress("task-1", "scan", "running", "step")


class TestGenerateReport:
    @pytest.mark.asyncio
    async def test_report_with_findings(self):
        state = _default_state("manual", targets=["host-a"])
        v = _vuln()
        mock_store = AsyncMock()
        mock_store.list_vulns.return_value = [v]
        mock_store.save_report = AsyncMock()
        mock_store.update_task = AsyncMock()

        mock_adapter = AsyncMock()
        mock_adapter.chat_completion.return_value = "summary text"

        with (
            patch("src.orchestration.subgraphs.vulnscan.nodes.get_vulnscan_store", return_value=mock_store),
            patch("src.knowledge.models.adapter.get_model_adapter", return_value=mock_adapter),
            patch("redis.asyncio.from_url", return_value=AsyncMock()),
            patch("src.common.config.settings.get_settings", return_value=MagicMock(redis_url="redis://x")),
            patch("src.orchestration.subgraphs.vulnscan.nodes._pub_progress", AsyncMock()),
        ):
            result = await generate_report(state)
            assert result["status"] == "completed"
            report = result["report"]
            assert isinstance(report, ScanReport)
            assert report.stats["total"] == 1

    @pytest.mark.asyncio
    async def test_report_no_vulns(self):
        state = _default_state("manual", targets=["host-a"])
        mock_store = AsyncMock()
        mock_store.list_vulns.return_value = []
        mock_store.save_report = AsyncMock()
        mock_store.update_task = AsyncMock()

        with (
            patch("src.orchestration.subgraphs.vulnscan.nodes.get_vulnscan_store", return_value=mock_store),
            patch("redis.asyncio.from_url", return_value=AsyncMock()),
            patch("src.common.config.settings.get_settings", return_value=MagicMock(redis_url="redis://x")),
            patch("src.orchestration.subgraphs.vulnscan.nodes._pub_progress", AsyncMock()),
        ):
            result = await generate_report(state)
            assert result["status"] == "completed"
            assert "no vulnerabilities" in result["report"].summary.lower()

    @pytest.mark.asyncio
    async def test_report_sorts_by_severity(self):
        state = _default_state("manual", targets=["host-a"])
        critical = _vuln(finding_id="f-c", severity="critical", name="CVE-CRIT")
        medium = _vuln(finding_id="f-m", severity="medium", name="CVE-MED")
        high = _vuln(finding_id="f-h", severity="high", name="CVE-HIGH")
        mock_store = AsyncMock()
        mock_store.list_vulns.return_value = [medium, high, critical]
        mock_store.save_report = AsyncMock()
        mock_store.update_task = AsyncMock()

        mock_adapter = AsyncMock()
        mock_adapter.chat_completion.return_value = "Scan summary"

        with (
            patch("src.orchestration.subgraphs.vulnscan.nodes.get_vulnscan_store", return_value=mock_store),
            patch("src.knowledge.models.adapter.get_model_adapter", return_value=mock_adapter),
            patch("redis.asyncio.from_url", return_value=AsyncMock()),
            patch("src.common.config.settings.get_settings", return_value=MagicMock(redis_url="redis://x")),
            patch("src.orchestration.subgraphs.vulnscan.nodes._pub_progress", AsyncMock()),
        ):
            result = await generate_report(state)
            top = result["report"].top_vulns
            assert top[0]["name"] == "CVE-CRIT"
            assert top[1]["name"] == "CVE-HIGH"
            assert top[2]["name"] == "CVE-MED"

    @pytest.mark.asyncio
    async def test_report_recommendations(self):
        state = _default_state("manual", targets=["host-a"])
        critical = _vuln(finding_id="f-c", severity="critical")
        baseline = _vuln(
            finding_id="f-b", severity="low", cve=None,
            category=ScanModule.BASELINE, name="Weak password policy",
        )
        mock_store = AsyncMock()
        mock_store.list_vulns.return_value = [critical, baseline]
        mock_store.save_report = AsyncMock()
        mock_store.update_task = AsyncMock()

        mock_adapter = AsyncMock()
        mock_adapter.chat_completion.return_value = "summary"

        with (
            patch("src.orchestration.subgraphs.vulnscan.nodes.get_vulnscan_store", return_value=mock_store),
            patch("src.knowledge.models.adapter.get_model_adapter", return_value=mock_adapter),
            patch("redis.asyncio.from_url", return_value=AsyncMock()),
            patch("src.common.config.settings.get_settings", return_value=MagicMock(redis_url="redis://x")),
            patch("src.orchestration.subgraphs.vulnscan.nodes._pub_progress", AsyncMock()),
        ):
            result = await generate_report(state)
            recs = result["report"].recommendations
            assert any("Critical" in r for r in recs)
            # str(ScanModule.BASELINE) == "ScanModule.BASELINE" which contains "baseline" (case-insensitive)
            assert any("Baseline" in r for r in recs)
            assert any("remediation" in r.lower() for r in recs)

    @pytest.mark.asyncio
    async def test_report_llm_summary_fails_gracefully(self):
        state = _default_state("manual", targets=["host-a"])
        v = _vuln()
        mock_store = AsyncMock()
        mock_store.list_vulns.return_value = [v]
        mock_store.save_report = AsyncMock()
        mock_store.update_task = AsyncMock()

        mock_adapter = AsyncMock()
        mock_adapter.chat_completion.side_effect = RuntimeError("LLM timeout")

        with (
            patch("src.orchestration.subgraphs.vulnscan.nodes.get_vulnscan_store", return_value=mock_store),
            patch("src.knowledge.models.adapter.get_model_adapter", return_value=mock_adapter),
            patch("redis.asyncio.from_url", return_value=AsyncMock()),
            patch("src.common.config.settings.get_settings", return_value=MagicMock(redis_url="redis://x")),
            patch("src.orchestration.subgraphs.vulnscan.nodes._pub_progress", AsyncMock()),
        ):
            result = await generate_report(state)
            assert result["status"] == "completed"
            assert "Scan completed" in result["report"].summary
