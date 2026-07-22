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


class TestNucleiParams:
    """V4.1 (P1-7): regression test for the engine selector + nuclei knobs
    added to vulnscan/graph.py::run_vulnscan. Each must propagate through
    _default_state so dispatch() and the WS scan_command payload see them.
    Without this test the new parameters could be silently dropped (e.g.
    a future refactor forgetting to thread them into _default_state).
    """

    def test_default_engine_is_matcher(self):
        state = _default_state("manual", targets=["host-a"])
        assert state["engine"] == "matcher"
        assert state["nuclei_severity"] == []
        assert state["nuclei_tags"] == []
        assert state["nuclei_templates"] == []
        assert state["nuclei_timeout_sec"] == 0

    def test_nuclei_engine_propagates_all_knobs(self):
        state = _default_state(
            "manual",
            targets=["host-a"],
            engine="nuclei",
            nuclei_severity=["critical", "high"],
            nuclei_tags=["cve", "rce"],
            nuclei_templates=["cves/2024/CVE-2024-0001.yaml"],
            nuclei_timeout_sec=120,
        )
        assert state["engine"] == "nuclei"
        assert state["nuclei_severity"] == ["critical", "high"]
        assert state["nuclei_tags"] == ["cve", "rce"]
        assert state["nuclei_templates"] == ["cves/2024/CVE-2024-0001.yaml"]
        assert state["nuclei_timeout_sec"] == 120

    def test_nuclei_knobs_default_to_empty(self):
        # Engine=nuclei but no knobs -- state still well-formed (empty lists),
        # never raises (a previous draft crashed when nuclei_severity=None).
        state = _default_state("manual", targets=["host-a"], engine="nuclei")
        assert state["engine"] == "nuclei"
        assert state["nuclei_severity"] == []
        assert state["nuclei_tags"] == []
        assert state["nuclei_templates"] == []
        assert state["nuclei_timeout_sec"] == 0


def _host(agent_id, hostname, ip, group=None):
    from src.agents.models import Host
    return Host(agent_id=agent_id, hostname=hostname, ip=ip, group=group,
                os="linux", arch="amd64", kernel="5.x")


class TestResolveTargets:
    """Covers P1-VULN-02: a group target must expand to ALL agents in the
    group, not just the first match."""

    @pytest.mark.asyncio
    async def test_group_target_returns_all_group_members(self):
        hosts = [
            _host("agent-1", "web-01", "10.0.0.1", group="prod"),
            _host("agent-2", "web-02", "10.0.0.2", group="prod"),
            _host("agent-3", "db-01", "10.0.0.3", group="db"),
            _host("agent-4", "web-03", "10.0.0.4", group="prod"),
        ]
        mock_store = AsyncMock()
        mock_store.list_hosts = AsyncMock(return_value=hosts)
        with patch("src.orchestration.subgraphs.vulnscan.nodes.get_vulnscan_store", return_value=mock_store):
            result = await _resolve_targets(["prod"])
        assert sorted(result) == ["agent-1", "agent-2", "agent-4"]

    @pytest.mark.asyncio
    async def test_hostname_target_returns_single(self):
        hosts = [_host("agent-1", "web-01", "10.0.0.1", group="prod")]
        mock_store = AsyncMock()
        mock_store.list_hosts = AsyncMock(return_value=hosts)
        with patch("src.orchestration.subgraphs.vulnscan.nodes.get_vulnscan_store", return_value=mock_store):
            result = await _resolve_targets(["web-01"])
        assert result == ["agent-1"]

    @pytest.mark.asyncio
    async def test_mixed_targets_dedup(self):
        """agent_id + its group should not double-count the same agent."""
        hosts = [
            _host("agent-1", "web-01", "10.0.0.1", group="prod"),
            _host("agent-2", "web-02", "10.0.0.2", group="prod"),
        ]
        mock_store = AsyncMock()
        mock_store.list_hosts = AsyncMock(return_value=hosts)
        with patch("src.orchestration.subgraphs.vulnscan.nodes.get_vulnscan_store", return_value=mock_store):
            result = await _resolve_targets(["agent-1", "prod"])
        assert sorted(result) == ["agent-1", "agent-2"]

    @pytest.mark.asyncio
    async def test_no_match_returns_targets_as_is(self):
        mock_store = AsyncMock()
        mock_store.list_hosts = AsyncMock(return_value=[])
        with patch("src.orchestration.subgraphs.vulnscan.nodes.get_vulnscan_store", return_value=mock_store):
            result = await _resolve_targets(["unknown-agent-id"])
        assert result == ["unknown-agent-id"]


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
            assert result["modules"] == ["sys_vuln"]

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
        mock_store.update_task = AsyncMock()
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
            assert result["total_targets"] == 0
            # P1-VULN-01: failure must be persisted to ES so /tasks/{id}
            # sees "failed" instead of polling collect for 30 minutes.
            failed_updates = [
                c for c in mock_store.update_task.call_args_list
                if c.kwargs.get("status") == "failed"
            ]
            assert failed_updates, "expected an update_task(status=failed) call"
            assert failed_updates[0].kwargs.get("error") == "No target agents found"



    # F1.4a (2026-07-21): regression test for the silent 30-minute timeout.
    # The previous collect() read stats["failed"] from the in-memory task
    # (always 0) and overwrote the dispatch-time failure count back to 0.
    # Real path: task 141217b6 sat in "scanning" for 1800s because no
    # agent ever responded and the dispatch-time failed=1 was lost.
    @pytest.mark.asyncio
    async def test_collect_fails_fast_when_dispatch_reported_failed(self):
        state = _default_state("manual", targets=["host-a"])
        state["total_targets"] = 1
        state["task"] = ScanTask(
            task_id=state["task_id"], source="manual", targets=["host-a"],
            policy=ScanPolicy(timeout_sec=1800), status="scanning",
            stats={"total": 1, "done": 0, "failed": 0},
        )
        result = _result(task_id=state["task_id"], is_final=False)
        mock_store = AsyncMock()
        mock_store.list_results.return_value = [result]
        mock_store.update_task = AsyncMock()
        mock_store.get_task = AsyncMock(return_value=ScanTask(
            task_id=state["task_id"], source="manual", targets=["host-a"],
            policy=ScanPolicy(), status="scanning",
            stats={"total": 1, "done": 0, "failed": 1},
        ))
        with (
            patch("src.orchestration.subgraphs.vulnscan.nodes.get_vulnscan_store", return_value=mock_store),
            patch("redis.asyncio.from_url", return_value=AsyncMock()),
            patch("src.common.config.settings.get_settings", return_value=MagicMock(redis_url="redis://x")),
        ):
            new_state = await collect(state)
        assert new_state["status"] == "analyzing"
        assert new_state["received_results"] == 0

    # F1.4c: dispatch must publish to vulnscan:task:{id} so SSE pushes the
    # failure event (no 30-min "waiting for agent" stall on the frontend).
    @pytest.mark.asyncio
    async def test_dispatch_no_agents_publishes_sse(self):
        state = _default_state("manual", targets=["host-a"])
        mock_store = AsyncMock()
        mock_store.save_task = AsyncMock()
        mock_store.update_task = AsyncMock()
        mock_gateway = MagicMock()
        fake_redis = AsyncMock()
        fake_redis.publish = AsyncMock()
        with (
            patch("src.orchestration.subgraphs.vulnscan.nodes.get_vulnscan_store", return_value=mock_store),
            patch("src.orchestration.subgraphs.vulnscan.nodes.get_agent_gateway", return_value=mock_gateway),
            patch("src.orchestration.subgraphs.vulnscan.nodes._resolve_targets", return_value=[]),
            patch("redis.asyncio.from_url", return_value=fake_redis),
            patch("src.common.config.settings.get_settings", return_value=MagicMock(redis_url="redis://x")),
        ):
            await dispatch(state)
        published = [c for c in fake_redis.publish.call_args_list
                     if c.args and c.args[0] == f"vulnscan:task:{state['task_id']}"]
        assert published, "dispatch failure must publish to vulnscan:task SSE channel"


class TestCollect:
    @pytest.mark.asyncio
    async def test_collect_short_circuits_on_failed_dispatch(self):
        """P1-VULN-01: when dispatch already failed, collect must NOT poll ES
        for 30 minutes -- it returns failed immediately."""
        state = _default_state("manual", targets=["host-a"])
        state["total_targets"] = 0
        state["status"] = "failed"
        state["task"] = ScanTask(
            task_id=state["task_id"], source="manual", targets=[],
            policy=ScanPolicy(), status="failed",
            stats={"total": 0, "done": 0, "failed": 0},
        )
        mock_store = AsyncMock()  # list_results must NOT be called
        mock_store.get_task = AsyncMock(return_value=None)
        with patch("src.orchestration.subgraphs.vulnscan.nodes.get_vulnscan_store", return_value=mock_store):
            new_state = await collect(state)
        assert new_state["status"] == "failed"
        mock_store.list_results.assert_not_called()

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
        # F1.2: collect re-reads stats from ES via store.get_task().
        mock_store.get_task = AsyncMock(return_value=None)
        # F1.2 (2026-07-21): collect now re-reads stats from ES via
        # store.get_task() so dispatch-time failure counts are not lost.
        mock_store.get_task = AsyncMock(return_value=None)

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
        """Partial results (1/2 done) must not block forever.

        The collect node either returns "analyzing" (all done, or deadline
        passed with partial results) or keeps polling. It no longer returns
        "scanning". We simulate the deadline passing on the first poll so the
        node returns "analyzing" with the partial count -- the previously
        asserted "scanning" return value was removed by the P1-VS-3 fix.
        """
        state = _default_state("manual", targets=["host-a"])
        state["total_targets"] = 2  # waiting for 2 agents, only 1 done
        state["task"] = ScanTask(
            task_id=state["task_id"], source="manual", targets=["agent-a", "agent-b"],
            policy=ScanPolicy(timeout_sec=1800), status="scanning",
            stats={"total": 2, "done": 0, "failed": 0},
        )
        result = _result(task_id=state["task_id"], is_final=True)
        mock_store = AsyncMock()
        mock_store.list_results.return_value = [result]
        mock_store.update_task = AsyncMock()
        # F1.2: collect re-reads stats from ES via store.get_task().
        mock_store.get_task = AsyncMock(return_value=None)

        # First loop.time() call computes deadline = t0 + 1800; subsequent
        # calls (the deadline check) return a time past it so the timeout
        # branch fires immediately with the partial result.
        loop_times = iter([0, 9999, 9999, 9999])
        fake_loop = MagicMock()
        fake_loop.time = lambda: next(loop_times)

        with (
            patch("src.orchestration.subgraphs.vulnscan.nodes.get_vulnscan_store", return_value=mock_store),
            patch("redis.asyncio.from_url", return_value=AsyncMock()),
            patch("src.common.config.settings.get_settings", return_value=MagicMock(redis_url="redis://x")),
            patch("asyncio.get_running_loop", return_value=fake_loop),
            patch("asyncio.sleep", new=AsyncMock()),
        ):
            new_state = await collect(state)
            assert new_state["status"] == "analyzing"
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
