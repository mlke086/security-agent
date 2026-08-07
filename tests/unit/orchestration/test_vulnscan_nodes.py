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
    _nuclei_targets_by_agent,
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
        "finding_id": "f-1",
        "task_id": "task-1",
        "agent_id": "agent-a",
        "hostname": "web-01",
        "category": ScanModule.SYS_VULN,
        "name": "CVE-2024-0001",
        "cve": "CVE-2024-0001",
        "severity": "high",
        "ai_severity": "high",
        "ai_filtered": False,
        "evidence": "...",
        "fix_advice": "patch",
        "status": "open",
        "detected_at": "2026-01-01T00:00:00",
    }
    defaults.update(kw)
    return VulnFinding(**defaults)


def _result(task_id="task-1", agent_id="agent-a", is_final=False, batch=1):
    return ScanResult(
        task_id=task_id,
        agent_id=agent_id,
        hostname="web-01",
        findings=[_vuln().model_dump()],
        batch=batch,
        is_final=is_final,
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


def _make_mock_adapter():
    """Build an AsyncMock adapter with sensible defaults.

    V9 4.7: production code calls ``adapter.current_model_name`` in
    multiple places, which used to force every test to repeat
    ``mock.current_model_name = MagicMock(return_value="")``. Provide
    it here once so each test gets the default. Tests that need a
    specific value still set the attribute on their mock (they
    shadow the default cleanly).
    """
    mock = AsyncMock()
    mock.current_model_name = MagicMock(return_value="")
    return mock


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
        with patch(
            "src.orchestration.subgraphs.vulnscan.nodes.get_vulnscan_store", return_value=mock_store
        ):
            result = await _resolve_targets(["prod"])
        assert sorted(result) == ["agent-1", "agent-2", "agent-4"]

    @pytest.mark.asyncio
    async def test_hostname_target_returns_single(self):
        hosts = [_host("agent-1", "web-01", "10.0.0.1", group="prod")]
        mock_store = AsyncMock()
        mock_store.list_hosts = AsyncMock(return_value=hosts)
        with patch(
            "src.orchestration.subgraphs.vulnscan.nodes.get_vulnscan_store", return_value=mock_store
        ):
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
        with patch(
            "src.orchestration.subgraphs.vulnscan.nodes.get_vulnscan_store", return_value=mock_store
        ):
            result = await _resolve_targets(["agent-1", "prod"])
        assert sorted(result) == ["agent-1", "agent-2"]

    @pytest.mark.asyncio
    async def test_no_match_returns_targets_as_is(self):
        mock_store = AsyncMock()
        mock_store.list_hosts = AsyncMock(return_value=[])
        with patch(
            "src.orchestration.subgraphs.vulnscan.nodes.get_vulnscan_store", return_value=mock_store
        ):
            result = await _resolve_targets(["unknown-agent-id"])
        assert result == ["unknown-agent-id"]

    @pytest.mark.asyncio
    async def test_nuclei_targets_use_each_agents_managed_ip(self):
        mock_store = AsyncMock()
        # P1-VULN-GLOBAL (2026-07-31): _nuclei_targets_by_agent resolves each
        # agent's managed IP via get_host (per-agent, one at a time) -- the
        # earlier list_hosts mock never matched the implementation.
        mock_store.get_host = AsyncMock(
            side_effect=[
                _host("agent-1", "web-01", "10.0.0.1"),
                _host("agent-2", "web-02", "10.0.0.2"),
            ]
        )
        with patch(
            "src.orchestration.subgraphs.vulnscan.nodes.get_vulnscan_store",
            return_value=mock_store,
        ):
            result = await _nuclei_targets_by_agent(["agent-1", "agent-2"])
        assert result == {"agent-1": ["10.0.0.1"], "agent-2": ["10.0.0.2"]}


class TestParseIntent:
    @pytest.mark.asyncio
    async def test_manual_source_passes_through(self):
        state = _default_state("manual", targets=["host-a"])
        result = await parse_intent(state)
        assert result["status"] == "dispatching"

    @pytest.mark.asyncio
    async def test_confirmed_dialog_intent_is_not_reparsed(self):
        state = _default_state(
            "dialog",
            intent_text="scan Rocky001 with nuclei",
            targets=["Rocky001"],
            modules=["baseline"],
            engine="nuclei",
        )
        with patch("src.knowledge.models.adapter.get_model_adapter") as get_adapter:
            result = await parse_intent(state)
        assert result["status"] == "dispatching"
        get_adapter.assert_not_called()

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
        mock_adapter = _make_mock_adapter()
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
        mock_adapter = _make_mock_adapter()
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
            patch(
                "src.orchestration.subgraphs.vulnscan.nodes.get_vulnscan_store",
                return_value=mock_store,
            ),
            patch(
                "src.orchestration.subgraphs.vulnscan.nodes.get_agent_gateway",
                return_value=mock_gateway,
            ),
            patch("src.orchestration.subgraphs.vulnscan.nodes._resolve_targets", return_value=[]),
            patch(
                "redis.asyncio.from_url", return_value=AsyncMock(exists=AsyncMock(return_value=0))
            ),
            patch(
                "src.common.config.settings.get_settings",
                return_value=MagicMock(redis_url="redis://x"),
            ),
        ):
            result = await dispatch(state)
            assert result["status"] == "failed"
            assert "No target agents" in result["error"]
            assert result["total_targets"] == 0
            # P1-VULN-01: failure must be persisted to ES so /tasks/{id}
            # sees "failed" instead of polling collect for 30 minutes.
            failed_updates = [
                c
                for c in mock_store.update_task.call_args_list
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
            task_id=state["task_id"],
            source="manual",
            targets=["host-a"],
            policy=ScanPolicy(timeout_sec=1800),
            status="scanning",
            stats={"total": 1, "done": 0, "failed": 0},
        )
        result = _result(task_id=state["task_id"], is_final=False)
        mock_store = AsyncMock()
        mock_store.list_results.return_value = [result]
        mock_store.update_task = AsyncMock()
        mock_store.get_task = AsyncMock(
            return_value=ScanTask(
                task_id=state["task_id"],
                source="manual",
                targets=["host-a"],
                policy=ScanPolicy(),
                status="scanning",
                stats={"total": 1, "done": 0, "failed": 1},
            )
        )
        with (
            patch(
                "src.orchestration.subgraphs.vulnscan.nodes.get_vulnscan_store",
                return_value=mock_store,
            ),
            patch(
                "redis.asyncio.from_url", return_value=AsyncMock(exists=AsyncMock(return_value=0))
            ),
            patch(
                "src.common.config.settings.get_settings",
                return_value=MagicMock(redis_url="redis://x"),
            ),
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
        fake_redis = AsyncMock(exists=AsyncMock(return_value=0))
        fake_redis.publish = AsyncMock()
        with (
            patch(
                "src.orchestration.subgraphs.vulnscan.nodes.get_vulnscan_store",
                return_value=mock_store,
            ),
            patch(
                "src.orchestration.subgraphs.vulnscan.nodes.get_agent_gateway",
                return_value=mock_gateway,
            ),
            patch("src.orchestration.subgraphs.vulnscan.nodes._resolve_targets", return_value=[]),
            patch("redis.asyncio.from_url", return_value=fake_redis),
            patch(
                "src.common.config.settings.get_settings",
                return_value=MagicMock(redis_url="redis://x"),
            ),
        ):
            await dispatch(state)
        published = [
            c
            for c in fake_redis.publish.call_args_list
            if c.args and c.args[0] == f"vulnscan:task:{state['task_id']}"
        ]
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
            task_id=state["task_id"],
            source="manual",
            targets=[],
            policy=ScanPolicy(),
            status="failed",
            stats={"total": 0, "done": 0, "failed": 0},
        )
        mock_store = AsyncMock()  # list_results must NOT be called
        mock_store.get_task = AsyncMock(return_value=None)
        with patch(
            "src.orchestration.subgraphs.vulnscan.nodes.get_vulnscan_store", return_value=mock_store
        ):
            new_state = await collect(state)
        assert new_state["status"] == "failed"
        mock_store.list_results.assert_not_called()

    @pytest.mark.asyncio
    async def test_collect_with_final_result(self):
        state = _default_state("manual", targets=["host-a"])
        state["total_targets"] = 1
        state["task"] = ScanTask(
            task_id=state["task_id"],
            source="manual",
            targets=["agent-a"],
            policy=ScanPolicy(),
            status="scanning",
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
            patch(
                "src.orchestration.subgraphs.vulnscan.nodes.get_vulnscan_store",
                return_value=mock_store,
            ),
            patch(
                "redis.asyncio.from_url", return_value=AsyncMock(exists=AsyncMock(return_value=0))
            ),
            patch(
                "src.common.config.settings.get_settings",
                return_value=MagicMock(redis_url="redis://x"),
            ),
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
            task_id=state["task_id"],
            source="manual",
            targets=["agent-a", "agent-b"],
            policy=ScanPolicy(timeout_sec=1800),
            status="scanning",
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
            patch(
                "src.orchestration.subgraphs.vulnscan.nodes.get_vulnscan_store",
                return_value=mock_store,
            ),
            patch(
                "redis.asyncio.from_url", return_value=AsyncMock(exists=AsyncMock(return_value=0))
            ),
            patch(
                "src.common.config.settings.get_settings",
                return_value=MagicMock(redis_url="redis://x"),
            ),
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
            ScanResult(
                task_id=state["task_id"],
                agent_id="a",
                hostname="h1",
                findings=[f1.model_dump(), f2.model_dump()],
                batch=1,
                is_final=True,
                ts="",
            ),
            ScanResult(
                task_id=state["task_id"],
                agent_id="b",
                hostname="h2",
                findings=[f3.model_dump()],
                batch=2,
                is_final=True,
                ts="",
            ),
        ]
        mock_store.save_vulns = AsyncMock()
        # 2026-07-31 reconcile: no existing vulns -> every key is a fresh index;
        # the store writes go through bulk_update_vulns (not save_vulns).
        mock_store.list_vulns_all = AsyncMock(return_value=[])
        mock_store.bulk_update_vulns = AsyncMock()

        with patch(
            "src.orchestration.subgraphs.vulnscan.nodes.get_vulnscan_store", return_value=mock_store
        ):
            new_state = await aggregate(state)
            assert len(new_state["collected_findings"]) == 2
        assert mock_store.bulk_update_vulns.await_args is not None
        actions = mock_store.bulk_update_vulns.await_args.args[0]
        assert [a["_op_type"] for a in actions].count("index") == 2

    @pytest.mark.asyncio
    async def test_aggregate_no_findings(self):
        state = _default_state("manual", targets=["host-a"])
        mock_store = AsyncMock()
        mock_store.list_results.return_value = []
        mock_store.save_vulns = AsyncMock()

        with patch(
            "src.orchestration.subgraphs.vulnscan.nodes.get_vulnscan_store", return_value=mock_store
        ):
            new_state = await aggregate(state)
            assert new_state["collected_findings"] == []

    # -- 2026-07-31 consolidate + auto-fix ------------------------------------

    @staticmethod
    def _scan_result(state, findings, scanned_categories, ts="2026-02-01T00:00:00"):
        return ScanResult(
            task_id=state["task_id"],
            agent_id="agent-a",
            hostname="web-01",
            findings=[f.model_dump() for f in findings],
            batch=1,
            is_final=True,
            ts=ts,
            scanned_categories=scanned_categories,
        )

    @pytest.mark.asyncio
    async def test_aggregate_merges_previous_scan_into_same_record(self):
        """Same host+vuln re-detected: update in place (keep finding_id), roll
        the previous detected_at into scan_history, stay open."""
        state = _default_state("manual", targets=["host-a"])
        old = _vuln(finding_id="old-1", detected_at="2026-01-01T00:00:00")
        new = _vuln(finding_id="new-1", detected_at="2026-02-01T00:00:00")
        mock_store = AsyncMock()
        mock_store.list_results.return_value = [
            self._scan_result(state, [new], ["sys_vuln", "baseline"])
        ]
        mock_store.list_vulns_all = AsyncMock(return_value=[old])
        mock_store.bulk_update_vulns = AsyncMock()

        with patch(
            "src.orchestration.subgraphs.vulnscan.nodes.get_vulnscan_store", return_value=mock_store
        ):
            new_state = await aggregate(state)

        merged = new_state["collected_findings"]
        assert len(merged) == 1
        assert merged[0].finding_id == "old-1"  # reused, not a new random UUID
        assert merged[0].detected_at == "2026-02-01T00:00:00"
        actions = mock_store.bulk_update_vulns.await_args.args[0]
        updates = [a for a in actions if a["_op_type"] == "update"]
        assert len(updates) == 1
        assert updates[0]["_id"] == "old-1"
        doc = updates[0]["doc"]
        assert doc["status"] == "open"
        assert doc["scan_history"] == ["2026-01-01T00:00:00"]
        # V12 5.7: the merge must NOT overwrite the original owner's task_id
        # (the old task's monitor page would lose the vuln). It records the
        # latest confirming scan in last_seen_task_id instead.
        assert "task_id" not in doc, "merge must keep the original task_id"
        assert doc["last_seen_task_id"] == new.task_id

    @pytest.mark.asyncio
    async def test_aggregate_reopens_previously_fixed(self):
        """A fixed vuln that reappears on a rescan is reopened to open."""
        state = _default_state("manual", targets=["host-a"])
        old = _vuln(
            finding_id="old-1",
            status="fixed",
            first_fixed_at="2026-01-05T00:00:00",
            last_fixed_at="2026-01-05T00:00:00",
            detected_at="2026-01-01T00:00:00",
        )
        new = _vuln(finding_id="new-1", detected_at="2026-02-01T00:00:00")
        mock_store = AsyncMock()
        mock_store.list_results.return_value = [self._scan_result(state, [new], ["sys_vuln"])]
        mock_store.list_vulns_all = AsyncMock(return_value=[old])
        mock_store.bulk_update_vulns = AsyncMock()

        with patch(
            "src.orchestration.subgraphs.vulnscan.nodes.get_vulnscan_store", return_value=mock_store
        ):
            await aggregate(state)
        doc = [a for a in mock_store.bulk_update_vulns.await_args.args[0] if a["_op_type"] == "update"][0][
            "doc"
        ]
        assert doc["status"] == "open"

    @pytest.mark.asyncio
    async def test_aggregate_auto_fixes_disappeared_open(self):
        """An open vuln in a covered category that the rescan no longer reports
        is automatically marked fixed with timestamps + an audit entry."""
        state = _default_state("manual", targets=["host-a"])
        gone = _vuln(finding_id="gone-1", detected_at="2026-01-01T00:00:00")
        found = _vuln(
            finding_id="found-1",
            name="Other CVE",
            cve="CVE-2024-0002",
            detected_at="2026-02-01T00:00:00",
        )
        mock_store = AsyncMock()
        mock_store.list_results.return_value = [
            self._scan_result(state, [found], ["sys_vuln", "baseline"])
        ]
        mock_store.list_vulns_all = AsyncMock(return_value=[gone])
        mock_store.bulk_update_vulns = AsyncMock()
        audit = AsyncMock()

        with (
            patch(
                "src.orchestration.subgraphs.vulnscan.nodes.get_vulnscan_store", return_value=mock_store
            ),
            patch(
                "src.orchestration.subgraphs.vulnscan.nodes.get_audit_logger", return_value=audit
            ),
        ):
            await aggregate(state)
        actions = mock_store.bulk_update_vulns.await_args.args[0]
        fixed = [a for a in actions if a["_op_type"] == "update" and a["doc"].get("status") == "fixed"]
        assert len(fixed) == 1
        assert fixed[0]["_id"] == "gone-1"
        assert fixed[0]["doc"]["last_fixed_at"]
        assert fixed[0]["doc"]["first_fixed_at"]
        audit.log.assert_awaited_once()

    @pytest.mark.asyncio
    async def test_aggregate_no_coverage_skips_auto_fix(self):
        """Legacy agent without scanned_categories -> conservative, no auto-fix."""
        state = _default_state("manual", targets=["host-a"])
        gone = _vuln(finding_id="gone-1", detected_at="2026-01-01T00:00:00")
        found = _vuln(
            finding_id="found-1",
            name="Other CVE",
            cve="CVE-2024-0002",
            detected_at="2026-02-01T00:00:00",
        )
        mock_store = AsyncMock()
        mock_store.list_results.return_value = [self._scan_result(state, [found], [])]
        mock_store.list_vulns_all = AsyncMock(return_value=[gone])
        mock_store.bulk_update_vulns = AsyncMock()
        audit = AsyncMock()

        with (
            patch(
                "src.orchestration.subgraphs.vulnscan.nodes.get_vulnscan_store", return_value=mock_store
            ),
            patch(
                "src.orchestration.subgraphs.vulnscan.nodes.get_audit_logger", return_value=audit
            ),
        ):
            await aggregate(state)
        actions = mock_store.bulk_update_vulns.await_args.args[0]
        fixed = [a for a in actions if a["_op_type"] == "update" and a["doc"].get("status") == "fixed"]
        assert fixed == []
        audit.log.assert_not_awaited()

    @pytest.mark.asyncio
    async def test_aggregate_does_not_touch_accepted(self):
        """Manual accepted decisions are never auto-overridden."""
        state = _default_state("manual", targets=["host-a"])
        accepted = _vuln(
            finding_id="acc-1",
            status="accepted",
            first_fixed_at="2026-01-05T00:00:00",
            detected_at="2026-01-01T00:00:00",
        )
        found = _vuln(finding_id="found-1", name="Other CVE", cve="CVE-2024-0002")
        mock_store = AsyncMock()
        mock_store.list_results.return_value = [self._scan_result(state, [found], ["sys_vuln"])]
        mock_store.list_vulns_all = AsyncMock(return_value=[accepted])
        mock_store.bulk_update_vulns = AsyncMock()
        audit = AsyncMock()

        with (
            patch(
                "src.orchestration.subgraphs.vulnscan.nodes.get_vulnscan_store", return_value=mock_store
            ),
            patch(
                "src.orchestration.subgraphs.vulnscan.nodes.get_audit_logger", return_value=audit
            ),
        ):
            await aggregate(state)
        actions = mock_store.bulk_update_vulns.await_args.args[0]
        fixed = [a for a in actions if a["_op_type"] == "update" and a["doc"].get("status") == "fixed"]
        assert fixed == []
        audit.log.assert_not_awaited()

    @pytest.mark.asyncio
    async def test_aggregate_only_auto_fixes_covered_category(self):
        """A baseline vuln is left alone when the rescan only covered sys_vuln."""
        state = _default_state("manual", targets=["host-a"])
        baseline = _vuln(
            finding_id="bl-1",
            category=ScanModule.BASELINE,
            name="Weak SSH config",
            cve=None,
            detected_at="2026-01-01T00:00:00",
        )
        found = _vuln(finding_id="found-1", name="Other CVE", cve="CVE-2024-0002")
        mock_store = AsyncMock()
        mock_store.list_results.return_value = [self._scan_result(state, [found], ["sys_vuln"])]
        mock_store.list_vulns_all = AsyncMock(return_value=[baseline])
        mock_store.bulk_update_vulns = AsyncMock()
        audit = AsyncMock()

        with (
            patch(
                "src.orchestration.subgraphs.vulnscan.nodes.get_vulnscan_store", return_value=mock_store
            ),
            patch(
                "src.orchestration.subgraphs.vulnscan.nodes.get_audit_logger", return_value=audit
            ),
        ):
            await aggregate(state)
        actions = mock_store.bulk_update_vulns.await_args.args[0]
        fixed = [a for a in actions if a["_op_type"] == "update" and a["doc"].get("status") == "fixed"]
        assert fixed == []
        audit.log.assert_not_awaited()

    @pytest.mark.asyncio
    async def test_aggregate_deletes_legacy_duplicates_and_keeps_their_times(self):
        """Two legacy docs for the same host+vuln: newest kept, older deleted,
        and BOTH prior detection times survive in scan_history."""
        state = _default_state("manual", targets=["host-a"])
        old1 = _vuln(finding_id="old-1", detected_at="2026-01-01T00:00:00")
        old2 = _vuln(finding_id="old-2", detected_at="2026-02-01T00:00:00")
        new = _vuln(finding_id="new-1", detected_at="2026-03-01T00:00:00")
        mock_store = AsyncMock()
        mock_store.list_results.return_value = [
            self._scan_result(state, [new], ["sys_vuln"], ts="2026-03-01T00:00:00")
        ]
        mock_store.list_vulns_all = AsyncMock(return_value=[old1, old2])
        mock_store.bulk_update_vulns = AsyncMock()

        with patch(
            "src.orchestration.subgraphs.vulnscan.nodes.get_vulnscan_store", return_value=mock_store
        ):
            await aggregate(state)
        actions = mock_store.bulk_update_vulns.await_args.args[0]
        deletes = [a["_id"] for a in actions if a["_op_type"] == "delete"]
        assert deletes == ["old-1"]  # oldest duplicate removed
        updates = [a for a in actions if a["_op_type"] == "update"]
        assert updates[0]["_id"] == "old-2"  # newest existing doc survives
        assert updates[0]["doc"]["scan_history"] == ["2026-01-01T00:00:00", "2026-02-01T00:00:00"]


class TestBuildAnalysisPrompt:
    def test_builds_prompt_with_findings(self):
        findings = [
            _vuln(finding_id="f-1").model_dump(),
            _vuln(
                finding_id="f-2",
                cve=None,
                name="Weak SSH config",
                category=ScanModule.BASELINE,
                severity="medium",
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

        mock_adapter = _make_mock_adapter()
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
            patch(
                "src.orchestration.subgraphs.vulnscan.nodes.get_vulnscan_store",
                return_value=mock_store,
            ),
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
        """2026-07-29 UX upgrade: a batch-level LLM failure now writes a
        fallback row (ai_processed=False) for every finding whose batch
        failed, instead of silently leaving ai_severity blank."""
        state = _default_state("manual", targets=["host-a"])
        f1 = _vuln(finding_id="f-1", cve="CVE-2024-0001", severity="high").model_dump()
        state["collected_findings"] = [f1]

        mock_adapter = _make_mock_adapter()
        mock_adapter.chat_completion.side_effect = RuntimeError("timeout")
        mock_store = AsyncMock()
        mock_store.update_vuln = AsyncMock()

        with (
            patch("src.knowledge.models.adapter.get_model_adapter", return_value=mock_adapter),
            patch(
                "src.orchestration.subgraphs.vulnscan.nodes.get_vulnscan_store",
                return_value=mock_store,
            ),
            patch("src.orchestration.subgraphs.vulnscan.nodes._pub_progress", AsyncMock()),
        ):
            result = await llm_analysis(state)
            assert result["status"] == "reporting"
            assert result["ai_processed"] is False
            # Exactly one fallback write for the one unanalysed finding.
            assert mock_store.update_vuln.await_count == 1
            kwargs = mock_store.update_vuln.await_args.kwargs
            assert kwargs["ai_processed"] is False
            assert kwargs["ai_severity"] == "high"
            assert "LLM" in (kwargs.get("ai_reason") or "")


class TestPubProgress:
    @pytest.mark.asyncio
    async def test_pub_progress_publishes(self):
        mock_redis = AsyncMock()
        mock_redis.publish = AsyncMock()

        with patch(
            "src.common.config.settings.get_settings", return_value=MagicMock(redis_url="redis://x")
        ):
            with patch("redis.asyncio.from_url", return_value=mock_redis):
                await _pub_progress("task-1", "scan", "running", "step 1 of 3")
                mock_redis.publish.assert_called_once()

    @pytest.mark.asyncio
    async def test_pub_progress_handles_redis_failure(self):
        mock_redis = AsyncMock()
        mock_redis.publish.side_effect = RuntimeError("redis down")

        with patch(
            "src.common.config.settings.get_settings", return_value=MagicMock(redis_url="redis://x")
        ):
            with patch("redis.asyncio.from_url", return_value=mock_redis):
                await _pub_progress("task-1", "scan", "running", "step")


class TestGenerateReport:
    @pytest.mark.asyncio
    async def test_report_with_findings(self):
        state = _default_state("manual", targets=["host-a"])
        v = _vuln()
        mock_store = AsyncMock()
        mock_store.list_vulns_all.return_value = [v]
        mock_store.save_report = AsyncMock()
        mock_store.update_task = AsyncMock()

        mock_adapter = _make_mock_adapter()
        mock_adapter.chat_completion.return_value = "summary text"

        with (
            patch(
                "src.orchestration.subgraphs.vulnscan.nodes.get_vulnscan_store",
                return_value=mock_store,
            ),
            patch("src.knowledge.models.adapter.get_model_adapter", return_value=mock_adapter),
            patch(
                "redis.asyncio.from_url", return_value=AsyncMock(exists=AsyncMock(return_value=0))
            ),
            patch(
                "src.common.config.settings.get_settings",
                return_value=MagicMock(redis_url="redis://x"),
            ),
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
        mock_store.list_vulns_all.return_value = []
        mock_store.save_report = AsyncMock()
        mock_store.update_task = AsyncMock()

        with (
            patch(
                "src.orchestration.subgraphs.vulnscan.nodes.get_vulnscan_store",
                return_value=mock_store,
            ),
            patch(
                "redis.asyncio.from_url", return_value=AsyncMock(exists=AsyncMock(return_value=0))
            ),
            patch(
                "src.common.config.settings.get_settings",
                return_value=MagicMock(redis_url="redis://x"),
            ),
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
        mock_store.list_vulns_all.return_value = [medium, high, critical]
        mock_store.save_report = AsyncMock()
        mock_store.update_task = AsyncMock()

        mock_adapter = _make_mock_adapter()
        mock_adapter.chat_completion.return_value = "Scan summary"

        with (
            patch(
                "src.orchestration.subgraphs.vulnscan.nodes.get_vulnscan_store",
                return_value=mock_store,
            ),
            patch("src.knowledge.models.adapter.get_model_adapter", return_value=mock_adapter),
            patch(
                "redis.asyncio.from_url", return_value=AsyncMock(exists=AsyncMock(return_value=0))
            ),
            patch(
                "src.common.config.settings.get_settings",
                return_value=MagicMock(redis_url="redis://x"),
            ),
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
            finding_id="f-b",
            severity="low",
            cve=None,
            category=ScanModule.BASELINE,
            name="Weak password policy",
        )
        mock_store = AsyncMock()
        mock_store.list_vulns_all.return_value = [critical, baseline]
        mock_store.save_report = AsyncMock()
        mock_store.update_task = AsyncMock()

        mock_adapter = _make_mock_adapter()
        mock_adapter.chat_completion.return_value = "summary"

        with (
            patch(
                "src.orchestration.subgraphs.vulnscan.nodes.get_vulnscan_store",
                return_value=mock_store,
            ),
            patch("src.knowledge.models.adapter.get_model_adapter", return_value=mock_adapter),
            patch(
                "redis.asyncio.from_url", return_value=AsyncMock(exists=AsyncMock(return_value=0))
            ),
            patch(
                "src.common.config.settings.get_settings",
                return_value=MagicMock(redis_url="redis://x"),
            ),
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
        """2026-07-29 UX upgrade: when the LLM is unavailable the report
        still completes, but the AI evidence fields mark it honestly as
        ``ai_processed=False`` and ``ai_model=""``."""
        state = _default_state("manual", targets=["host-a"])
        v = _vuln()
        mock_store = AsyncMock()
        mock_store.list_vulns_all.return_value = [v]
        mock_store.save_report = AsyncMock()
        mock_store.update_task = AsyncMock()

        mock_adapter = _make_mock_adapter()
        mock_adapter.chat_completion.side_effect = RuntimeError("LLM timeout")

        with (
            patch(
                "src.orchestration.subgraphs.vulnscan.nodes.get_vulnscan_store",
                return_value=mock_store,
            ),
            patch("src.knowledge.models.adapter.get_model_adapter", return_value=mock_adapter),
            patch(
                "redis.asyncio.from_url", return_value=AsyncMock(exists=AsyncMock(return_value=0))
            ),
            patch(
                "src.common.config.settings.get_settings",
                return_value=MagicMock(redis_url="redis://x"),
            ),
            patch("src.orchestration.subgraphs.vulnscan.nodes._pub_progress", AsyncMock()),
        ):
            result = await generate_report(state)
            assert result["status"] == "completed"
            assert "Scan completed" in result["report"].summary
            assert result["report"].ai_processed is False
            assert result["report"].ai_model == ""
            assert result["report"].ai_overall_advice == ""
            assert result["report"].ai_processed_at is None


# ---------------------------------------------------------------
# P2-1 regression: _is_task_cancelled must fail-CLOSED.
#
# A redis connection error during the cancellation tombstone
# check must be treated as "cancelled" (return True), not
# "not cancelled" (return False). Otherwise a redis blip
# silently drops user-initiated cancellations and lets the
# dispatched work run to completion.
# ---------------------------------------------------------------
class TestIsTaskCancelledFailClosed:
    """Lock in the fail-closed behavior of the cancel check."""

    @pytest.mark.asyncio
    async def test_redis_connection_error_returns_true(self):
        from src.orchestration.subgraphs.vulnscan.nodes import _is_task_cancelled

        with patch("redis.asyncio.from_url") as mock_from_url:
            # Simulate redis.from_url raising during connection setup.
            mock_from_url.side_effect = ConnectionError("redis down")
            cancelled = await _is_task_cancelled("task-x")
        assert cancelled is True, "redis connection failure must fail-closed; abort the node"

    @pytest.mark.asyncio
    async def test_redis_exists_raises_returns_true(self):
        from src.orchestration.subgraphs.vulnscan.nodes import _is_task_cancelled

        fake_redis = AsyncMock()
        fake_redis.exists = AsyncMock(side_effect=TimeoutError("slow"))
        with patch("redis.asyncio.from_url", return_value=fake_redis):
            cancelled = await _is_task_cancelled("task-x")
        assert cancelled is True

    @pytest.mark.asyncio
    async def test_key_exists_returns_true(self):
        from src.orchestration.subgraphs.vulnscan.nodes import _is_task_cancelled

        fake_redis = AsyncMock()
        fake_redis.exists = AsyncMock(return_value=1)
        with patch("redis.asyncio.from_url", return_value=fake_redis):
            assert await _is_task_cancelled("task-x") is True
        # S-P1-1 (V12): shared client is NOT closed per call anymore.
        assert fake_redis.aclose.await_count == 0

    @pytest.mark.asyncio
    async def test_key_missing_returns_false(self):
        from src.orchestration.subgraphs.vulnscan.nodes import _is_task_cancelled

        fake_redis = AsyncMock()
        fake_redis.exists = AsyncMock(return_value=0)
        with patch("redis.asyncio.from_url", return_value=fake_redis):
            assert await _is_task_cancelled("task-x") is False
        # S-P1-1 (V12): shared client is NOT closed per call anymore.
        assert fake_redis.aclose.await_count == 0

    @pytest.mark.asyncio
    async def test_aclose_failure_does_not_mask_decision(self):
        from src.orchestration.subgraphs.vulnscan.nodes import _is_task_cancelled

        fake_redis = AsyncMock()
        fake_redis.exists = AsyncMock(return_value=1)
        fake_redis.aclose = AsyncMock(side_effect=ConnectionError("teardown"))
        with patch("redis.asyncio.from_url", return_value=fake_redis):
            # Decision must still be True (cancelled); teardown
            # failure is logged + swallowed, not raised.
            assert await _is_task_cancelled("task-x") is True

    @pytest.mark.asyncio
    async def test_dispatch_aborts_when_redis_unavailable(self):
        # End-to-end: with fail-closed, dispatch() short-circuits
        with patch("redis.asyncio.from_url") as mock_from_url:
            mock_from_url.side_effect = ConnectionError("redis down")
            state = _default_state("manual", targets=["host-a"])
            mock_store = AsyncMock()
            mock_gateway = MagicMock()
            with (
                patch(
                    "src.orchestration.subgraphs.vulnscan.nodes.get_vulnscan_store",
                    return_value=mock_store,
                ),
                patch(
                    "src.orchestration.subgraphs.vulnscan.nodes.get_agent_gateway",
                    return_value=mock_gateway,
                ),
                patch(
                    "src.orchestration.subgraphs.vulnscan.nodes._resolve_targets",
                    return_value=["agent-a"],
                ),
                patch(
                    "src.common.config.settings.get_settings",
                    return_value=MagicMock(redis_url="redis://x"),
                ),
            ):
                result = await dispatch(state)
        assert result["status"] == "cancelled", "with redis down, fail-closed dispatch must abort"


class TestConfirmCancellation:
    """S-P1-9 (V12): the cancellation tombstone is confirmed twice before
    a node persists "cancelled". _is_task_cancelled stays fail-closed, but
    the double check keeps a redis blip from killing a healthy scan.
    """

    @pytest.mark.asyncio
    async def test_both_checks_cancelled_persists(self):
        from src.orchestration.subgraphs.vulnscan.nodes import _confirm_cancellation

        with (
            patch(
                "src.orchestration.subgraphs.vulnscan.nodes._is_task_cancelled",
                AsyncMock(return_value=True),
            ),
            patch("src.orchestration.subgraphs.vulnscan.nodes.asyncio.sleep", AsyncMock()),
        ):
            assert await _confirm_cancellation("task-x") is True

    @pytest.mark.asyncio
    async def test_first_true_second_false_treats_as_healthy(self):
        # Redis blip between the two checks: the scan must NOT be
        # persisted as cancelled, and an audit entry is written.
        from src.orchestration.subgraphs.vulnscan.nodes import _confirm_cancellation

        with (
            patch(
                "src.orchestration.subgraphs.vulnscan.nodes._is_task_cancelled",
                AsyncMock(side_effect=[True, False]),
            ),
            patch("src.orchestration.subgraphs.vulnscan.nodes.asyncio.sleep", AsyncMock()),
            patch(
                "src.orchestration.subgraphs.vulnscan.nodes.get_audit_logger",
                return_value=AsyncMock(),
            ) as mock_audit,
        ):
            assert await _confirm_cancellation("task-x") is False
            mock_audit.return_value.log.assert_awaited_once()
            call_kwargs = mock_audit.return_value.log.await_args.kwargs
            assert call_kwargs["action"] == "cancellation_check_degraded"

    @pytest.mark.asyncio
    async def test_first_false_no_sleep_no_audit(self):
        from src.orchestration.subgraphs.vulnscan.nodes import _confirm_cancellation

        with (
            patch(
                "src.orchestration.subgraphs.vulnscan.nodes._is_task_cancelled",
                AsyncMock(return_value=False),
            ),
            patch("src.orchestration.subgraphs.vulnscan.nodes.asyncio.sleep", AsyncMock()) as mock_sleep,
            patch(
                "src.orchestration.subgraphs.vulnscan.nodes.get_audit_logger",
                return_value=AsyncMock(),
            ) as mock_audit,
        ):
            assert await _confirm_cancellation("task-x") is False
            mock_sleep.assert_not_awaited()
            mock_audit.return_value.log.assert_not_awaited()

    @pytest.mark.asyncio
    async def test_collect_redis_blip_does_not_mark_cancelled(self):
        # End-to-end through collect(): a redis blip (first check True,
        # second False) must NOT persist "cancelled" -- the scan keeps
        # collecting and finishes normally.
        from src.orchestration.subgraphs.vulnscan.nodes import collect

        state = _default_state("manual", targets=["host-a"])
        state["total_targets"] = 1
        task = ScanTask(
            task_id="task-x",
            source="manual",
            targets=["host-a"],
            policy=ScanPolicy(modules=["sys_vuln"], resource_limit={}),
            engine="matcher",
        )
        task.stats = {"failed": 0, "done": 0, "total": 1}
        state["task"] = task

        # First poll: blip (True then False) -> healthy. Second poll:
        # list_results returns the final batch -> analyzing.
        result_batch = MagicMock()
        result_batch.is_final = True
        result_batch.agent_id = "agent-a"
        result_batch.findings = []

        calls = {"poll": 0}

        async def fake_confirm(task_id: str) -> bool:
            calls["poll"] += 1
            # Simulate: first check confirms tombstone (blip), re-check
            # does not -> treated as healthy.
            return False

        with (
            patch(
                "src.orchestration.subgraphs.vulnscan.nodes._confirm_cancellation",
                side_effect=fake_confirm,
            ),
            patch(
                "src.orchestration.subgraphs.vulnscan.nodes.get_vulnscan_store"
            ) as mock_store,
            patch(
                "src.orchestration.subgraphs.vulnscan.nodes.asyncio.sleep",
                AsyncMock(),
            ),
        ):
            mock_store.return_value.get_task = AsyncMock(return_value=task)
            mock_store.return_value.list_results = AsyncMock(return_value=[result_batch])
            mock_store.return_value.update_task = AsyncMock()
            result = await collect(state)

        assert result["status"] == "analyzing", "blip must not cancel the scan"
        # update_task must never have been called with status="cancelled"
        for call in mock_store.return_value.update_task.await_args_list:
            assert call.kwargs.get("status") != "cancelled"

    @pytest.mark.asyncio
    async def test_dispatch_redis_blip_does_not_abort(self):
        """V13 P1-5: the dispatch entry check must use the double-checked
        confirmation -- a redis blip (unconfirmed) must NOT abort a healthy
        task before it even dispatches."""
        from src.orchestration.subgraphs.vulnscan.nodes import dispatch

        state = _default_state("manual", targets=["host-a"])
        mock_store = AsyncMock()
        mock_store.save_task = AsyncMock()
        mock_store.update_task = AsyncMock()
        mock_gateway = MagicMock()
        mock_gateway.broadcast = AsyncMock(return_value={"sent": 1, "failed": 0})
        mock_gateway.send_to_agent = AsyncMock(return_value=True)
        fake_redis = AsyncMock(exists=AsyncMock(return_value=0))
        fake_redis.publish = AsyncMock()
        with (
            patch(
                "src.orchestration.subgraphs.vulnscan.nodes._confirm_cancellation",
                AsyncMock(return_value=False),  # blip: first check True, re-check False
            ),
            patch(
                "src.orchestration.subgraphs.vulnscan.nodes.get_vulnscan_store",
                return_value=mock_store,
            ),
            patch(
                "src.orchestration.subgraphs.vulnscan.nodes.get_agent_gateway",
                return_value=mock_gateway,
            ),
            patch(
                "src.orchestration.subgraphs.vulnscan.nodes._resolve_targets",
                return_value=["agent-a"],
            ),
            patch(
                "src.orchestration.subgraphs.vulnscan.nodes._nuclei_targets_by_agent",
                return_value={},
            ),
            patch("redis.asyncio.from_url", return_value=fake_redis),
            patch(
                "src.common.config.settings.get_settings",
                return_value=MagicMock(redis_url="redis://x"),
            ),
        ):
            result = await dispatch(state)

        assert result["status"] != "cancelled", "blip must not abort dispatch"
        mock_store.save_task.assert_awaited_once()

    @pytest.mark.asyncio
    async def test_dispatch_confirmed_cancel_still_aborts(self):
        """A real (double-confirmed) cancellation must still abort dispatch."""
        from src.orchestration.subgraphs.vulnscan.nodes import dispatch

        state = _default_state("manual", targets=["host-a"])
        with (
            patch(
                "src.orchestration.subgraphs.vulnscan.nodes._confirm_cancellation",
                AsyncMock(return_value=True),
            ),
            patch(
                "src.orchestration.subgraphs.vulnscan.nodes.get_vulnscan_store",
                return_value=AsyncMock(),
            ),
        ):
            result = await dispatch(state)
        assert result["status"] == "cancelled"
        assert result["dispatched"] is False


class TestLLMAnalysisFallback:
    """2026-07-29 UX upgrade: the LLM analysis node must always write back
    ai_processed/ai_reason for every finding, even when the LLM is
    completely unavailable. Otherwise the UI shows blank AI columns
    and operators can't tell whether AI was skipped or just slow.
    """

    @pytest.mark.asyncio
    async def test_adapter_unavailable_writes_fallback_for_every_finding(self):
        state = _default_state("manual", targets=["host-a"])
        f1 = _vuln(finding_id="f-1", severity="high").model_dump()
        f2 = _vuln(finding_id="f-2", severity="critical").model_dump()
        state["collected_findings"] = [f1, f2]

        # get_model_adapter() raises -> the node must fall back to template
        # mode instead of silently returning "reporting".
        mock_store = AsyncMock()
        mock_store.update_vuln = AsyncMock()
        with (
            patch(
                "src.knowledge.models.adapter.get_model_adapter",
                side_effect=RuntimeError("adapter down"),
            ),
            patch(
                "src.orchestration.subgraphs.vulnscan.nodes.get_vulnscan_store",
                return_value=mock_store,
            ),
            patch("src.orchestration.subgraphs.vulnscan.nodes._pub_progress", AsyncMock()),
        ):
            result = await llm_analysis(state)
        assert result["status"] == "reporting"
        assert result["ai_processed"] is False
        assert mock_store.update_vuln.await_count == 2
        for call in mock_store.update_vuln.await_args_list:
            assert call.kwargs["ai_processed"] is False
            assert "LLM" in (call.kwargs.get("ai_reason") or "")
            assert call.kwargs["ai_severity"] in ("high", "critical")
            assert call.kwargs["ai_processed_at"]

    @pytest.mark.asyncio
    async def test_adapter_returns_non_structured_payload_falls_back(self):
        """When the adapter is available but returns a non-AnalyzedResult
        (e.g. a string instead of the schema), each batch's findings get
        a fallback write at the end of the loop."""
        state = _default_state("manual", targets=["host-a"])
        f1 = _vuln(finding_id="f-1", severity="medium").model_dump()
        state["collected_findings"] = [f1]

        mock_adapter = _make_mock_adapter()
        # chat_completion returns a string, not the expected schema
        mock_adapter.chat_completion.return_value = "not what we wanted"
        mock_store = AsyncMock()
        mock_store.update_vuln = AsyncMock()
        with (
            patch("src.knowledge.models.adapter.get_model_adapter", return_value=mock_adapter),
            patch(
                "src.orchestration.subgraphs.vulnscan.nodes.get_vulnscan_store",
                return_value=mock_store,
            ),
            patch("src.orchestration.subgraphs.vulnscan.nodes._pub_progress", AsyncMock()),
        ):
            result = await llm_analysis(state)
        assert result["status"] == "reporting"
        # the batch call returned a string so result.analyzed AttributeError
        # fires; the unanalysed finding is then re-written with the fallback.
        assert mock_store.update_vuln.await_count == 1
        assert mock_store.update_vuln.await_args.kwargs["ai_processed"] is False




class TestWriteFallback:
    # V10 1.3: _write_fallback marks every finding with the same
    # ai_* fields and only differs by the reason string. Cover both
    # the happy path and the per-row try/except.

    async def test_write_fallback_calls_update_vuln_per_finding(self):
        from unittest.mock import AsyncMock, MagicMock, patch

        from src.orchestration.subgraphs.vulnscan.nodes import _write_fallback

        mock_store = MagicMock()
        mock_store.update_vuln = AsyncMock()
        findings = [
            {"finding_id": "f-1", "severity": "high", "fix_advice": "patch"},
            {"finding_id": "f-2", "severity": "low"},
        ]
        with patch(
            "src.orchestration.subgraphs.vulnscan.nodes.get_vulnscan_store",
            return_value=mock_store,
        ):
            await _write_fallback(findings, reason="LLM unavailable")
        assert mock_store.update_vuln.await_count == 2
        kwargs = mock_store.update_vuln.await_args_list[0].kwargs
        assert kwargs["ai_processed"] is False
        assert kwargs["ai_filtered"] is False
        assert kwargs["ai_reason"] == "LLM unavailable"
        assert kwargs["ai_severity"] == "high"
        assert kwargs["fix_advice"] == "patch"

    async def test_write_fallback_continues_on_per_row_failure(self):
        from unittest.mock import AsyncMock, MagicMock, patch

        from src.orchestration.subgraphs.vulnscan.nodes import _write_fallback

        mock_store = MagicMock()
        # First call fails, second succeeds -- the loop must not abort.
        mock_store.update_vuln = AsyncMock(
            side_effect=[RuntimeError("es down"), None]
        )
        findings = [
            {"finding_id": "f-1", "severity": "high"},
            {"finding_id": "f-2", "severity": "low"},
        ]
        with patch(
            "src.orchestration.subgraphs.vulnscan.nodes.get_vulnscan_store",
            return_value=mock_store,
        ):
            await _write_fallback(findings, reason="LLM batch failed")
        assert mock_store.update_vuln.await_count == 2

    async def test_write_fallback_empty_findings_is_noop(self):
        from unittest.mock import AsyncMock, MagicMock, patch

        from src.orchestration.subgraphs.vulnscan.nodes import _write_fallback

        mock_store = MagicMock()
        mock_store.update_vuln = AsyncMock()
        with patch(
            "src.orchestration.subgraphs.vulnscan.nodes.get_vulnscan_store",
            return_value=mock_store,
        ):
            await _write_fallback([], reason="noop")
        mock_store.update_vuln.assert_not_called()



class TestGenerateReportAIEvidence:
    """2026-07-29 UX upgrade: ScanReport now carries ai_processed,
    ai_model, ai_overall_advice, ai_processed_at. The happy path must
    populate them all when the LLM succeeds."""

    @pytest.mark.asyncio
    async def test_report_with_findings_records_ai_evidence(self):
        state = _default_state("manual", targets=["host-a"])
        # V10 2.2 (2026-07-30): the report badge reads ai_processed from the
        # upstream llm_analysis node via state, so the report matches what the
        # findings table showed -- not a local re-computation.
        state["ai_processed"] = True
        v = _vuln()
        mock_store = AsyncMock()
        mock_store.list_vulns_all.return_value = [v]
        mock_store.save_report = AsyncMock()
        mock_store.update_task = AsyncMock()

        # First call = summary, second call = overall_advice
        mock_adapter = _make_mock_adapter()
        mock_adapter.chat_completion.side_effect = ["summary text", "advice text"]
        mock_adapter.current_model_name = MagicMock(return_value="claude-sonnet-4-5")

        with (
            patch(
                "src.orchestration.subgraphs.vulnscan.nodes.get_vulnscan_store",
                return_value=mock_store,
            ),
            patch("src.knowledge.models.adapter.get_model_adapter", return_value=mock_adapter),
            patch(
                "redis.asyncio.from_url", return_value=AsyncMock(exists=AsyncMock(return_value=0))
            ),
            patch(
                "src.common.config.settings.get_settings",
                return_value=MagicMock(redis_url="redis://x"),
            ),
            patch("src.orchestration.subgraphs.vulnscan.nodes._pub_progress", AsyncMock()),
        ):
            result = await generate_report(state)
        assert result["status"] == "completed"
        r = result["report"]
        assert r.ai_processed is True
        assert r.ai_model == "claude-sonnet-4-5"
        assert r.ai_overall_advice == "advice text"
        assert r.ai_processed_at  # non-empty
        # And the LLM was called exactly twice: once for summary, once for advice
        assert mock_adapter.chat_completion.await_count == 2

    @pytest.mark.asyncio
    async def test_report_with_no_vulns_marks_ai_not_processed(self):
        state = _default_state("manual", targets=["host-a"])
        mock_store = AsyncMock()
        mock_store.list_vulns_all.return_value = []
        mock_store.save_report = AsyncMock()
        mock_store.update_task = AsyncMock()

        with (
            patch(
                "src.orchestration.subgraphs.vulnscan.nodes.get_vulnscan_store",
                return_value=mock_store,
            ),
            patch(
                "redis.asyncio.from_url", return_value=AsyncMock(exists=AsyncMock(return_value=0))
            ),
            patch(
                "src.common.config.settings.get_settings",
                return_value=MagicMock(redis_url="redis://x"),
            ),
            patch("src.orchestration.subgraphs.vulnscan.nodes._pub_progress", AsyncMock()),
        ):
            result = await generate_report(state)
        r = result["report"]
        assert r.ai_processed is False
        assert r.ai_model == ""
        assert r.ai_overall_advice == ""
        assert r.ai_processed_at is None


class TestDispatchLanes:
    """S-P1-2 (V12): global-engine dispatch must keep matcher and nuclei
    delivery counts separate so a failed nuclei push is never hidden behind
    a successful matcher broadcast."""

    @pytest.mark.asyncio
    async def test_global_reports_matcher_and_nuclei_separately(self):
        state = _default_state("manual", targets=["host-a"], engine="global")
        mock_store = AsyncMock()
        mock_store.save_task = AsyncMock()
        mock_store.update_task = AsyncMock()
        mock_gateway = MagicMock()
        mock_gateway.broadcast = AsyncMock(return_value={"sent": 1, "failed": 0})
        mock_gateway.send_to_agent = AsyncMock(side_effect=[True, False])  # 2 agents
        fake_redis = AsyncMock(exists=AsyncMock(return_value=0))
        fake_redis.publish = AsyncMock()
        with (
            patch(
                "src.orchestration.subgraphs.vulnscan.nodes.get_vulnscan_store",
                return_value=mock_store,
            ),
            patch(
                "src.orchestration.subgraphs.vulnscan.nodes.get_agent_gateway",
                return_value=mock_gateway,
            ),
            patch(
                "src.orchestration.subgraphs.vulnscan.nodes._resolve_targets",
                return_value=["agent-a", "agent-b"],
            ),
            patch(
                "src.orchestration.subgraphs.vulnscan.nodes._nuclei_targets_by_agent",
                return_value={"agent-a": ["10.0.0.1"], "agent-b": ["10.0.0.2"]},
            ),
            patch("redis.asyncio.from_url", return_value=fake_redis),
            patch(
                "src.common.config.settings.get_settings",
                return_value=MagicMock(redis_url="redis://x"),
            ),
        ):
            result = await dispatch(state)

        # Matcher broadcast sent 1; nuclei per-agent sent 1 failed 1.
        assert result["received_results"] == 2
        # Task stats must reflect the merged totals.
        stats_update = [
            c for c in mock_store.update_task.call_args_list if c.kwargs.get("stats")
        ]
        assert stats_update, "expected update_task with stats"
        stats = stats_update[-1].kwargs["stats"]
        assert stats["done"] == 2 and stats["failed"] == 1

        # SSE message must mention both lanes explicitly.
        published = [
            c
            for c in fake_redis.publish.call_args_list
            if c.args and c.args[0] == f"vulnscan:task:{state['task_id']}"
        ]
        assert published
        msg = published[0].args[1]
        assert "matcher 1 sent/0 failed" in msg
        assert "nuclei 1 sent/1 failed" in msg
