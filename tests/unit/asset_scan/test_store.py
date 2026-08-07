"""Unit tests for AssetScanStore (需求②, ES client mocked)."""

from unittest.mock import AsyncMock, patch

import pytest

from src.asset_scan.store import AssetScanStore


@pytest.fixture
def store():
    s = AssetScanStore.__new__(AssetScanStore)
    s._es = AsyncMock()
    return s


class TestTasks:
    @pytest.mark.asyncio
    async def test_save_and_get_task(self, store):
        task = {"task_id": "t-1", "source": "manual", "targets": ["10.0.0.0/24"],
                "status": "queued", "created_at": "2026-08-06T00:00:00+00:00"}
        await store.save_task(task)
        store._es.index.assert_awaited_once()
        assert store._es.index.await_args.kwargs["id"] == "t-1"

        store._es.get = AsyncMock(return_value={"found": True, "_source": task})
        got = await store.get_task("t-1")
        assert got["task_id"] == "t-1"

    @pytest.mark.asyncio
    async def test_update_task_stamps_updated_at(self, store):
        await store.update_task("t-1", status="running")
        doc = store._es.update.await_args.kwargs["doc"]
        assert doc["status"] == "running"
        assert "updated_at" in doc

    @pytest.mark.asyncio
    async def test_list_tasks_sort_and_filter(self, store):
        store._es.search = AsyncMock(return_value={"hits": {"hits": [
            {"_source": {"task_id": "t-2", "status": "completed"}},
        ]}})
        rows = await store.list_tasks(status="completed")
        assert rows[0]["task_id"] == "t-2"
        query = store._es.search.await_args.kwargs["query"]
        assert query == {"bool": {"must": [{"term": {"status": "completed"}}]}}

    @pytest.mark.asyncio
    async def test_delete_task_cascades(self, store):
        await store.delete_task("t-1")
        assert store._es.delete_by_query.await_count == 4  # tasks/assets/vulns/reports


class TestAssetsAndVulns:
    @pytest.mark.asyncio
    async def test_save_and_list_assets(self, store):
        store._es.search = AsyncMock(return_value={"hits": {"hits": [
            {"_source": {"task_id": "t-1", "ip": "10.0.0.5", "ports": [80]}},
        ]}})
        assets = await store.list_assets("t-1")
        assert assets[0]["ip"] == "10.0.0.5"
        query = store._es.search.await_args.kwargs["query"]
        assert query == {"term": {"task_id": "t-1"}}

    @pytest.mark.asyncio
    async def test_save_vulns_empty_noop(self, store):
        await store.save_vulns("t-1", [])  # 不应抛错

    @pytest.mark.asyncio
    async def test_save_report_and_get(self, store):
        store._es.get = AsyncMock(return_value={"found": True, "_source": {"task_id": "t-1"}})
        report = await store.get_report("t-1")
        assert report["task_id"] == "t-1"


class TestEnvelopeAndRunner:
    @pytest.mark.asyncio
    async def test_runner_marks_failed_on_subgraph_error(self, store):
        """子图执行抛错时, runner 写 failed 状态后 re-raise(进 DLQ)。"""
        from src.asset_scan import store as store_mod
        from src.asset_scan.runner import run_asset_scan_from_envelope
        from src.orchestration.task_queue.enqueue import AssetScanEnvelope

        envelope = AssetScanEnvelope(task_id="a-x", source="manual", targets=["10.0.0.0/24"])
        store_mod._store = store  # 注入 mock 单例
        store.update_task = AsyncMock()
        with (
            pytest.raises(RuntimeError, match="scan blew up"),
            patch(
                "src.orchestration.subgraphs.asset_scan.graph.run_asset_scan",
                AsyncMock(side_effect=RuntimeError("scan blew up")),
            ),
        ):
            await run_asset_scan_from_envelope(envelope)
        # 先写 running，再写 failed（2 次）；task_id 为位置参数
        assert store.update_task.await_count == 2
        calls = [c for c in store.update_task.await_args_list]
        assert calls[0].args[0] == "a-x"
        assert calls[0].kwargs["status"] == "running"
        assert calls[1].args[0] == "a-x"
        assert calls[1].kwargs["status"] == "failed"
