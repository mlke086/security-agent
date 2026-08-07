"""Unit tests for HostMetricsStore (需求① Agent 性能监控).

ES client is mocked (AsyncMock) so the tests run offline; each test
stubs the exact response shape the store expects.
"""

from unittest.mock import AsyncMock

import pytest

from src.agents.metrics_store import HostMetricsStore


@pytest.fixture
def store():
    """Store with a mocked ES client (bypasses __init__ network setup)."""
    s = HostMetricsStore.__new__(HostMetricsStore)
    s._es = AsyncMock()
    return s


class TestSaveMetrics:
    @pytest.mark.asyncio
    async def test_save_metrics_indexes_filtered_fields(self, store):
        await store.save_metrics(
            "agent-1",
            "web-01",
            {
                "cpu_percent": 42.3,
                "mem_percent": 68.1,
                "mem_total_mb": 8192,
                "disk_percent": 71.0,
                "net_in_kbps": 128.5,
                "load1": 1.05,
                "unknown_field": "should-be-dropped",
            },
        )
        store._es.index.assert_awaited_once()
        doc = store._es.index.await_args.kwargs["document"]
        assert doc["agent_id"] == "agent-1"
        assert doc["hostname"] == "web-01"
        assert doc["cpu_percent"] == 42.3
        assert doc["mem_percent"] == 68.1
        assert doc["disk_percent"] == 71.0
        assert doc["net_in_kbps"] == 128.5
        assert doc["load1"] == 1.05
        # 未知字段不落 ES（payload 白名单过滤）
        assert "unknown_field" not in doc
        # 数值字段转 float
        assert isinstance(doc["cpu_percent"], float)

    @pytest.mark.asyncio
    async def test_save_metrics_never_raises(self, store):
        """Best-effort: ES 故障只 log，不抛异常（WS 网关 fire-and-forget）。"""
        store._es.index = AsyncMock(side_effect=RuntimeError("es down"))
        await store.save_metrics("agent-1", "h", {"cpu_percent": 1.0})  # 不应抛


class TestQueryTimeseries:
    @pytest.mark.asyncio
    async def test_raw_points_shape(self, store):
        store._es.search = AsyncMock(
            return_value={
                "hits": {
                    "hits": [
                        {
                            "_source": {
                                "ts": "2026-08-06T10:00:00+00:00",
                                "cpu_percent": 42.345,
                                "mem_percent": 68.1,
                                "disk_percent": 71.0,
                                "net_in_kbps": 128.5,
                                "net_out_kbps": 64.2,
                                "load1": 1.05,
                            }
                        },
                        {
                            "_source": {
                                "ts": "2026-08-06T10:00:15+00:00",
                                "cpu_percent": 43.0,
                                "mem_percent": 68.2,
                            }
                        },
                    ]
                }
            }
        )
        points = await store.query_timeseries("agent-1", "2026-08-06T09:00:00Z", "2026-08-06T11:00:00Z")
        assert len(points) == 2
        assert points[0]["ts"] == "2026-08-06T10:00:00+00:00"
        assert points[0]["cpu"] == 42.34  # 四舍五入 2 位
        assert points[0]["mem"] == 68.1
        assert points[1]["cpu"] == 43.0
        # 缺省字段 -> None（前端图表容错）
        assert points[1]["disk"] is None
        # 查询下推：agent_id term + ts range
        query = store._es.search.await_args.kwargs["query"]
        assert query["bool"]["must"][0] == {"term": {"agent_id": "agent-1"}}
        assert "range" in query["bool"]["must"][1]

    @pytest.mark.asyncio
    async def test_downsampled_points_use_date_histogram(self, store):
        store._es.search = AsyncMock(
            return_value={
                "aggregations": {
                    "series": {
                        "buckets": [
                            {
                                "key": 1785992400000,  # 2026-08-06T05:00:00Z
                                "cpu": {"value": 50.5},
                                "mem": {"value": 70.2},
                                "disk": {"value": 80.0},
                                "net_in": {"value": 100.1},
                                "net_out": {"value": 50.0},
                                "load1": {"value": 2.0},
                            }
                        ]
                    }
                }
            }
        )
        points = await store.query_timeseries(
            "agent-1", "2026-07-30T00:00:00Z", "2026-08-06T12:00:00Z", downsample_interval="5m"
        )
        assert len(points) == 1
        assert points[0]["ts"] == "2026-08-06T05:00:00+00:00"
        assert points[0]["cpu"] == 50.5
        assert points[0]["mem"] == 70.2
        # 降采样路径必须走 aggs（size=0）
        assert store._es.search.await_args.kwargs["size"] == 0
        assert "date_histogram" in store._es.search.await_args.kwargs["aggs"]["series"]

    @pytest.mark.asyncio
    async def test_query_es_error_returns_empty(self, store):
        store._es.search = AsyncMock(side_effect=RuntimeError("es down"))
        assert await store.query_timeseries("agent-1", "a", "b") == []


class TestLatest:
    @pytest.mark.asyncio
    async def test_latest_returns_newest(self, store):
        store._es.search = AsyncMock(
            return_value={
                "hits": {
                    "hits": [
                        {
                            "_source": {
                                "agent_id": "agent-1",
                                "ts": "2026-08-06T10:00:00+00:00",
                                "cpu_percent": 42.3,
                                "mem_percent": 68.1,
                                "mem_total_mb": 8192.0,
                                "mem_used_mb": 5580.0,
                                "disk_percent": 71.0,
                                "disk_total_gb": 100.0,
                                "disk_used_gb": 71.0,
                                "net_in_kbps": 128.5,
                                "net_out_kbps": 64.2,
                                "load1": 1.05,
                            }
                        }
                    ]
                }
            }
        )
        latest = await store.latest("agent-1")
        assert latest is not None
        assert latest["cpu"] == 42.3
        assert latest["mem_total_mb"] == 8192.0
        # 按 ts desc 取 1 条
        assert store._es.search.await_args.kwargs["sort"] == [{"ts": {"order": "desc"}}]
        assert store._es.search.await_args.kwargs["size"] == 1

    @pytest.mark.asyncio
    async def test_latest_empty_returns_none(self, store):
        store._es.search = AsyncMock(return_value={"hits": {"hits": []}})
        assert await store.latest("agent-1") is None


class TestDeleteBefore:
    @pytest.mark.asyncio
    async def test_delete_before_returns_count(self, store):
        store._es.delete_by_query = AsyncMock(return_value={"deleted": 1234})
        deleted = await store.delete_before("2026-07-07T00:00:00+00:00")
        assert deleted == 1234
        # 清扫按 ts range < cutoff 删除
        query = store._es.delete_by_query.await_args.kwargs["query"]
        assert query == {"range": {"ts": {"lt": "2026-07-07T00:00:00+00:00"}}}

    @pytest.mark.asyncio
    async def test_delete_before_error_returns_zero(self, store):
        store._es.delete_by_query = AsyncMock(side_effect=RuntimeError("es down"))
        assert await store.delete_before("2026-07-07T00:00:00+00:00") == 0


class TestMapping:
    def test_mapping_matches_metrics_sample_fields(self):
        """mapping 覆盖 reporter.go MetricsSample 的全部 JSON tag。"""
        from src.agents.metrics_store import METRICS_MAPPING

        props = METRICS_MAPPING["mappings"]["properties"]
        for field in (
            "agent_id",
            "hostname",
            "ts",
            "cpu_percent",
            "mem_percent",
            "mem_total_mb",
            "mem_used_mb",
            "disk_percent",
            "disk_total_gb",
            "disk_used_gb",
            "net_in_kbps",
            "net_out_kbps",
            "load1",
        ):
            assert field in props, f"missing mapping field: {field}"
