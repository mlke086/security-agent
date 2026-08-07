"""Unit tests for the TaskEnvelope dataclass (no Redis required)."""

from __future__ import annotations

import json

from src.orchestration.task_queue.enqueue import TaskEnvelope


def test_envelope_defaults():
    e = TaskEnvelope(task_id="t-1", source="manual")
    assert e.task_id == "t-1"
    assert e.source == "manual"
    assert e.targets == []
    assert e.modules == ["sys_vuln", "baseline"]
    assert e.engine == "matcher"
    assert e.nuclei_severity == []
    assert e.nuclei_severity is not e.__dataclass_fields__  # just an is-check, ignore
    assert e.nuclei_tags == []
    assert e.nuclei_templates == []
    assert e.nuclei_timeout_sec == 0


def test_envelope_to_from_json_roundtrip():
    e = TaskEnvelope(
        task_id="t-2",
        source="manual",
        targets=["h-a", "h-b"],
        modules=["sys_vuln"],
        engine="nuclei",
        nuclei_severity=["critical", "high"],
        nuclei_tags=["rce"],
        nuclei_templates=["cves/2024/CVE-2024-1234"],
        nuclei_timeout_sec=120,
        actor="admin",
    )
    raw = e.to_json()
    decoded = TaskEnvelope.from_json(raw)
    assert decoded.task_id == e.task_id
    assert decoded.targets == e.targets
    assert decoded.engine == "nuclei"
    assert decoded.nuclei_severity == ["critical", "high"]
    assert decoded.nuclei_tags == ["rce"]
    assert decoded.nuclei_templates == ["cves/2024/CVE-2024-1234"]
    assert decoded.nuclei_timeout_sec == 120
    assert decoded.actor == "admin"


def test_envelope_from_bytes():
    """XREAD returns bytes; the worker must accept either type."""
    payload = {"task_id": "t-3", "source": "manual", "engine": "matcher"}
    raw = json.dumps(payload).encode("utf-8")
    e = TaskEnvelope.from_json(raw)
    assert e.task_id == "t-3"
    assert e.source == "manual"


def test_envelope_from_dict_drops_unknown_keys():
    """A future schema bump must not crash older workers."""
    e = TaskEnvelope.from_dict({"task_id": "t-4", "source": "manual", "future_field": "ignored"})
    assert e.task_id == "t-4"
    assert e.source == "manual"
    # No exception, unknown field silently dropped


def test_envelope_asdict_serialisable_to_json():
    """Sanity check that json.dumps accepts the dataclass asdict output."""
    e = TaskEnvelope(task_id="t-5", source="manual")
    payload = json.loads(e.to_json())
    assert payload["task_id"] == "t-5"
    assert payload["submitted_at"] == ""  # not yet populated by enqueue_task


# -- P3-A (需求②): AssetScanEnvelope -----------------------------------------


def test_asset_envelope_defaults():
    from src.orchestration.task_queue.enqueue import AssetScanEnvelope

    e = AssetScanEnvelope(task_id="a-1", source="manual")
    assert e.task_id == "a-1"
    assert e.targets == []
    assert e.ports == []
    assert e.engine == "fast"
    assert e.modules == ["discovery", "fingerprint", "cve", "nuclei"]
    assert e.schedule == ""


def test_asset_envelope_roundtrip_and_bytes():
    from src.orchestration.task_queue.enqueue import AssetScanEnvelope

    e = AssetScanEnvelope(
        task_id="a-2",
        source="manual",
        targets=["10.0.0.0/24", "10.0.1.5"],
        ports=[80, 443, 22],
        engine="full",
        modules=["discovery", "cve"],
        schedule="0 2 * * *",
        actor="admin",
    )
    decoded = AssetScanEnvelope.from_json(e.to_json())
    assert decoded.targets == e.targets
    assert decoded.ports == [80, 443, 22]
    assert decoded.engine == "full"
    assert decoded.schedule == "0 2 * * *"
    assert decoded.actor == "admin"
    # bytes 形态（XREAD 返回 bytes）
    decoded_bytes = AssetScanEnvelope.from_json(e.to_json().encode("utf-8"))
    assert decoded_bytes.task_id == "a-2"


def test_asset_envelope_from_dict_drops_unknown_keys():
    from src.orchestration.task_queue.enqueue import AssetScanEnvelope

    e = AssetScanEnvelope.from_dict({"task_id": "a-3", "source": "manual", "future_field": "x"})
    assert e.task_id == "a-3"
    assert not hasattr(e, "future_field")


def test_enqueue_asset_task_uses_assetscan_stream():
    """enqueue_asset_task 必须写 assetscan 流 + assetscan 状态键 + ES queued 记录。"""
    import asyncio
    from unittest.mock import AsyncMock, patch

    from src.orchestration.task_queue import enqueue as enq_mod
    from src.orchestration.task_queue.keys import STREAM_ASSET_TASKS

    async def run():
        fake_redis = AsyncMock()
        fake_redis.xadd = AsyncMock(return_value="1-0")
        fake_redis.set = AsyncMock(return_value=True)
        fake_store = AsyncMock()
        fake_store.save_task = AsyncMock()
        with (
            patch.object(enq_mod.aioredis, "from_url", return_value=fake_redis),
            patch("src.asset_scan.store.get_asset_store", return_value=fake_store),
        ):
            e = await enq_mod.enqueue_asset_task(
                source="manual", targets=["10.0.0.0/24"], actor="admin"
            )
        return e, fake_redis, fake_store

    e, fake_redis, fake_store = asyncio.run(run())
    assert e.task_id
    assert e.source == "manual"
    fake_redis.xadd.assert_awaited_once()
    stream = fake_redis.xadd.await_args.args[0]
    assert stream == STREAM_ASSET_TASKS
    fake_redis.set.assert_awaited_once()
    status_key = fake_redis.set.await_args.args[0]
    assert status_key.startswith("assetscan:queue:status:")
    # 与 vulnscan 流隔离
    assert stream != "vulnscan:queue:tasks"
    # ES queued 记录（P3-F：runner update_task 依赖文档存在）
    fake_store.save_task.assert_awaited_once()
    doc = fake_store.save_task.await_args.args[0]
    assert doc["task_id"] == e.task_id
    assert doc["status"] == "queued"
