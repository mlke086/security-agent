"""Unit tests for scheduler: start/stop, offline check, rules sync loop."""
import asyncio
from unittest.mock import AsyncMock, patch

import pytest

from src.agents.scheduler import (
    _offline_check_loop,
    _rules_sync_loop,
    start_background_tasks,
    stop_background_tasks,
)


class TestStartStop:
    @pytest.mark.asyncio
    async def test_start_creates_tasks(self):
        with patch("src.agents.scheduler.asyncio.create_task") as mock_ct:
            mock_ct.side_effect = lambda c: c
            start_background_tasks()
            assert mock_ct.call_count == 2

    @pytest.mark.asyncio
    async def test_stop_cancels_and_clears(self):
        # Create real cancelled coroutines as mock tasks
        async def dummy():
            pass

        t1 = asyncio.create_task(dummy())
        t2 = asyncio.create_task(dummy())
        t1.cancel()
        t2.cancel()
        # Suppress cancellation errors
        try:
            await t1
        except asyncio.CancelledError:
            pass
        try:
            await t2
        except asyncio.CancelledError:
            pass

        import src.agents.scheduler as sched_mod
        sched_mod._tasks = [t1, t2]
        await stop_background_tasks()
        assert len(sched_mod._tasks) == 0


class TestOfflineCheckLoop:
    @pytest.mark.asyncio
    async def test_offline_check_runs_once_then_cancelled(self):
        with patch("src.agents.manager.mark_offline_expired", AsyncMock(return_value=0)):
            task = asyncio.create_task(_offline_check_loop())
            await asyncio.sleep(0.1)
            task.cancel()
            try:
                await task
            except asyncio.CancelledError:
                pass

    @pytest.mark.asyncio
    async def test_offline_check_handles_error(self):
        with patch("src.agents.manager.mark_offline_expired", AsyncMock(side_effect=RuntimeError("ES down"))):
            task = asyncio.create_task(_offline_check_loop())
            await asyncio.sleep(0.1)
            task.cancel()
            try:
                await task
            except asyncio.CancelledError:
                pass


class TestRulesSyncLoop:
    @pytest.mark.asyncio
    async def test_rules_sync_runs_once_then_cancelled(self):
        # Patch datetime.now so next_run is far in the future -> wait is long
        # But we cancel quickly
        with (
            patch("src.agents.rules_sync.sync_rules", AsyncMock(return_value="v99")),
            patch("src.agents.scheduler.get_settings") as mock_settings,
        ):
            mock_settings.return_value.rules_sync_cron = "0 3 * * *"
            mock_settings.return_value.rules_sync_source = "nvd"
            task = asyncio.create_task(_rules_sync_loop())
            await asyncio.sleep(0.1)
            task.cancel()
            try:
                await task
            except asyncio.CancelledError:
                pass
