"""Background periodic tasks: rules sync and offline host detection."""

import asyncio
from datetime import datetime, timedelta

from src.common.config.settings import get_settings
from src.common.logging.logger import get_logger

logger = get_logger(__name__)

_tasks: list[asyncio.Task] = []


async def _rules_sync_loop() -> None:
    """Daily rules sync at 03:00 (configurable via settings.rules_sync_cron)."""
    settings = get_settings()
    cron = settings.rules_sync_cron  # e.g. "0 3 * * *"
    hour = 3
    minute = 0
    try:
        parts = cron.split()
        minute = int(parts[0])
        hour = int(parts[1])
    except (ValueError, IndexError):
        pass

    logger.info("rules_sync_scheduler_started", hour=hour, minute=minute)
    while True:
        # P2-COMMON-01 (2026-07-20): use timedelta(days=1) so the loop survives
        # month boundaries (datetime.replace(day=32) raises ValueError on
        # Jan 31 / Mar 31 / etc). datetime.now() stays naive here because the
        # cron fields are wall-clock; we compare like-for-like.
        now = datetime.now()
        next_run = now.replace(hour=hour, minute=minute, second=0, microsecond=0)
        if next_run <= now:
            next_run = next_run + timedelta(days=1)
        wait_sec = (next_run - now).total_seconds()
        await asyncio.sleep(wait_sec)

        try:
            from src.agents.rules_sync import sync_rules

            version = await sync_rules(source=settings.rules_sync_source)
            logger.info("scheduled_rules_sync_complete", version=version)
        except Exception as exc:
            logger.warning("scheduled_rules_sync_failed", error=str(exc))


async def _offline_check_loop() -> None:
    """Periodic offline host detection every 60 seconds."""
    interval = 60
    logger.info("offline_check_scheduler_started", interval_sec=interval)
    while True:
        await asyncio.sleep(interval)
        try:
            from src.agents.manager import mark_offline_expired

            count = await mark_offline_expired()
            if count > 0:
                logger.info("offline_detected", count=count)
        except Exception as exc:
            logger.warning("offline_check_failed", error=str(exc))


def start_background_tasks() -> None:
    """Start all periodic background tasks. Called during FastAPI lifespan startup."""
    global _tasks
    _tasks = [
        asyncio.create_task(_rules_sync_loop()),
        asyncio.create_task(_offline_check_loop()),
    ]
    logger.info("background_tasks_started", count=len(_tasks))


async def stop_background_tasks() -> None:
    """Cancel all periodic background tasks. Called during FastAPI lifespan shutdown."""
    for t in _tasks:
        t.cancel()
    if _tasks:
        await asyncio.gather(*_tasks, return_exceptions=True)
    _tasks.clear()
    logger.info("background_tasks_stopped")
