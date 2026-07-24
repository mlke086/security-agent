#!/usr/bin/env python3
"""TaskWorker entrypoint -- vulnscan Redis Stream consumer.

Mirrors the inline `python -c "..."` block that used to live in
entrypoint.sh. Extracted into a real file so it can be linted, type-checked,
and unit-tested independently of the shell environment.

Signal handling:
  SIGTERM / SIGINT -> set stop event -> graceful shutdown (handle.stop(timeout=10s))

Boot order:
  1. Attach signal handlers (SIGTERM, SIGINT) to set a stop event
  2. Construct TaskWorker (does not connect yet)
  3. start() -> returns a WorkerHandle that owns the consumer task
  4. await stop event
  5. handle.stop(timeout=10.0)
  6. log stop, return

Intentionally a thin file -- business logic lives in
src.orchestration.task_queue.TaskWorker.
"""

import asyncio
import signal

from src.common.logging.logger import get_logger
from src.orchestration.task_queue import TaskWorker


log = get_logger("entrypoint.taskworker")


async def main() -> None:
    worker = TaskWorker()
    handle = worker.start()
    stop = asyncio.Event()

    def _on_term() -> None:
        log.info("taskworker_signal_received")
        stop.set()

    loop = asyncio.get_event_loop()
    for sig in (signal.SIGTERM, signal.SIGINT):
        loop.add_signal_handler(sig, _on_term)

    log.info("taskworker_started", consumer=handle.consumer)
    await stop.wait()
    await handle.stop(timeout=10.0)
    log.info("taskworker_stopped")


if __name__ == "__main__":
    asyncio.run(main())
