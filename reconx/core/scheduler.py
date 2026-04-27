"""
core/scheduler.py — Concurrency and task scheduling utilities.
Wraps asyncio patterns used throughout the pipeline.
"""

import asyncio
import logging
from typing import Callable, Any, Coroutine

logger = logging.getLogger("reconx.scheduler")


async def run_with_limit(
    coroutines: list[Coroutine],
    max_concurrent: int = 10,
    label: str = "tasks"
) -> list[Any]:
    """
    Run coroutines with a concurrency limit using asyncio.Semaphore.
    Returns list of results in same order as input.
    """
    sem = asyncio.Semaphore(max_concurrent)
    results = []

    async def bounded(coro):
        async with sem:
            return await coro

    bounded_tasks = [bounded(c) for c in coroutines]
    results = await asyncio.gather(*bounded_tasks, return_exceptions=True)

    errors = [r for r in results if isinstance(r, Exception)]
    if errors:
        logger.warning(f"[scheduler] {len(errors)}/{len(results)} {label} failed")

    return results


async def run_parallel_targets(
    targets: list[str],
    handler: Callable[[str], Coroutine],
    max_concurrent: int = 10,
) -> dict[str, Any]:
    """
    Run handler(target) for each target in parallel.
    Returns {target: result} dict.
    """
    sem = asyncio.Semaphore(max_concurrent)
    output: dict[str, Any] = {}

    async def process(target: str):
        async with sem:
            try:
                result = await handler(target)
                output[target] = result
            except Exception as e:
                logger.error(f"[scheduler] Failed for {target}: {e}")
                output[target] = None

    await asyncio.gather(*[process(t) for t in targets])
    return output
