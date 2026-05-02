"""
adapters/katana.py — Web crawler adapter to find hidden endpoints.
"""

import asyncio
import logging

logger = logging.getLogger("reconx.adapters.katana")


async def run_katana(targets: list[str], timeout: int = 300) -> list[str]:
    """
    Run katana to crawl URLs and find endpoints.
    """
    if not targets:
        return []

    input_data = "\n".join(targets)
    # -silent: no banner, -jc: js crawling, -kf: known files
    cmd = "katana -silent -jc -kf all"

    logger.info(f"[katana] Crawling {len(targets)} targets...")

    try:
        proc = await asyncio.create_subprocess_shell(
            cmd,
            stdin=asyncio.subprocess.PIPE,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
        )
        stdout, stderr = await asyncio.wait_for(
            proc.communicate(input=input_data.encode()), timeout=timeout
        )

        urls = [line.strip() for line in stdout.decode().splitlines() if line.strip()]
        logger.info(f"[katana] Discovered {len(urls)} URLs")
        return list(set(urls))

    except Exception as e:
        logger.error(f"[katana] Error: {e}")
        return []
