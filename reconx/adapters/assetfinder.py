"""
adapters/assetfinder.py — Assetfinder adapter for better subdomain discovery.
"""

import asyncio
import logging

logger = logging.getLogger("reconx.adapters.assetfinder")


async def run_assetfinder(domain: str, timeout: int = 60) -> list[str]:
    """
    Run assetfinder to find subdomains.
    """
    cmd = f"assetfinder --subs-only {domain}"
    logger.info(f"[assetfinder] Running: {cmd}")

    try:
        proc = await asyncio.create_subprocess_shell(
            cmd,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
        )
        stdout, stderr = await asyncio.wait_for(proc.communicate(), timeout=timeout)

        subs = [line.strip() for line in stdout.decode().splitlines() if line.strip()]
        logger.info(f"[assetfinder] Found {len(subs)} subdomains for {domain}")
        return subs

    except Exception as e:
        logger.error(f"[assetfinder] Error: {e}")
        return []
