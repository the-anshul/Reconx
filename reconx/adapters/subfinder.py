"""
adapters/subfinder.py — Subfinder tool adapter.
Isolated, testable, no raw output leakage.
"""

import asyncio
import logging
from typing import Optional

logger = logging.getLogger("reconx.adapters.subfinder")


async def run_subfinder(domain: str, timeout: int = 60, extra_flags: str = "-silent") -> list[str]:
    """
    Run subfinder for passive subdomain enumeration.
    Returns list of discovered subdomains.
    """
    cmd = f"subfinder -d {domain} {extra_flags}"
    logger.info(f"[subfinder] Running: {cmd}")

    try:
        proc = await asyncio.create_subprocess_shell(
            cmd,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
        )
        stdout, stderr = await asyncio.wait_for(proc.communicate(), timeout=timeout)

        if proc.returncode not in (0, None):
            logger.warning(f"[subfinder] Non-zero exit ({proc.returncode}): {stderr.decode().strip()}")

        subs = [line.strip() for line in stdout.decode().splitlines() if line.strip()]
        logger.info(f"[subfinder] Found {len(subs)} subdomains for {domain}")
        return subs

    except asyncio.TimeoutError:
        logger.error(f"[subfinder] Timed out after {timeout}s for {domain}")
        return []
    except FileNotFoundError:
        logger.error("[subfinder] Not found in PATH. Run: reconx setup")
        return []
    except Exception as e:
        logger.error(f"[subfinder] Unexpected error: {e}")
        return []
