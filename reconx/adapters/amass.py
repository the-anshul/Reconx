"""
adapters/amass.py — Amass passive recon adapter.
"""

import asyncio
import logging

logger = logging.getLogger("reconx.adapters.amass")


async def run_amass(domain: str, timeout: int = 120, extra_flags: str = "") -> list[str]:
    """
    Run amass in passive mode for subdomain discovery.
    Returns list of subdomains.
    """
    cmd = f"amass enum -passive -d {domain} {extra_flags}"
    logger.info(f"[amass] Running: {cmd}")

    try:
        proc = await asyncio.create_subprocess_shell(
            cmd,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
        )
        stdout, stderr = await asyncio.wait_for(proc.communicate(), timeout=timeout)

        subs = [line.strip() for line in stdout.decode().splitlines() if line.strip()]
        logger.info(f"[amass] Found {len(subs)} subdomains for {domain}")
        return subs

    except asyncio.TimeoutError:
        logger.warning(f"[amass] Timed out after {timeout}s — partial results may be missing")
        return []
    except FileNotFoundError:
        logger.warning("[amass] Not installed — skipping")
        return []
    except Exception as e:
        logger.error(f"[amass] Error: {e}")
        return []
