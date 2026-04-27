"""
adapters/dnsx.py — DNS resolution and live host filtering.
"""

import asyncio
import json
import logging

logger = logging.getLogger("reconx.adapters.dnsx")


async def run_dnsx(subdomains: list[str], timeout: int = 60) -> list[dict]:
    """
    Resolve subdomains using dnsx.
    Returns list of {domain, ip} for live hosts only.
    """
    if not subdomains:
        return []

    # Write temp input
    input_data = "\n".join(subdomains)
    cmd = "dnsx -silent -resp -json"

    logger.info(f"[dnsx] Resolving {len(subdomains)} subdomains...")

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

        results = []
        for line in stdout.decode().splitlines():
            line = line.strip()
            if not line:
                continue
            try:
                data = json.loads(line)
                results.append({
                    "domain": data.get("host", ""),
                    "ip": data.get("a", [None])[0] if data.get("a") else None,
                    "cnames": data.get("cname", []),
                })
            except json.JSONDecodeError:
                continue

        logger.info(f"[dnsx] {len(results)} live hosts resolved")
        return results

    except asyncio.TimeoutError:
        logger.error(f"[dnsx] Timed out after {timeout}s")
        return []
    except FileNotFoundError:
        logger.error("[dnsx] Not found in PATH. Run: reconx setup")
        return []
    except Exception as e:
        logger.error(f"[dnsx] Error: {e}")
        return []
