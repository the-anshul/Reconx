"""
adapters/httpx.py — HTTP probing adapter.
"""

import asyncio
import json
import logging

logger = logging.getLogger("reconx.adapters.httpx")


async def run_httpx(hosts: list[str], timeout: int = 60) -> list[dict]:
    """
    Probe hosts for live HTTP/HTTPS services.
    Returns normalized list of {url, status, title, tech}.
    """
    if not hosts:
        return []

    input_data = "\n".join(hosts)
    cmd = "httpx-toolkit -silent -status-code -tech-detect -title -follow-redirects -random-agent -json"

    logger.info(f"[httpx] Probing {len(hosts)} hosts...")

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
                    "url": data.get("url", ""),
                    "domain": data.get("input", ""),
                    "status": data.get("status-code", 0),
                    "title": data.get("title", ""),
                    "technologies": data.get("tech", []),
                    "content_length": data.get("content-length", 0),
                })
            except json.JSONDecodeError:
                continue

        logger.info(f"[httpx] {len(results)} HTTP services found")
        return results

    except asyncio.TimeoutError:
        logger.error(f"[httpx] Timed out after {timeout}s")
        return []
    except FileNotFoundError:
        logger.error("[httpx] Not found in PATH. Run: reconx setup")
        return []
    except Exception as e:
        logger.error(f"[httpx] Error: {e}")
        return []
