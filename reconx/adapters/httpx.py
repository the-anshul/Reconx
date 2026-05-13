"""
adapters/httpx.py — HTTP probing adapter.
"""

import asyncio
import json
import logging
import ssl
import urllib.error
import urllib.request

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

        if proc.returncode not in (0, None):
            error = stderr.decode(errors="replace").strip()
            logger.warning(f"[httpx] Tool failed ({proc.returncode}): {error}")
            return await _probe_with_python(hosts)

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
        if results:
            return results

        logger.warning("[httpx] No results from httpx-toolkit; trying Python HTTP fallback")
        return await _probe_with_python(hosts)

    except asyncio.TimeoutError:
        logger.error(f"[httpx] Timed out after {timeout}s")
        return await _probe_with_python(hosts)
    except FileNotFoundError:
        logger.error("[httpx] Not found in PATH. Run: reconx setup")
        return await _probe_with_python(hosts)
    except Exception as e:
        logger.error(f"[httpx] Error: {e}")
        return await _probe_with_python(hosts)


async def _probe_with_python(hosts: list[str]) -> list[dict]:
    """Small stdlib HTTP probe fallback for machines without ProjectDiscovery httpx."""
    async def probe_one(host: str) -> dict | None:
        for scheme in ("https", "http"):
            url = f"{scheme}://{host}"
            result = await asyncio.to_thread(_request_url, url, host)
            if result:
                return result
        return None

    probed = await asyncio.gather(*(probe_one(host) for host in hosts))
    results = [item for item in probed if item]
    logger.info(f"[httpx:fallback] {len(results)} HTTP services found")
    return results


def _request_url(url: str, host: str) -> dict | None:
    context = ssl._create_unverified_context()
    request = urllib.request.Request(
        url,
        method="GET",
        headers={"User-Agent": "ReconX/2.0"},
    )
    try:
        with urllib.request.urlopen(request, timeout=8, context=context) as response:
            content = response.read(8192).decode("utf-8", errors="ignore")
            return {
                "url": response.geturl(),
                "domain": host,
                "status": response.getcode(),
                "title": _extract_title(content),
                "technologies": [],
                "content_length": response.headers.get("Content-Length") or len(content),
            }
    except urllib.error.HTTPError as e:
        return {
            "url": url,
            "domain": host,
            "status": e.code,
            "title": "",
            "technologies": [],
            "content_length": 0,
        }
    except Exception:
        return None


def _extract_title(html: str) -> str:
    lower = html.lower()
    start = lower.find("<title")
    if start == -1:
        return ""
    start = lower.find(">", start)
    end = lower.find("</title>", start)
    if start == -1 or end == -1:
        return ""
    return html[start + 1:end].strip()[:120]
