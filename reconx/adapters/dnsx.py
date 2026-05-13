"""
adapters/dnsx.py — DNS resolution and live host filtering.
"""

import asyncio
import json
import logging
import socket

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

        if proc.returncode not in (0, None):
            error = stderr.decode(errors="replace").strip()
            logger.warning(f"[dnsx] Tool failed ({proc.returncode}): {error}")
            return await _resolve_with_python(subdomains)

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
        if results:
            return results

        logger.warning("[dnsx] No results from dnsx; trying Python DNS fallback")
        return await _resolve_with_python(subdomains)

    except asyncio.TimeoutError:
        logger.error(f"[dnsx] Timed out after {timeout}s")
        return await _resolve_with_python(subdomains)
    except FileNotFoundError:
        logger.error("[dnsx] Not found in PATH. Run: reconx setup")
        return await _resolve_with_python(subdomains)
    except Exception as e:
        logger.error(f"[dnsx] Error: {e}")
        return await _resolve_with_python(subdomains)


async def _resolve_with_python(subdomains: list[str]) -> list[dict]:
    """Resolve hosts with stdlib DNS so ReconX still returns useful output."""
    async def resolve_one(host: str) -> dict | None:
        try:
            infos = await asyncio.to_thread(socket.getaddrinfo, host, None, type=socket.SOCK_STREAM)
            ips = []
            for info in infos:
                ip = info[4][0]
                if ip not in ips:
                    ips.append(ip)
            if not ips:
                return None
            return {"domain": host, "ip": ips[0], "cnames": []}
        except socket.gaierror:
            return None
        except Exception as e:
            logger.debug(f"[dnsx:fallback] Could not resolve {host}: {e}")
            return None

    resolved = await asyncio.gather(*(resolve_one(host) for host in subdomains))
    results = [item for item in resolved if item]
    logger.info(f"[dnsx:fallback] {len(results)} live hosts resolved")
    return results
