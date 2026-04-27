"""
modules/enum.py — DNS + HTTP enumeration module.
"""

import asyncio
import logging
from adapters.dnsx import run_dnsx
from adapters.httpx import run_httpx

logger = logging.getLogger("reconx.modules.enum")


async def run_dns_enum(subdomains: list[str], config: dict) -> list[dict]:
    """
    Resolve subdomains to live IPs using dnsx.
    Returns list of {domain, ip, cnames}.
    """
    timeout = config.get("general", {}).get("timeout", 60)
    logger.info(f"[enum.dns] Resolving {len(subdomains)} subdomains...")
    live = await run_dnsx(subdomains, timeout=timeout * 2)
    logger.info(f"[enum.dns] {len(live)} live hosts")
    return live


async def run_http_enum(hosts: list[str], config: dict) -> list[dict]:
    """
    Probe live hosts for HTTP services.
    Returns list of {url, domain, status, title, technologies}.
    """
    timeout = config.get("general", {}).get("timeout", 60)
    logger.info(f"[enum.http] Probing {len(hosts)} hosts for HTTP...")
    http_results = await run_httpx(hosts, timeout=timeout * 2)
    logger.info(f"[enum.http] {len(http_results)} HTTP services found")
    return http_results
