"""
modules/vuln.py — Vulnerability scanning module.
Runs nmap (port scan) + nuclei (vuln detection).
"""

import asyncio
import logging
from adapters.nmap import run_nmap
from adapters.nuclei import run_nuclei

logger = logging.getLogger("reconx.modules.vuln")


async def run_port_scan(targets: list[str], config: dict) -> dict[str, list[dict]]:
    """
    Run nmap on each target concurrently (with concurrency limit).
    Returns dict: {host -> [port_dicts]}
    """
    nmap_cfg = config.get("tools", {}).get("nmap", {})
    top_ports = nmap_cfg.get("top_ports", 1000)
    timeout = config.get("general", {}).get("timeout", 60) * 5
    max_concurrent = config.get("safety", {}).get("max_concurrent", 10)

    sem = asyncio.Semaphore(max_concurrent)
    results: dict[str, list[dict]] = {}

    async def scan_one(host: str):
        async with sem:
            ports = await run_nmap(host, top_ports=top_ports, timeout=timeout)
            results[host] = ports

    await asyncio.gather(*[scan_one(t) for t in targets])
    return results


async def run_vuln_scan(http_targets: list[str], config: dict) -> list[dict]:
    """
    Run nuclei against all HTTP targets.
    Returns flat list of vuln findings.
    """
    nuclei_cfg = config.get("tools", {}).get("nuclei", {})
    severity = nuclei_cfg.get("severity", "low,medium,high,critical")
    templates = nuclei_cfg.get("templates", "")
    timeout = config.get("general", {}).get("timeout", 60) * 5

    if not http_targets:
        logger.warning("[vuln] No HTTP targets to scan")
        return []

    findings = await run_nuclei(http_targets, severity=severity, templates=templates, timeout=timeout)
    return findings
