"""
modules/recon.py — Passive reconnaissance module.
Runs subfinder + amass, deduplicates, and returns clean subdomain list.
"""

import asyncio
import logging
from adapters.subfinder import run_subfinder
from adapters.amass import run_amass
from adapters.assetfinder import run_assetfinder
from adapters.passive_sources import run_passive_sources

logger = logging.getLogger("reconx.modules.recon")


import shutil
import os

async def run_recon(domain: str, config: dict) -> dict[str, set[str]]:
    """
    Passive subdomain enumeration using multiple tools.
    Returns dict mapping subdomain to a list of sources.
    """
    logger.info(f"[recon] Starting passive recon for: {domain}")

    recon_cfg = config.get("tools", {})
    timeout = config.get("general", {}).get("timeout", 60)

    # (Tool Name, Coroutine, Binary Path)
    tool_tasks = []

    # 1. Subfinder
    sf_path = shutil.which("subfinder") or os.path.expanduser("~/go/bin/subfinder")
    if os.path.exists(sf_path) or shutil.which("subfinder"):
        sf_flags = recon_cfg.get("subfinder", {}).get("flags", "-silent")
        tool_tasks.append(("subfinder", run_subfinder(domain, timeout=timeout * 2, extra_flags=sf_flags)))
    else:
        logger.warning("  [!] subfinder missing. Using Python passive fallback.")

    # 2. Assetfinder
    if shutil.which("assetfinder") or os.path.exists(os.path.expanduser("~/go/bin/assetfinder")):
        tool_tasks.append(("assetfinder", run_assetfinder(domain, timeout=timeout * 2)))

    # 3. Amass
    if shutil.which("amass") or os.path.exists(os.path.expanduser("~/go/bin/amass")):
        amass_flags = recon_cfg.get("amass", {}).get("flags", "")
        tool_tasks.append(("amass", run_amass(domain, timeout=timeout * 4, extra_flags=amass_flags)))

    # 4. Pure Python Passive Sources (Always Run)
    tool_tasks.append(("passive", run_passive_sources(domain, timeout=min(timeout, 60))))

    # Gather all
    names = [t[0] for t in tool_tasks]
    coroutines = [t[1] for t in tool_tasks]
    results = await asyncio.gather(*coroutines, return_exceptions=True)

    findings: dict[str, set[str]] = {}
    
    # Initialize with the target domain itself
    findings[domain] = {"manual"}

    for name, result in zip(names, results):
        if isinstance(result, Exception):
            logger.warning(f"[recon] Tool {name} returned exception: {result}")
            continue
        
        if name == "passive":
            # result is list[tuple[sub, source]]
            for sub, source in result:
                if sub not in findings: findings[sub] = set()
                findings[sub].add(source)
        else:
            # result is list[sub]
            for sub in result:
                if sub not in findings: findings[sub] = set()
                findings[sub].add(name)

    # Filter/Capping
    max_subs = config.get("safety", {}).get("max_subdomains", 500)
    all_subs = list(findings.keys())
    if len(all_subs) > max_subs:
        logger.warning(f"[recon] Found {len(all_subs)} subs — capping at {max_subs}")
        all_subs = sorted(all_subs)[:max_subs]
        findings = {s: findings[s] for s in all_subs}

    # Convert sets to sorted lists for JSON serialization
    final_findings = {sub: sorted(list(sources)) for sub, sources in findings.items()}

    logger.info(f"[recon] Total unique subdomains: {len(final_findings)}")
    return final_findings
