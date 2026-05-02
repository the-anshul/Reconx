"""
modules/recon.py — Passive reconnaissance module.
Runs subfinder + amass, deduplicates, and returns clean subdomain list.
"""

import asyncio
import logging
from adapters.subfinder import run_subfinder
from adapters.amass import run_amass
from adapters.assetfinder import run_assetfinder

logger = logging.getLogger("reconx.modules.recon")


async def run_recon(domain: str, config: dict) -> list[str]:
    """
    Passive subdomain enumeration using multiple tools.
    Returns deduplicated list of subdomains.
    """
    logger.info(f"[recon] Starting passive recon for: {domain}")

    recon_cfg = config.get("tools", {})
    timeout = config.get("general", {}).get("timeout", 60)

    tasks = []

    # Always run subfinder
    sf_flags = recon_cfg.get("subfinder", {}).get("flags", "-silent")
    tasks.append(run_subfinder(domain, timeout=timeout * 2, extra_flags=sf_flags))

    # Run assetfinder
    tasks.append(run_assetfinder(domain, timeout=timeout * 2))

    # Run amass if enabled (slower, so longer timeout)
    amass_flags = recon_cfg.get("amass", {}).get("flags", "")
    tasks.append(run_amass(domain, timeout=timeout * 4, extra_flags=amass_flags))

    results = await asyncio.gather(*tasks, return_exceptions=True)

    all_subs = set()
    for result in results:
        if isinstance(result, Exception):
            logger.warning(f"[recon] Tool returned exception: {result}")
            continue
        all_subs.update(result)

    # Add the target domain itself to the set to ensure it gets scanned
    all_subs.add(domain)

    max_subs = config.get("safety", {}).get("max_subdomains", 500)
    if len(all_subs) > max_subs:
        logger.warning(f"[recon] Found {len(all_subs)} subs — capping at {max_subs} (safety limit)")
        all_subs = set(list(all_subs)[:max_subs])

    subs = sorted(all_subs)
    logger.info(f"[recon] Total unique subdomains: {len(subs)}")
    return subs
