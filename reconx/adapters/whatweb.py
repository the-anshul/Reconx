"""
adapters/whatweb.py — WhatWeb adapter for detailed technology fingerprinting.
"""

import asyncio
import logging
import json
import os

logger = logging.getLogger("reconx.adapters.whatweb")


async def run_whatweb(targets: list[str], timeout: int = 300) -> list[dict]:
    """
    Run WhatWeb to fingerprint technologies on the targets.
    Returns a list of dicts with tech info.
    """
    if not targets:
        return []

    # Filter out non-http targets for safety
    targets = [t for t in targets if t.startswith("http")]
    if not targets:
        return []

    # Using a temporary file for JSON output to avoid shell piping issues with large data
    output_file = f"output_whatweb_{os.getpid()}.json"
    
    # We'll run them in small batches to avoid too long command lines
    results = []
    
    # WhatWeb can take multiple targets
    targets_str = " ".join(targets)
    cmd = f"whatweb --color=never --no-errors --log-json={output_file} {targets_str}"

    logger.info(f"[whatweb] Fingerprinting {len(targets)} targets...")

    try:
        proc = await asyncio.create_subprocess_shell(
            cmd,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
        )
        await asyncio.wait_for(proc.communicate(), timeout=timeout)

        if os.path.exists(output_file):
            with open(output_file, "r") as f:
                try:
                    results = json.load(f)
                except json.JSONDecodeError:
                    logger.error("[whatweb] Failed to parse JSON output")
            os.remove(output_file)

        logger.info(f"[whatweb] Finished fingerprinting. Data collected for {len(results)} hosts.")
        return results

    except Exception as e:
        logger.error(f"[whatweb] Error: {e}")
        if os.path.exists(output_file):
            os.remove(output_file)
        return []
