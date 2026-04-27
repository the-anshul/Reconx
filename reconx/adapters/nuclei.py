"""
adapters/nuclei.py — Vulnerability scanning adapter.
"""

import asyncio
import json
import logging

logger = logging.getLogger("reconx.adapters.nuclei")


async def run_nuclei(
    targets: list[str],
    severity: str = "low,medium,high,critical",
    templates: str = "",
    timeout: int = 300,
) -> list[dict]:
    """
    Run nuclei against HTTP targets.
    Returns list of normalized vuln dicts.
    """
    if not targets:
        return []

    input_data = "\n".join(targets)
    tmpl_flag = f"-t {templates}" if templates else ""
    cmd = f"nuclei -silent -json -severity {severity} {tmpl_flag}"

    logger.info(f"[nuclei] Scanning {len(targets)} targets with severity={severity}...")

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

        findings = []
        for line in stdout.decode().splitlines():
            line = line.strip()
            if not line:
                continue
            try:
                data = json.loads(line)
                findings.append({
                    "name": data.get("info", {}).get("name", "Unknown"),
                    "severity": data.get("info", {}).get("severity", "info"),
                    "template_id": data.get("template-id", ""),
                    "matched_at": data.get("matched-at", ""),
                    "description": data.get("info", {}).get("description", ""),
                    "tags": data.get("info", {}).get("tags", []),
                    "cvss_score": data.get("info", {}).get("classification", {}).get("cvss-score"),
                })
            except json.JSONDecodeError:
                continue

        logger.info(f"[nuclei] {len(findings)} vulnerabilities found")
        return findings

    except asyncio.TimeoutError:
        logger.error(f"[nuclei] Timed out after {timeout}s")
        return []
    except FileNotFoundError:
        logger.error("[nuclei] Not found in PATH. Run: reconx setup")
        return []
    except Exception as e:
        logger.error(f"[nuclei] Error: {e}")
        return []
