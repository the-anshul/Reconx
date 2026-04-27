"""
parsers/nuclei_parser.py — Parse nuclei JSON output into VulnInfo objects.
Used when reading saved nuclei output files (not live stream).
"""

import json
import logging
from models.asset import VulnInfo

logger = logging.getLogger("reconx.parsers.nuclei")


def parse_nuclei_json(raw_output: str) -> list[VulnInfo]:
    """
    Parse nuclei -json output into list of VulnInfo models.
    Handles malformed lines gracefully.
    """
    findings = []

    for line in raw_output.splitlines():
        line = line.strip()
        if not line:
            continue
        try:
            data = json.loads(line)
            info = data.get("info", {})
            findings.append(VulnInfo(
                name=info.get("name", "Unknown"),
                severity=info.get("severity", "info"),
                template_id=data.get("template-id", ""),
                description=info.get("description", ""),
                matched_at=data.get("matched-at", ""),
                cvss_score=info.get("classification", {}).get("cvss-score"),
                tags=info.get("tags", []) if isinstance(info.get("tags"), list) else [],
            ))
        except (json.JSONDecodeError, Exception) as e:
            logger.debug(f"[nuclei_parser] Skipping line: {e}")

    logger.info(f"[nuclei_parser] Parsed {len(findings)} findings")
    return findings


def parse_nuclei_file(filepath: str) -> list[VulnInfo]:
    """Parse a nuclei output file."""
    try:
        with open(filepath) as f:
            return parse_nuclei_json(f.read())
    except FileNotFoundError:
        logger.error(f"[nuclei_parser] File not found: {filepath}")
        return []
