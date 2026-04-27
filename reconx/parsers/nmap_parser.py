"""
parsers/nmap_parser.py — Parse nmap XML output into PortInfo objects.
Used when reading saved nmap -oX output files.
"""

import xml.etree.ElementTree as ET
import logging
from models.asset import PortInfo

logger = logging.getLogger("reconx.parsers.nmap")


def parse_nmap_xml(xml_data: str) -> dict[str, list[PortInfo]]:
    """
    Parse nmap XML into {host_ip: [PortInfo]} dict.
    Handles multiple hosts in one scan.
    """
    results: dict[str, list[PortInfo]] = {}

    try:
        root = ET.fromstring(xml_data)
    except ET.ParseError as e:
        logger.error(f"[nmap_parser] XML parse error: {e}")
        return results

    for host_elem in root.findall("host"):
        # Get IP address
        addr_elem = host_elem.find("address[@addrtype='ipv4']")
        if addr_elem is None:
            continue
        ip = addr_elem.get("addr", "unknown")

        ports = []
        for port_elem in host_elem.findall(".//port"):
            state_elem = port_elem.find("state")
            if state_elem is None or state_elem.get("state") != "open":
                continue

            service_elem = port_elem.find("service")
            service_name = service_elem.get("name") if service_elem is not None else None
            product = service_elem.get("product", "") if service_elem is not None else ""
            version = service_elem.get("version", "") if service_elem is not None else ""
            full_version = f"{product} {version}".strip() or None

            ports.append(PortInfo(
                port=int(port_elem.get("portid", 0)),
                protocol=port_elem.get("protocol", "tcp"),
                service=service_name,
                version=full_version,
                state="open",
            ))

        results[ip] = ports
        logger.debug(f"[nmap_parser] {ip}: {len(ports)} open ports")

    logger.info(f"[nmap_parser] Parsed {len(results)} hosts")
    return results


def parse_nmap_file(filepath: str) -> dict[str, list[PortInfo]]:
    """Parse a saved nmap XML file."""
    try:
        with open(filepath) as f:
            return parse_nmap_xml(f.read())
    except FileNotFoundError:
        logger.error(f"[nmap_parser] File not found: {filepath}")
        return {}
