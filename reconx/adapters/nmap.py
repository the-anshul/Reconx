"""
adapters/nmap.py — Port scanning adapter.
"""

import asyncio
import logging
import xml.etree.ElementTree as ET

logger = logging.getLogger("reconx.adapters.nmap")


async def run_nmap(target: str, top_ports: int = 1000, timeout: int = 300) -> list[dict]:
    """
    Run nmap port scan on a target host.
    Returns list of open port dicts: {port, protocol, service, version, state}.
    """
    cmd = f"nmap -sV -T4 --open --top-ports {top_ports} -oX - {target}"
    logger.info(f"[nmap] Scanning {target}...")

    try:
        proc = await asyncio.create_subprocess_shell(
            cmd,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
        )
        stdout, stderr = await asyncio.wait_for(proc.communicate(), timeout=timeout)

        xml_output = stdout.decode()
        return _parse_nmap_xml(xml_output)

    except asyncio.TimeoutError:
        logger.error(f"[nmap] Timed out after {timeout}s for {target}")
        return []
    except FileNotFoundError:
        logger.error("[nmap] Not found. Install nmap and add to PATH")
        return []
    except Exception as e:
        logger.error(f"[nmap] Error scanning {target}: {e}")
        return []


def _parse_nmap_xml(xml_data: str) -> list[dict]:
    """Parse nmap XML output into normalized port list."""
    ports = []
    try:
        root = ET.fromstring(xml_data)
        for host in root.findall("host"):
            for port_elem in host.findall(".//port"):
                state = port_elem.find("state")
                service = port_elem.find("service")
                if state is not None and state.get("state") == "open":
                    ports.append({
                        "port": int(port_elem.get("portid", 0)),
                        "protocol": port_elem.get("protocol", "tcp"),
                        "service": service.get("name") if service is not None else None,
                        "version": (
                            f"{service.get('product', '')} {service.get('version', '')}".strip()
                            if service is not None else None
                        ),
                        "state": "open",
                    })
    except ET.ParseError as e:
        logger.warning(f"[nmap] XML parse error: {e}")
    return ports
