"""
core/orchestrator.py — The heart of ReconX.
Runs the full pipeline, manages state, and coordinates all modules.
"""

import asyncio
import logging
from rich.console import Console
from rich.progress import Progress, SpinnerColumn, TextColumn, BarColumn, TimeElapsedColumn
from rich.panel import Panel

from core.state_manager import StateManager
from modules.recon import run_recon
from modules.enum import run_dns_enum, run_http_enum
from modules.vuln import run_port_scan, run_vuln_scan
from models.asset import Asset, PortInfo, VulnInfo

logger = logging.getLogger("reconx.orchestrator")
console = Console()


def correlate(
    subdomains: list[str],
    dns_data: list[dict],
    http_data: list[dict],
    port_data: dict[str, list[dict]],
    vuln_data: list[dict],
) -> list[Asset]:
    """
    Intelligence layer — correlates all data into normalized Asset objects.
    This is where raw data becomes actionable intelligence.
    """
    # Build lookup maps
    dns_map = {d["domain"]: d for d in dns_data}
    http_map = {h["domain"]: h for h in http_data}
    # Also index by URL host for port mapping
    http_url_map = {h["url"]: h for h in http_data}

    assets = []

    for sub in subdomains:
        dns_info = dns_map.get(sub, {})
        http_info = http_map.get(sub, {})

        # Get IP — try DNS first
        ip = dns_info.get("ip")

        # Get ports — match by IP or domain
        raw_ports = port_data.get(ip, []) or port_data.get(sub, [])
        ports = [
            PortInfo(
                port=p["port"],
                protocol=p.get("protocol", "tcp"),
                service=p.get("service"),
                version=p.get("version"),
                state=p.get("state", "open"),
            )
            for p in raw_ports
        ]

        # Get vulns — match by URL or domain
        url = http_info.get("url", "")
        matched_vulns = [
            v for v in vuln_data
            if sub in v.get("matched_at", "") or url in v.get("matched_at", "")
        ]
        vulns = [
            VulnInfo(
                name=v["name"],
                severity=v.get("severity", "info"),
                template_id=v.get("template_id"),
                description=v.get("description"),
                matched_at=v.get("matched_at"),
                cvss_score=v.get("cvss_score"),
                tags=v.get("tags", []),
            )
            for v in matched_vulns
        ]

        asset = Asset(
            domain=sub,
            ip=ip,
            is_live=bool(dns_info),
            http_status=http_info.get("status"),
            http_url=url,
            technologies=http_info.get("technologies", []),
            cnames=dns_info.get("cnames", []),
            ports=ports,
            vulns=vulns,
        )
        assets.append(asset)

    # Sort by vuln count descending (most interesting first)
    assets.sort(key=lambda a: len(a.vulns), reverse=True)
    return assets


async def run_pipeline(domain: str, config: dict, resume: bool = False) -> list[Asset]:
    """
    Main pipeline: recon → dns → http → ports → vulns → correlate.
    Supports resumption via StateManager checkpoints.
    """
    output_dir = config.get("general", {}).get("output_dir", "output")
    state = StateManager(domain=domain, output_dir=output_dir)

    phases = ["recon", "dns", "http", "ports", "vulns"]
    state.set_pending(phases)

    with Progress(
        SpinnerColumn(),
        TextColumn("[bold cyan]{task.description}"),
        BarColumn(),
        TimeElapsedColumn(),
        console=console,
    ) as progress:

        # ── PHASE 1: Recon ──────────────────────────────────────────────────
        if state.is_done("recon") and resume:
            subdomains = state.get_result("recon")
            console.print(f"  [dim]↩ Recon: loaded {len(subdomains)} subs from state[/]")
        else:
            task = progress.add_task("[bold green]Phase 1: Passive Recon...", total=None)
            subdomains = await run_recon(domain, config)
            state.mark_done("recon", subdomains)
            progress.remove_task(task)

        console.print(f"  ✅ [green]Recon:[/] {len(subdomains)} subdomains found")

        if not subdomains:
            console.print("[yellow]⚠ No subdomains found. Exiting pipeline.[/]")
            return []

        # ── PHASE 2: DNS ────────────────────────────────────────────────────
        if state.is_done("dns") and resume:
            dns_data = state.get_result("dns")
            console.print(f"  [dim]↩ DNS: loaded {len(dns_data)} live hosts from state[/]")
        else:
            task = progress.add_task("[bold green]Phase 2: DNS Resolution...", total=None)
            dns_data = await run_dns_enum(subdomains, config)
            state.mark_done("dns", dns_data)
            progress.remove_task(task)

        console.print(f"  ✅ [green]DNS:[/] {len(dns_data)} live hosts")

        # ── PHASE 3: HTTP ───────────────────────────────────────────────────
        live_hosts = [d["domain"] for d in dns_data]

        if state.is_done("http") and resume:
            http_data = state.get_result("http")
            console.print(f"  [dim]↩ HTTP: loaded {len(http_data)} services from state[/]")
        else:
            task = progress.add_task("[bold green]Phase 3: HTTP Probing...", total=None)
            http_data = await run_http_enum(live_hosts, config)
            state.mark_done("http", http_data)
            progress.remove_task(task)

        console.print(f"  ✅ [green]HTTP:[/] {len(http_data)} web services detected")
        http_urls = [h["url"] for h in http_data if h.get("url")]

        # ── PHASE 4: Port Scan ──────────────────────────────────────────────
        port_data: dict[str, list] = {}
        if config.get("modules", {}).get("enum", True):
            if state.is_done("ports") and resume:
                port_data = state.get_result("ports")
                console.print(f"  [dim]↩ Ports: loaded from state[/]")
            else:
                task = progress.add_task("[bold green]Phase 4: Port Scanning...", total=None)
                # Scan unique IPs to avoid duplicate nmap runs
                unique_ips = list({d["ip"] for d in dns_data if d.get("ip")})
                port_data = await run_port_scan(unique_ips, config)
                state.mark_done("ports", port_data)
                progress.remove_task(task)

            total_ports = sum(len(v) for v in port_data.values())
            console.print(f"  ✅ [green]Ports:[/] {total_ports} open ports found")

        # ── PHASE 5: Vuln Scan ──────────────────────────────────────────────
        vuln_data: list[dict] = []
        if config.get("modules", {}).get("vuln", True):
            if state.is_done("vulns") and resume:
                vuln_data = state.get_result("vulns")
                console.print(f"  [dim]↩ Vulns: loaded {len(vuln_data)} findings from state[/]")
            else:
                task = progress.add_task("[bold green]Phase 5: Vulnerability Scan...", total=None)
                vuln_data = await run_vuln_scan(http_urls, config)
                state.mark_done("vulns", vuln_data)
                progress.remove_task(task)

            console.print(f"  ✅ [green]Vulns:[/] {len(vuln_data)} findings")

    # ── CORRELATION ─────────────────────────────────────────────────────────
    console.print("\n[bold cyan]🔗 Correlating intelligence...[/]")
    assets = correlate(subdomains, dns_data, http_data, port_data, vuln_data)
    console.print(f"  ✅ [green]Assets built:[/] {len(assets)} total\n")

    return assets
