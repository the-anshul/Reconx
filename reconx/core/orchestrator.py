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
from adapters.katana import run_katana
from adapters.whatweb import run_whatweb
from models.asset import Asset, PortInfo, VulnInfo

logger = logging.getLogger("reconx.orchestrator")
console = Console()


def correlate(subdomains, dns_data, http_data, port_data, vuln_data, whatweb_data=None) -> list[Asset]:
    """Combine data from all tools into a list of Asset objects."""
    assets_dict: dict[str, Asset] = {}
    
    # Initialize assets from subdomains
    for sub in subdomains:
        assets_dict[sub] = Asset(domain=sub)

    # Merge DNS info
    for d in dns_data:
        domain = d.get("host")
        if domain in assets_dict:
            assets_dict[domain].ip = d.get("ip")
            assets_dict[domain].cnames = d.get("cnames", [])

    # Merge HTTP info
    for h in http_data:
        domain = h.get("input") or h.get("url", "").replace("http://", "").replace("https://", "").split("/")[0]
        if domain in assets_dict:
            assets_dict[domain].is_live = True
            assets_dict[domain].http_status = h.get("status_code")
            assets_dict[domain].http_url = h.get("url")
            assets_dict[domain].technologies.extend(h.get("tech", []))

    # Merge WhatWeb tech info (Enrichment)
    if whatweb_data:
        for w in whatweb_data:
            target = w.get("target", "")
            domain = target.replace("http://", "").replace("https://", "").split("/")[0]
            if domain in assets_dict:
                plugins = w.get("plugins", {})
                new_techs = list(plugins.keys())
                assets_dict[domain].technologies.extend(new_techs)
                assets_dict[domain].technologies = list(set(assets_dict[domain].technologies))

    # Merge Port info
    for ip, raw_ports in port_data.items():
        for asset in assets_dict.values():
            if asset.ip == ip:
                asset.ports = [
                    PortInfo(port=p["port"], service=p.get("service"), version=p.get("version"))
                    for p in raw_ports
                ]

    # Merge Vuln info
    for v in vuln_data:
        matched = v.get("matched_at", "")
        for asset in assets_dict.values():
            if asset.domain in matched or (asset.http_url and asset.http_url in matched):
                asset.vulns.append(VulnInfo(
                    name=v["name"],
                    severity=v.get("severity", "info"),
                    matched_at=v.get("matched_at")
                ))

    assets = list(assets_dict.values())
    assets.sort(key=lambda a: len(a.vulns), reverse=True)
    return assets


async def run_pipeline(domain: str, config: dict, resume: bool = False) -> list[Asset]:
    """Main pipeline execution."""
    output_dir = config.get("general", {}).get("output_dir", "output")
    state = StateManager(domain=domain, output_dir=output_dir)

    phases = ["recon", "dns", "http", "whatweb", "crawl", "ports", "vulns"]
    state.set_pending(phases)

    # Initialize all results to avoid NameError
    subdomains = []
    dns_data = []
    http_data = []
    http_urls = []
    whatweb_data = []
    crawled_urls = []
    port_data = {}
    vuln_data = []

    with Progress(
        SpinnerColumn(),
        TextColumn("[bold cyan]{task.description}"),
        BarColumn(),
        TimeElapsedColumn(),
        console=console,
    ) as progress:

        # 1. Recon
        if state.is_done("recon") and resume:
            subdomains = state.get_result("recon")
        else:
            task = progress.add_task("[bold green]Phase 1: Recon...", total=None)
            subdomains = await run_recon(domain, config)
            state.mark_done("recon", subdomains)
            progress.remove_task(task)
        console.print(f"  ✅ [green]Recon:[/] {len(subdomains)} subdomains found")

        if not subdomains:
            return []

        # 2. DNS
        if state.is_done("dns") and resume:
            dns_data = state.get_result("dns")
        else:
            task = progress.add_task("[bold green]Phase 2: DNS Resolution...", total=None)
            dns_data = await run_dns_enum(subdomains, config)
            state.mark_done("dns", dns_data)
            progress.remove_task(task)
        console.print(f"  ✅ [green]DNS:[/] {len(dns_data)} live hosts")

        # 3. HTTP
        live_hosts = [d["domain"] for d in dns_data]
        if state.is_done("http") and resume:
            http_data = state.get_result("http")
        else:
            task = progress.add_task("[bold green]Phase 3: HTTP Probing...", total=None)
            http_data = await run_http_enum(live_hosts, config)
            state.mark_done("http", http_data)
            progress.remove_task(task)
        console.print(f"  ✅ [green]HTTP:[/] {len(http_data)} web services detected")
        http_urls = [h["url"] for h in http_data if h.get("url")]

        # 4. WhatWeb
        if state.is_done("whatweb") and resume:
            whatweb_data = state.get_result("whatweb")
        elif http_urls:
            task = progress.add_task("[bold green]Phase 4: Fingerprinting...", total=None)
            whatweb_data = await run_whatweb(http_urls)
            state.mark_done("whatweb", whatweb_data)
            progress.remove_task(task)
            console.print(f"  ✅ [green]Fingerprint:[/] Info collected")

        # 5. Crawl
        if state.is_done("crawl") and resume:
            crawled_urls = state.get_result("crawl")
        elif http_urls:
            task = progress.add_task("[bold green]Phase 5: Crawling...", total=None)
            crawled_urls = await run_katana(http_urls)
            state.mark_done("crawl", crawled_urls)
            progress.remove_task(task)
            console.print(f"  ✅ [green]Crawl:[/] {len(crawled_urls)} endpoints")

        # 6. Ports
        if state.is_done("ports") and resume:
            port_data = state.get_result("ports")
        else:
            task = progress.add_task("[bold green]Phase 6: Port Scan...", total=None)
            unique_ips = list({d["ip"] for d in dns_data if d.get("ip")})
            port_data = await run_port_scan(unique_ips, config)
            state.mark_done("ports", port_data)
            progress.remove_task(task)
            console.print(f"  ✅ [green]Ports:[/] Done")

        # 7. Vulns
        if state.is_done("vulns") and resume:
            vuln_data = state.get_result("vulns")
        else:
            task = progress.add_task("[bold green]Phase 7: Vuln Scan...", total=None)
            scan_targets = list(set(http_urls + crawled_urls))
            vuln_data = await run_vuln_scan(scan_targets, config)
            state.mark_done("vulns", vuln_data)
            progress.remove_task(task)
            console.print(f"  ✅ [green]Vulns:[/] {len(vuln_data)} findings")

    console.print("\n[bold cyan]🔗 Correlating intelligence...[/]")
    assets = correlate(subdomains, dns_data, http_data, port_data, vuln_data, whatweb_data)
    return assets
