"""
reporting/reporter.py — CLI output + JSON file reporting.
Rich tables for terminal, JSON for machine consumption.
"""

import json
import logging
from pathlib import Path
from datetime import datetime

from rich.console import Console
from rich.table import Table
from rich.panel import Panel
from rich.text import Text
from rich import box

from models.asset import Asset

logger = logging.getLogger("reconx.reporter")
console = Console()

SEVERITY_COLOR = {
    "critical": "bold red",
    "high":     "red",
    "medium":   "yellow",
    "low":      "cyan",
    "info":     "dim white",
}


def print_summary(domain: str, assets: list[Asset]):
    """Print rich CLI summary report."""

    live_assets   = [a for a in assets if a.is_live]
    total_ports   = sum(len(a.ports) for a in assets)
    total_vulns   = sum(len(a.vulns) for a in assets)
    critical_count = sum(1 for a in assets for v in a.vulns if v.severity == "critical")
    high_count     = sum(1 for a in assets for v in a.vulns if v.severity == "high")

    # ── Summary Panel ─────────────────────────────────────────────────────
    summary = (
        f"[bold white]Target:[/]       {domain}\n"
        f"[bold white]Subdomains:[/]   {len(assets)}\n"
        f"[bold white]Live Hosts:[/]   {len(live_assets)}\n"
        f"[bold white]Open Ports:[/]   {total_ports}\n"
        f"[bold white]Vulnerabilities:[/] {total_vulns}  "
        f"([bold red]{critical_count} critical[/] / [red]{high_count} high[/])"
    )
    console.print(Panel(summary, title="[bold cyan]📊 ReconX Report[/]", border_style="cyan"))

    # ── Assets Table ──────────────────────────────────────────────────────
    table = Table(
        title="[bold white]Asset Overview[/]",
        box=box.ROUNDED,
        show_lines=True,
        header_style="bold cyan",
    )
    table.add_column("Domain",      style="bold white",  no_wrap=True)
    table.add_column("IP",          style="dim")
    table.add_column("HTTP",        justify="center")
    table.add_column("Ports",       justify="center")
    table.add_column("Tech",        style="dim",         max_width=30)
    table.add_column("Vulns",       justify="center")
    table.add_column("Severity",    justify="center")

    for asset in assets:
        status_str = (
            f"[green]{asset.http_status}[/]" if asset.http_status and asset.http_status < 400
            else f"[red]{asset.http_status}[/]" if asset.http_status
            else "[dim]-[/]"
        )
        ports_str = ", ".join(str(p.port) for p in asset.ports[:5])
        if len(asset.ports) > 5:
            ports_str += f" (+{len(asset.ports)-5})"

        tech_str = ", ".join(asset.technologies[:3]) if asset.technologies else "-"

        vuln_count = len(asset.vulns)
        vuln_str   = str(vuln_count) if vuln_count else "[dim]-[/]"

        # Worst severity
        sev_order = ["critical", "high", "medium", "low", "info"]
        worst = next(
            (s for s in sev_order if any(v.severity == s for v in asset.vulns)), None
        )
        sev_str = (
            f"[{SEVERITY_COLOR[worst]}]{worst.upper()}[/]" if worst else "[dim]-[/]"
        )

        table.add_row(
            asset.domain,
            asset.ip or "-",
            status_str,
            ports_str or "-",
            tech_str,
            vuln_str,
            sev_str,
        )

    console.print(table)

    # ── Vulnerability Detail ──────────────────────────────────────────────
    vuln_assets = [a for a in assets if a.vulns]
    if vuln_assets:
        console.print("\n[bold red]🔴 Vulnerability Details[/]")
        for asset in vuln_assets:
            for v in asset.vulns:
                color = SEVERITY_COLOR.get(v.severity, "white")
                console.print(
                    f"  [{color}][{v.severity.upper()}][/] "
                    f"[bold]{v.name}[/] → {asset.domain}"
                    + (f" ({v.matched_at})" if v.matched_at else "")
                )


def save_json_report(domain: str, assets: list[Asset], output_dir: str = "output") -> str:
    """Save full JSON report to output directory."""
    out = Path(output_dir)
    out.mkdir(parents=True, exist_ok=True)

    timestamp = datetime.utcnow().strftime("%Y%m%d_%H%M%S")
    safe_domain = domain.replace(".", "_")
    filename = out / f"reconx_{safe_domain}_{timestamp}.json"

    report = {
        "meta": {
            "domain": domain,
            "generated_at": datetime.utcnow().isoformat(),
            "total_assets": len(assets),
            "live_assets": sum(1 for a in assets if a.is_live),
            "total_vulns": sum(len(a.vulns) for a in assets),
        },
        "assets": [a.model_dump() for a in assets],
    }

    with open(filename, "w") as f:
        json.dump(report, f, indent=2, default=str)

    console.print(f"\n[bold green]💾 JSON report saved:[/] {filename}")
    return str(filename)


def generate_report(domain: str, assets: list[Asset], config: dict) -> str:
    """Main reporting entry point — prints CLI + asks to save files."""
    print_summary(domain, assets)

    output_dir = config.get("general", {}).get("output_dir", "output")
    formats = config.get("reporting", {}).get("formats", ["json"])

    saved_path = ""
    if "json" in formats:
        console.print("\n[bold cyan]Save report? (y/n): [/]", end="")
        choice = input().strip().lower()
        if choice == 'y':
            saved_path = save_json_report(domain, assets, output_dir)
        else:
            console.print("[dim]Skipped.[/]")

    return saved_path
