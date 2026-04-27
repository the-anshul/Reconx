"""
main.py -- ReconX CLI entry point.
Commands: setup, scan, resume, report

Usage:
    python main.py setup
    python main.py setup --auto
    python main.py scan -d example.com
    python main.py scan -d example.com --quick
    python main.py resume -d example.com
    python main.py report -d example.com
"""

import argparse
import asyncio
import json
import logging
import os
from pathlib import Path

import sys
import io

# Force UTF-8 output on Windows (fixes cp1252 UnicodeEncodeError)
if sys.stdout.encoding != "utf-8":
    sys.stdout = io.TextIOWrapper(sys.stdout.buffer, encoding="utf-8", errors="replace")
if sys.stderr.encoding != "utf-8":
    sys.stderr = io.TextIOWrapper(sys.stderr.buffer, encoding="utf-8", errors="replace")

import yaml
from rich.console import Console
from rich.panel import Panel
from rich import print as rprint

console = Console()

# ── Banner ────────────────────────────────────────────────────────────────────

BANNER = """
[bold cyan]
 ██████╗ ███████╗ ██████╗ ██████╗ ███╗   ██╗██╗  ██╗
 ██╔══██╗██╔════╝██╔════╝██╔═══██╗████╗  ██║╚██╗██╔╝
 ██████╔╝█████╗  ██║     ██║   ██║██╔██╗ ██║ ╚███╔╝ 
 ██╔══██╗██╔══╝  ██║     ██║   ██║██║╚██╗██║ ██╔██╗ 
 ██║  ██║███████╗╚██████╗╚██████╔╝██║ ╚████║██╔╝ ██╗
 ╚═╝  ╚═╝╚══════╝ ╚═════╝ ╚═════╝ ╚═╝  ╚═══╝╚═╝  ╚═╝
[/bold cyan]
[dim]  Recon + Enumeration + Vuln Automation Framework[/dim]
[cyan]  ─────────────────────────────────────────────────[/cyan]
"""


# ── Config loader ─────────────────────────────────────────────────────────────

def load_config(config_path: str = "config.yaml") -> dict:
    config_file = Path(config_path)
    if not config_file.exists():
        # Look next to main.py
        config_file = Path(__file__).parent / "config.yaml"
    if not config_file.exists():
        console.print("[red]❌ config.yaml not found[/]")
        sys.exit(1)
    with open(config_file) as f:
        return yaml.safe_load(f)


# ── Logging setup ─────────────────────────────────────────────────────────────

def setup_logging(level: str = "INFO"):
    numeric = getattr(logging, level.upper(), logging.INFO)
    logging.basicConfig(
        level=numeric,
        format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
        datefmt="%H:%M:%S",
        handlers=[logging.StreamHandler(sys.stderr)],
    )


# ── Safety helpers ────────────────────────────────────────────────────────────

def confirm_active_scan(domain: str) -> bool:
    console.print(
        f"\n[bold yellow]⚠  Active scan (nmap + nuclei) will be run against:[/] "
        f"[bold white]{domain}[/]"
    )
    console.print("[dim]Only proceed if you have explicit permission to scan this target.[/]")
    answer = console.input("[bold]Proceed? [y/N]: [/]").strip().lower()
    return answer == "y"


def validate_scope(domain: str) -> bool:
    """Basic scope validation — no IPs, no wildcards in CLI."""
    if domain.startswith("*"):
        console.print("[red]❌ Wildcard domains not supported as direct input[/]")
        return False
    if domain.replace(".", "").isdigit():
        console.print("[yellow]⚠ IP addresses are supported but ensure you have authorization[/]")
    return True


# ── Command handlers ──────────────────────────────────────────────────────────

def cmd_setup(args):
    """reconx setup [--auto]"""
    from setup.installer import run_setup
    run_setup(auto=args.auto)


def cmd_scan(args):
    """reconx scan -d domain [--quick] [--no-vuln] [--config path]"""
    config = load_config(args.config)

    log_level = config.get("general", {}).get("log_level", "INFO")
    setup_logging(log_level)

    domain = args.domain.strip().lower()

    if not validate_scope(domain):
        sys.exit(1)

    # Quick mode — disable slow modules
    if args.quick:
        config["modules"]["enum"]  = False
        config["modules"]["vuln"]  = False
        console.print("[yellow]⚡ Quick mode: nmap + nuclei disabled[/]")

    if args.no_vuln:
        config["modules"]["vuln"] = False

    # Safety: confirm active scan
    needs_active = config.get("modules", {}).get("enum", True) or \
                   config.get("modules", {}).get("vuln", True)
    safety_cfg = config.get("safety", {})
    if needs_active and safety_cfg.get("confirm_active", True):
        if not confirm_active_scan(domain):
            console.print("[dim]Scan cancelled.[/]")
            sys.exit(0)

    console.print(BANNER)
    console.print(f"[bold cyan]🎯 Target:[/] [bold white]{domain}[/]\n")

    # Run pipeline
    from core.orchestrator import run_pipeline
    from reporting.reporter import generate_report

    assets = asyncio.run(run_pipeline(domain, config, resume=False))

    if not assets:
        console.print("[yellow]No assets discovered.[/]")
        sys.exit(0)

    generate_report(domain, assets, config)


def cmd_resume(args):
    """reconx resume -d domain [--config path]"""
    config = load_config(args.config)
    setup_logging(config.get("general", {}).get("log_level", "INFO"))

    domain = args.domain.strip().lower()
    output_dir = config.get("general", {}).get("output_dir", "output")
    safe_domain = domain.replace(".", "_")
    state_file = Path(output_dir) / f"{safe_domain}_state.json"

    if not state_file.exists():
        console.print(f"[red]❌ No saved state found for {domain}[/]")
        console.print(f"[dim]Expected: {state_file}[/]")
        sys.exit(1)

    with open(state_file) as f:
        state = json.load(f)

    completed = state.get("completed", [])
    pending   = [p for p in ["recon","dns","http","ports","vulns"] if p not in completed]

    console.print(BANNER)
    console.print(f"[bold cyan]↩ Resuming scan for:[/] [bold white]{domain}[/]")
    console.print(f"  ✅ Completed: {', '.join(completed) or 'none'}")
    console.print(f"  ⏳ Pending:   {', '.join(pending) or 'none'}\n")

    from core.orchestrator import run_pipeline
    from reporting.reporter import generate_report

    assets = asyncio.run(run_pipeline(domain, config, resume=True))

    if assets:
        generate_report(domain, assets, config)


def cmd_report(args):
    """
    reconx report -d domain
    Reads saved state and regenerates the report without re-scanning.
    """
    config = load_config(args.config)
    domain = args.domain.strip().lower()
    output_dir = config.get("general", {}).get("output_dir", "output")
    safe_domain = domain.replace(".", "_")
    state_file = Path(output_dir) / f"{safe_domain}_state.json"

    if not state_file.exists():
        console.print(f"[red]❌ No state file found for [bold]{domain}[/]. Run a scan first.[/]")
        sys.exit(1)

    with open(state_file) as f:
        state = json.load(f)

    results = state.get("results", {})

    # Rebuild assets from saved state via correlation
    from core.orchestrator import correlate
    from reporting.reporter import generate_report

    subdomains = results.get("recon", [])
    dns_data   = results.get("dns", [])
    http_data  = results.get("http", [])
    port_data  = results.get("ports", {})
    vuln_data  = results.get("vulns", [])

    if not subdomains:
        console.print("[yellow]⚠ No recon data in state — run a full scan first[/]")
        sys.exit(1)

    console.print(BANNER)
    console.print(f"[bold cyan]📊 Generating report for:[/] [bold white]{domain}[/]\n")
    assets = correlate(subdomains, dns_data, http_data, port_data, vuln_data)
    generate_report(domain, assets, config)


# ── Argument parser ───────────────────────────────────────────────────────────

def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="reconx",
        description="ReconX — Recon + Enumeration + Vuln Automation Framework",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  python main.py setup --auto
  python main.py scan -d example.com
  python main.py scan -d example.com --quick
  python main.py resume -d example.com
  python main.py report -d example.com
        """,
    )

    sub = parser.add_subparsers(dest="command", required=True)

    # ── setup ──────────────────────────────────────────────────────────────
    p_setup = sub.add_parser("setup", help="Check and install required tools")
    p_setup.add_argument(
        "--auto", action="store_true",
        help="Auto-install missing tools via go install / apt / brew"
    )

    # ── scan ───────────────────────────────────────────────────────────────
    p_scan = sub.add_parser("scan", help="Run full recon → enum → vuln pipeline")
    p_scan.add_argument("-d", "--domain", required=True, help="Target domain")
    p_scan.add_argument("--quick",   action="store_true", help="Skip nmap + nuclei (fast mode)")
    p_scan.add_argument("--no-vuln", action="store_true", help="Skip nuclei vuln scan")
    p_scan.add_argument("--config",  default="config.yaml", help="Path to config.yaml")

    # ── resume ─────────────────────────────────────────────────────────────
    p_resume = sub.add_parser("resume", help="Resume interrupted scan from checkpoint")
    p_resume.add_argument("-d", "--domain", required=True, help="Target domain to resume")
    p_resume.add_argument("--config", default="config.yaml", help="Path to config.yaml")

    # ── report ─────────────────────────────────────────────────────────────
    p_report = sub.add_parser("report", help="Regenerate report from saved scan state")
    p_report.add_argument("-d", "--domain", required=True, help="Target domain")
    p_report.add_argument("--config", default="config.yaml", help="Path to config.yaml")

    return parser


# ── Entry ─────────────────────────────────────────────────────────────────────

def main():
    # Add reconx dir to sys.path so imports work from any working directory
    reconx_root = Path(__file__).parent
    if str(reconx_root) not in sys.path:
        sys.path.insert(0, str(reconx_root))

    parser = build_parser()
    args = parser.parse_args()

    dispatch = {
        "setup":  cmd_setup,
        "scan":   cmd_scan,
        "resume": cmd_resume,
        "report": cmd_report,
    }

    handler = dispatch.get(args.command)
    if handler:
        try:
            handler(args)
        except KeyboardInterrupt:
            console.print("\n[yellow]⚠ Interrupted by user. State saved — use 'reconx resume' to continue.[/]")
            sys.exit(0)
    else:
        parser.print_help()


if __name__ == "__main__":
    main()
