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
import shlex
import urllib.parse
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
from rich.table import Table
from rich import print as rprint

from core.banners import get_banner, BANNERS

console = Console()

# Banner logic is now moved to core/banners.py


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


def clean_domain(domain: str) -> str:
    """Clean user input to extract just the naked domain/hostname."""
    domain = domain.strip().lower()
    if domain.startswith("http://") or domain.startswith("https://"):
        domain = urllib.parse.urlparse(domain).netloc
    
    # Strip any paths or ports
    domain = domain.split('/')[0].split(':')[0]
    return domain


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

    domain = clean_domain(args.domain)

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
    is_interactive = getattr(args, 'interactive', False)
    needs_active = config.get("modules", {}).get("enum", True) or \
                   config.get("modules", {}).get("vuln", True)
    safety_cfg = config.get("safety", {})

    if needs_active and safety_cfg.get("confirm_active", True) and not is_interactive:
        if not confirm_active_scan(domain):
            console.print("[dim]Scan cancelled.[/]")
            sys.exit(0)

    if not is_interactive:
        banner_style = config.get("general", {}).get("banner_style", "standard")
        console.print(get_banner(banner_style))
    
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

    domain = clean_domain(args.domain)
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

    is_interactive = getattr(args, 'interactive', False)
    if not is_interactive:
        banner_style = config.get("general", {}).get("banner_style", "standard")
        console.print(get_banner(banner_style))
    
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
    domain = clean_domain(args.domain)
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

    is_interactive = getattr(args, 'interactive', False)
    if not is_interactive:
        banner_style = config.get("general", {}).get("banner_style", "standard")
        console.print(get_banner(banner_style))
    
    console.print(f"[bold cyan]📊 Generating report for:[/] [bold white]{domain}[/]\n")
    assets = correlate(subdomains, dns_data, http_data, port_data, vuln_data)
    generate_report(domain, assets, config)


# ── Argument parser ───────────────────────────────────────────────────────────

def cmd_banner(args):
    """reconx banner [--set style]"""
    config_path = args.config
    config = load_config(config_path)
    
    available_styles = list(BANNERS.keys())
    current_style = config.get("general", {}).get("banner_style", "standard")

    if args.set:
        style = args.set.lower()
        if style in BANNERS:
            new_style = style
        else:
            console.print(f"[red]❌ Style '{style}' not found.[/]")
            console.print(f"Available styles: {', '.join(available_styles)}")
            return
    else:
        # Cycle to the next style
        try:
            current_idx = available_styles.index(current_style)
            next_idx = (current_idx + 1) % len(available_styles)
        except ValueError:
            next_idx = 0
        new_style = available_styles[next_idx]

    # Save and show
    config["general"]["banner_style"] = new_style
    with open(config_path, "w") as f:
        yaml.dump(config, f)
    
    console.print(f"[green]🔄 Switched banner to: [bold]{new_style}[/][/]")
    console.print(get_banner(new_style))

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

    # ── banner ─────────────────────────────────────────────────────────────
    p_banner = sub.add_parser("banner", help="View or change the CLI banner style")
    p_banner.add_argument("--set", choices=BANNERS.keys(), help="Set a new default banner style")
    p_banner.add_argument("--config", default="config.yaml", help="Path to config.yaml")

    return parser


# ── Entry ─────────────────────────────────────────────────────────────────────

def main():
    # Add reconx dir to sys.path
    reconx_root = Path(__file__).parent
    if str(reconx_root) not in sys.path:
        sys.path.insert(0, str(reconx_root))

    parser = build_parser()

    # If no arguments, enter Version Selector
    if len(sys.argv) == 1:
        config = load_config()
        banner_style = config.get("general", {}).get("banner_style", "standard")
        clear_screen()
        console.print(get_banner(banner_style))
        
        console.print(Panel("[bold white]Select Interface Version[/]", style="blue"))
        console.print("[bold cyan]1.[/] [bold white]Interactive Shell Mode[/] (Classic 'reconx >' style)")
        console.print("[bold cyan]2.[/] [bold white]Interactive Menu Mode[/] (New guided list style)")
        
        choice = console.input("\n[bold yellow]Select Version [1 or 2]: [/]").strip()
        
        if choice == "1":
            run_interactive_shell()
        elif choice == "2":
            run_interactive_menu()
        else:
            console.print("[red]Invalid choice. Exiting.[/]")
        return

    # Normal CLI mode
    args = parser.parse_args()
    execute_command(args)

def clear_screen():
    os.system('cls' if os.name == 'nt' else 'clear')

def run_interactive_shell():
    config = load_config()
    banner_style = config.get("general", {}).get("banner_style", "standard")
    parser = build_parser()
    
    clear_screen()
    console.print(get_banner(banner_style))
    console.print("[bold green]Welcome to ReconX Interactive Shell (v1)![/]")
    console.print("[dim]Type 'help' for commands or 'exit' to quit.[/]\n")

    while True:
        try:
            cmd_line = console.input("[bold cyan]reconx > [/]").strip()
            if not cmd_line:
                continue
            if cmd_line.lower() in ["exit", "quit"]:
                break
            
            try:
                args = parser.parse_args(shlex.split(cmd_line))
                args.interactive = True 
            except SystemExit:
                continue

            execute_command(args)
        except KeyboardInterrupt:
            console.print("\n[yellow]Use 'exit' to quit.[/]")
        except Exception as e:
            console.print(f"[red]❌ Error: {e}[/]")
    
    console.print("[bold cyan]Goodbye![/]")

def run_interactive_menu():
    config = load_config()
    banner_style = config.get("general", {}).get("banner_style", "standard")
    
    while True:
        clear_screen()
        console.print(get_banner(banner_style))
        
        table = Table(title="[bold magenta]Main Menu[/]", box=None, show_header=False)
        table.add_column("Key", style="bold cyan")
        table.add_column("Operation", style="bold white")
        
        table.add_row("1", "🚀 Full Automated Scan (Recon → Enum → Vuln)")
        table.add_row("2", "🔍 Recon Only (Passive Discovery)")
        table.add_row("3", "🕷  Deep Crawling & Vuln Scan (Katana + Nuclei)")
        table.add_row("4", "📡 Port Scan & Service Detection (Nmap)")
        table.add_row("5", "📊 View Existing Reports")
        table.add_row("6", "🎨 Change Banner Style")
        table.add_row("7", "❌ Exit")
        
        console.print(table)
        console.print("\n[dim]Select an option [1-7][/]")
        
        choice = console.input("[bold yellow]reconx > [/]").strip()
        
        if choice == "7":
            console.print("[bold cyan]Goodbye![/]")
            break
        elif choice == "6":
            cmd_banner(argparse.Namespace(set=None, config="config.yaml"))
            input("\nPress Enter to continue...")
            continue
            
        # For scan options, ask for target
        if choice in ["1", "2", "3", "4"]:
            clear_screen()
            console.print(get_banner(banner_style))
            console.print(Panel(f"[bold white]Target Selection[/]", style="blue"))
            domain = console.input("[bold cyan]Enter Target Domain (e.g. example.com): [/]").strip()
            if not domain: continue
            
            # Show what will be run
            clear_screen()
            console.print(get_banner(banner_style))
            console.print(f"[bold cyan]🎯 Target:[/] [bold white]{domain}[/]\n")
            
            plan = Table(title="[bold yellow]Execution Plan[/]", box=None)
            plan.add_column("Step", style="bold green")
            plan.add_column("Description", style="dim")
            
            if choice == "1":
                plan.add_row("Recon", "Find subdomains using subfinder/amass/assetfinder")
                plan.add_row("DNS/HTTP", "Resolve IPs and probe for live web services")
                plan.add_row("Crawl", "Deep crawl hidden endpoints using Katana")
                plan.add_row("Fingerprint", "Advanced tech detection using WhatWeb")
                plan.add_row("Ports", "Identify open ports and versions using Nmap")
                plan.add_row("Vulns", "Automated vulnerability scan using Nuclei")
                cmd = f"scan -d {domain}"
            elif choice == "2":
                plan.add_row("Recon", "Passive subdomain discovery only")
                cmd = f"scan -d {domain} --quick"
            elif choice == "3":
                plan.add_row("Crawl", "Crawl endpoints and check for vulnerabilities")
                cmd = f"scan -d {domain} --no-recon" # Custom handling might be needed
            elif choice == "4":
                plan.add_row("Port Scan", "Detailed network service discovery")
                cmd = f"scan -d {domain} --no-vuln"

            console.print(plan)
            confirm = console.input("\n[bold green]Start scan? (y/n): [/]").strip().lower()
            if confirm == 'y':
                parser = build_parser()
                args = parser.parse_args(shlex.split(cmd))
                args.interactive = True
                execute_command(args)
                input("\nScan complete. Press Enter to return to menu...")
        
        elif choice == "5":
            domain = console.input("[bold cyan]Enter domain to view report: [/]").strip()
            if domain:
                args = argparse.Namespace(command="report", domain=domain, config="config.yaml")
                cmd_report(args)
                input("\nPress Enter to return to menu...")

def execute_command(args):
    dispatch = {
        "setup":  cmd_setup,
        "scan":   cmd_scan,
        "resume": cmd_resume,
        "report": cmd_report,
        "banner": cmd_banner,
    }

    handler = dispatch.get(args.command)
    if handler:
        try:
            handler(args)
        except KeyboardInterrupt:
            console.print("\n[yellow]⚠ Interrupted. State saved if applicable.[/]")
        except Exception as e:
            console.print(f"[red]❌ Execution failed: {e}[/]")

if __name__ == "__main__":
    main()
