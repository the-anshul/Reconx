"""
setup/checker.py — Tool availability checker.
Checks if all required tools are installed and in PATH.
"""

import os
import shutil
import subprocess
import logging
from rich.console import Console
from rich.table import Table

logger = logging.getLogger("reconx.setup.checker")
console = Console()

REQUIRED_TOOLS = {
    "subfinder": {
        "version_flag": "-version",
        "install_hint": "go install -v github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest",
        "critical": True,
    },
    "dnsx": {
        "version_flag": "-version",
        "install_hint": "go install -v github.com/projectdiscovery/dnsx/cmd/dnsx@latest",
        "critical": True,
    },
    "httpx-toolkit": {
        "version_flag": "-version",
        "install_hint": "go install -v github.com/projectdiscovery/httpx/cmd/httpx@latest",
        "critical": True,
    },
    "nuclei": {
        "version_flag": "-version",
        "install_hint": "go install -v github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest",
        "critical": True,
    },
    "katana": {
        "version_flag": "-version",
        "install_hint": "go install github.com/projectdiscovery/katana/cmd/katana@latest",
        "critical": False,
    },
    "assetfinder": {
        "version_flag": "-version",
        "install_hint": "go install github.com/tomnomnom/assetfinder@latest",
        "critical": False,
    },
    "nmap": {
        "version_flag": "--version",
        "install_hint": "https://nmap.org/download.html",
        "critical": False,
    },
    "amass": {
        "version_flag": "-version",
        "install_hint": "go install -v github.com/owasp-amass/amass/v4/...@master",
        "critical": False,
    },
}


def check_tool(name: str, version_flag: str) -> tuple[bool, str]:
    """Check if a tool is in PATH and get its version."""
    path = shutil.which(name)
    
    # Fallback for Go binaries if not in PATH
    if not path:
        go_path = os.path.expanduser(f"~/go/bin/{name}")
        if os.path.exists(go_path):
            path = go_path
        else:
            return False, "NOT FOUND"

    try:
        result = subprocess.run(
            [path, version_flag],
            capture_output=True,
            text=True,
            timeout=5,
        )
        version_line = (result.stdout + result.stderr).strip().splitlines()
        version = version_line[0][:50] if version_line else "unknown version"
        return True, version
    except Exception:
        return True, "found (version check failed)"


def check_all_tools(verbose: bool = True) -> dict[str, bool]:
    """
    Check all required tools.
    Returns {tool_name: is_available}.
    """
    results = {}

    if verbose:
        table = Table(title="[bold cyan]ReconX Tool Status[/]", show_lines=True)
        table.add_column("Tool", style="bold white")
        table.add_column("Status", justify="center")
        table.add_column("Version / Note", style="dim")
        table.add_column("Required", justify="center")

    for tool, info in REQUIRED_TOOLS.items():
        found, detail = check_tool(tool, info["version_flag"])
        results[tool] = found

        if verbose:
            status = "[bold green]✓ OK[/]" if found else "[bold red]✗ MISSING[/]"
            critical = "[red]YES[/]" if info["critical"] else "[yellow]optional[/]"
            table.add_row(tool, status, detail, critical)

    if verbose:
        console.print(table)

        missing_critical = [
            t for t, info in REQUIRED_TOOLS.items()
            if not results[t] and info["critical"]
        ]
        missing_optional = [
            t for t, info in REQUIRED_TOOLS.items()
            if not results[t] and not info["critical"]
        ]

        if missing_critical:
            console.print(f"\n[bold red]❌ Critical tools missing:[/] {', '.join(missing_critical)}")
            console.print("[dim]Run: [bold]reconx setup --auto[/] to install[/]")
        if missing_optional:
            console.print(f"[yellow]⚠ Optional tools missing:[/] {', '.join(missing_optional)}")
        if not missing_critical and not missing_optional:
            console.print("\n[bold green]✅ All tools ready![/]")

    return results


def get_missing_tools() -> list[str]:
    results = check_all_tools(verbose=False)
    return [t for t, ok in results.items() if not ok]
