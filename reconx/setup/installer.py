"""
setup/installer.py — Auto-installer for missing tools.
Detects OS and installs via go install / apt / brew / winget.
"""

import platform
import subprocess
import shutil
import logging
from rich.console import Console
from setup.checker import REQUIRED_TOOLS, check_tool

logger = logging.getLogger("reconx.setup.installer")
console = Console()

# Tools installable via 'go install'
GO_TOOLS = {
    "subfinder": "github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest",
    "dnsx":      "github.com/projectdiscovery/dnsx/cmd/dnsx@latest",
    "httpx":     "github.com/projectdiscovery/httpx/cmd/httpx@latest",
    "nuclei":    "github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest",
    "amass":     "github.com/owasp-amass/amass/v4/...@master",
}


def _has_go() -> bool:
    return shutil.which("go") is not None


def _install_via_go(tool: str, pkg: str) -> bool:
    console.print(f"  [cyan]→ go install {pkg}[/]")
    try:
        with console.status(f"  [yellow]Downloading and compiling {tool}... (This may take a few minutes)[/]", spinner="dots"):
            result = subprocess.run(
                f"go install -v {pkg}",
                shell=True,
                capture_output=True,
                text=True,
            )
        if result.returncode == 0:
            console.print(f"  [green]✓ {tool} installed[/]")
            return True
        else:
            console.print(f"  [red]✗ Failed: {result.stderr.strip()[:200]}[/]")
            return False
    except Exception as e:
        console.print(f"  [red]✗ Error: {e}[/]")
        return False


def _install_nmap() -> bool:
    os_name = platform.system().lower()
    console.print(f"  [cyan]→ Installing nmap via system package manager...[/]")
    try:
        if os_name == "linux":
            cmd = "sudo apt-get install -y nmap"
        elif os_name == "darwin":
            cmd = "brew install nmap"
        elif os_name == "windows":
            cmd = "winget install -e --id Insecure.Nmap"
        else:
            console.print(f"  [yellow]⚠ Unsupported OS — install nmap manually: https://nmap.org[/]")
            return False

        with console.status(f"  [yellow]Installing nmap... Please wait[/]", spinner="dots"):
            result = subprocess.run(cmd, shell=True, capture_output=True, text=True)
            
        if result.returncode == 0:
            console.print("  [green]✓ nmap installed[/]")
            return True
        else:
            console.print(f"  [red]✗ nmap install failed. Manual install: https://nmap.org/download.html[/]")
            return False
    except Exception as e:
        console.print(f"  [red]✗ Error: {e}[/]")
        return False


def auto_install(missing: list[str]) -> dict[str, bool]:
    """
    Try to auto-install all missing tools.
    Returns {tool: success}.
    """
    results = {}

    if not _has_go():
        console.print("[red]❌ Go not found in PATH.[/]")
        console.print("[dim]Install Go from: https://go.dev/dl/ then re-run setup[/]")
        for t in missing:
            if t in GO_TOOLS:
                results[t] = False

    console.print(f"\n[bold cyan]Installing {len(missing)} missing tools...[/]\n")

    for tool in missing:
        console.print(f"[bold white]► {tool}[/]")

        if tool in GO_TOOLS and _has_go():
            results[tool] = _install_via_go(tool, GO_TOOLS[tool])
        elif tool == "nmap":
            results[tool] = _install_nmap()
        else:
            hint = REQUIRED_TOOLS.get(tool, {}).get("install_hint", "unknown")
            console.print(f"  [yellow]⚠ Cannot auto-install. Manual: {hint}[/]")
            results[tool] = False

        console.print()

    return results


def run_setup(auto: bool = False) -> bool:
    """
    Full setup flow: check → detect missing → optionally install → verify.
    Returns True if all critical tools are ready.
    """
    from setup.checker import check_all_tools, get_missing_tools

    console.print("\n[bold cyan]━━━ ReconX Setup ━━━[/]\n")
    check_all_tools(verbose=True)

    missing = get_missing_tools()

    if not missing:
        console.print("\n[bold green]✅ All tools ready — ReconX is good to go![/]")
        return True

    if not auto:
        console.print(f"\n[yellow]Run [bold]reconx setup --auto[/] to attempt auto-install[/]")
        return False

    install_results = auto_install(missing)

    # Verify
    console.print("[bold cyan]━━━ Verification ━━━[/]\n")
    all_ok = True
    for tool, success in install_results.items():
        if not success:
            info = REQUIRED_TOOLS.get(tool, {})
            if info.get("critical"):
                all_ok = False

    check_all_tools(verbose=True)
    return all_ok
