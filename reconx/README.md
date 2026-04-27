# ReconX — Recon + Enumeration + Vuln Automation Framework

```
 ██████╗ ███████╗ ██████╗ ██████╗ ███╗   ██╗██╗  ██╗
 ██╔══██╗██╔════╝██╔════╝██╔═══██╗████╗  ██║╚██╗██╔╝
 ██████╔╝█████╗  ██║     ██║   ██║██╔██╗ ██║ ╚███╔╝
 ██╔══██╗██╔══╝  ██║     ██║   ██║██║╚██╗██║ ██╔██╗
 ██║  ██║███████╗╚██████╗╚██████╔╝██║ ╚████║██╔╝ ██╗
 ╚═╝  ╚═╝╚══════╝ ╚═════╝ ╚═════╝ ╚═╝  ╚═══╝╚═╝  ╚═╝
```

> Modular · Resumable · Parallel · Normalized Output · Actionable Reports

---

## 📐 Architecture

```
reconx/
├── core/
│   ├── orchestrator.py   ← Pipeline coordinator (heart)
│   ├── scheduler.py      ← Async concurrency helpers
│   └── state_manager.py  ← Resume / checkpoint system
├── modules/
│   ├── recon.py          ← Subfinder + Amass (passive)
│   ├── enum.py           ← dnsx (DNS) + httpx (HTTP)
│   └── vuln.py           ← Nmap (ports) + Nuclei (vulns)
├── adapters/
│   ├── subfinder.py      ← Isolated tool adapter
│   ├── amass.py
│   ├── dnsx.py
│   ├── httpx.py
│   ├── nmap.py
│   └── nuclei.py
├── parsers/
│   ├── nuclei_parser.py  ← Nuclei JSON → VulnInfo
│   └── nmap_parser.py    ← Nmap XML → PortInfo
├── models/
│   └── asset.py          ← Pydantic schema (Asset, PortInfo, VulnInfo)
├── setup/
│   ├── checker.py        ← Tool availability check
│   └── installer.py      ← Auto-install via go/apt/brew/winget
├── reporting/
│   └── reporter.py       ← Rich CLI tables + JSON file output
├── config.yaml           ← Master config
└── main.py               ← CLI entry point
```

---

## ⚡ Pipeline Flow

```
Domain
  │
  ▼
[Phase 1] Passive Recon    → subfinder + amass       → subdomains[]
  │
  ▼
[Phase 2] DNS Resolution   → dnsx                    → live hosts + IPs
  │
  ▼
[Phase 3] HTTP Probing     → httpx                   → URLs, status, tech
  │
  ▼
[Phase 4] Port Scan        → nmap (parallel per IP)  → open ports
  │
  ▼
[Phase 5] Vuln Scan        → nuclei                  → findings[]
  │
  ▼
[Correlation]              → Asset objects            → Report
```

---

## 🛠 Prerequisites

### System Tools (External — go install)

| Tool       | Install Command |
|------------|----------------|
| subfinder  | `go install github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest` |
| dnsx       | `go install github.com/projectdiscovery/dnsx/cmd/dnsx@latest` |
| httpx      | `go install github.com/projectdiscovery/httpx/cmd/httpx@latest` |
| nuclei     | `go install github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest` |
| amass      | `go install github.com/owasp-amass/amass/v4/...@master` |
| nmap       | https://nmap.org/download.html |

> **Requires Go 1.21+** — https://go.dev/dl/

### Python Dependencies

> ⚠️ **Kali / Debian users**: System Python is externally managed. Use a virtual environment:

```bash
# Create virtual environment
python3 -m venv venv

# Activate it
source venv/bin/activate        # Linux/Mac
# OR on Windows:
.\venv\Scripts\activate

# Install dependencies inside venv
pip install -r requirements.txt
```

---

## 🚀 Quick Start

### 1. Check / Install Tools

```bash
# Make sure venv is active first!
source venv/bin/activate

# Check what's installed
python main.py setup

# Auto-install missing tools
python main.py setup --auto
```

### 2. Run a Full Scan

```bash
python main.py scan -d example.com
```

### 3. Quick Scan (no nmap / nuclei)

```bash
python main.py scan -d example.com --quick
```

### 4. Skip Vuln Scan Only

```bash
python main.py scan -d example.com --no-vuln
```

### 5. Resume Interrupted Scan

```bash
python main.py resume -d example.com
```

### 6. Regenerate Report (no re-scan)

```bash
python main.py report -d example.com
```

---

## ⚙️ Configuration

Edit `config.yaml` to tune behavior:

```yaml
general:
  threads: 20
  timeout: 30          # per-tool timeout (seconds)
  output_dir: "output"

modules:
  recon: true          # subfinder + amass
  dns: true            # dnsx
  http: true           # httpx
  enum: true           # nmap
  vuln: true           # nuclei

safety:
  max_subdomains: 500
  max_concurrent: 10
  confirm_active: true # asks before nmap/nuclei
```

---

## 📊 Output

### CLI (Rich Tables)

```
╭──────────────────────────────────────────╮
│              📊 ReconX Report             │
│  Target:          example.com             │
│  Subdomains:      45                      │
│  Live Hosts:      20                      │
│  Open Ports:      38                      │
│  Vulnerabilities: 12  (2 critical / 4 high)│
╰──────────────────────────────────────────╯

[CRITICAL] Exposed Admin Panel → admin.example.com
[HIGH]     Missing Security Headers → api.example.com
```

### JSON File

Saved to `output/reconx_example_com_YYYYMMDD_HHMMSS.json`:

```json
{
  "meta": {
    "domain": "example.com",
    "total_assets": 45,
    "total_vulns": 12
  },
  "assets": [
    {
      "domain": "api.example.com",
      "ip": "1.2.3.4",
      "is_live": true,
      "http_status": 200,
      "ports": [{"port": 443, "service": "https"}],
      "vulns": [...]
    }
  ]
}
```

---

## 🔐 Legal Notice

> Only scan targets you own or have **explicit written permission** to test.  
> Unauthorized scanning is illegal and unethical.  
> ReconX prompts for confirmation before running active scans (nmap/nuclei).

---

## 🗺 Roadmap

| Phase | Status | Features |
|-------|--------|---------|
| 1 — MVP | ✅ Done | setup, recon, dns, http, nuclei, JSON report |
| 2 — Enum | ✅ Done | nmap integration, correlation engine |
| 3 — Resume | ✅ Done | state manager, resume command |
| 4 — HTML Report | 🔜 Next | Jinja2 HTML report generation |
| 5 — API | 🔜 Future | REST API mode, Burp integration |
