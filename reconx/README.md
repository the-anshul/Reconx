# ReconX — Recon + Enumeration + Vuln Automation Framework

```
 ██████╗ ███████╗ ██████╗ ██████╗ ███╗   ██╗██╗  ██╗
 ██╔══██╗██╔════╝██╔════╝██╔═══██╗████╗  ██║╚██╗██╔╝
 ██████╔╝█████╗  ██║     ██║   ██║██╔██╗ ██║ ╚███╔╝
 ██╔══██╗██╔══╝  ██║     ██║   ██║██║╚██╗██║ ██╔██╗
 ██║  ██║███████╗╚██████╗╚██████╔╝██║ ╚████║██╔╝ ██╗
 ╚═╝  ╚═╝╚══════╝ ╚═════╝ ╚═════╝ ╚═╝  ╚═══╝╚═╝  ╚═╝
```

> **Modular · Resumable · Parallel · Actionable Reports**  
> ReconX ek automation framework hai jo penetration testing aur bug bounty ke recon phase ko asaan banata hai.

---

## 🛠 Commands & Working (How to Use)

Is tool mein total 5 main commands hain. Har command ka kaam niche diya gaya hai:

### 1. `setup` — Tool Configuration
Iska kaam framework ke liye zaroori tools (subfinder, httpx, nuclei, etc.) ko check aur install karna hai.
*   **Check only:** `python3 main.py setup` (Sirf bataega kaunse tools missing hain).
*   **Auto Install:** `python3 main.py setup --auto` (Missing tools ko khud download aur install karega).

### 2. `scan` — Full Pipeline Execution
Yeh framework ka sabse main command hai. Yeh recon se lekar vulnerability scanning tak sab kuch karta hai.
*   **Basic Scan:** `python3 main.py scan -d example.com` (Subdomains, DNS, HTTP, Ports, aur Vulnerabilities scan karega).
*   **Quick Scan:** `python3 main.py scan -d example.com --quick` (Heavy tools jaise Nmap aur Nuclei ko skip karke jaldi results dega).
*   **No-Vuln Scan:** `python3 main.py scan -d example.com --no-vuln` (Sirf recon aur port scanning karega, vulnerability detection skip kar dega).

### 3. `resume` — Recover Interrupted Scans
Agar scan beech mein ruk jaye (internet ya crash ki wajah se), toh aap use wahin se shuru kar sakte hain jahan wo ruka tha.
*   **Usage:** `python3 main.py resume -d example.com`
*   **Working:** Yeh `output/` folder mein saved state file ko read karta hai aur pending phases ko execute karta hai.

### 4. `report` — View Results
Bina dubara scan kiye, pehle se kiye gaye scan ki report dekhne ke liye iska use hota hai.
*   **Usage:** `python3 main.py report -d example.com`
*   **Working:** Yeh purane data ko correlate karke Rich table format aur JSON file generate karta hai.

### 5. `banner` — Customize Look
Aap CLI ka look change kar sakte hain.
*   **List styles:** `python3 main.py banner` (Saare styles dikhaega).
*   **Set style:** `python3 main.py banner --set ghost` (Naya style default set kar dega).
*   **Styles:** `standard`, `slant`, `ghost`, `minimal`.

---

## 📐 Architecture & Tools

ReconX in tools ka use karta hai:
1.  **Passive Recon:** `subfinder`, `amass`
2.  **DNS Resolution:** `dnsx`
3.  **HTTP Probing:** `httpx`
4.  **Port Scanning:** `nmap`
5.  **Vuln Detection:** `nuclei`

---

## 🚀 Getting Started

1.  **Dependencies Install karein:**
    ```bash
    pip install -r requirements.txt
    ```
2.  **Tools Setup karein:**
    ```bash
    python3 main.py setup --auto
    ```
3.  **Pehla Scan chalayein:**
    ```bash
    python3 main.py scan -d testasp.vulnweb.com
    ```

---

## 💾 Output Data
Saara data `output/` folder mein save hota hai:
*   `domain_state.json`: Scan ki current state (resume karne ke liye).
*   `reconx_domain_timestamp.json`: Final combined report.

---

## 🔐 Legal Notice
Yeh tool sirf security research aur authorization ke saath use karne ke liye hai. Unauthorized scanning illegal hai.
