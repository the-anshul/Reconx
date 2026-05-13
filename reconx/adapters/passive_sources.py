"""
adapters/passive_sources.py - Pure Python passive subdomain discovery.

These sources keep ReconX useful on machines where subfinder/amass/assetfinder
are not installed yet.
"""

import asyncio
import json
import logging
import re
import ssl
import urllib.parse
import urllib.request

logger = logging.getLogger("reconx.adapters.passive_sources")

USER_AGENT = "ReconX/2.0 passive recon"


async def run_passive_sources(domain: str, timeout: int = 30) -> list[tuple[str, str]]:
    """Query public passive sources and return (subdomain, source) pairs."""
    tasks = [
        ("crt.sh", _fetch_crtsh(domain, timeout)),
        ("hackertarget", _fetch_hackertarget(domain, timeout)),
        ("alienvault", _fetch_alienvault(domain, timeout)),
        ("urlscan", _fetch_urlscan(domain, timeout)),
        ("wayback", _fetch_wayback(domain, timeout)),
        ("rapiddns", _fetch_rapiddns(domain, timeout)),
    ]
    
    # We need to gather the coroutines, keeping track of which name belongs to which
    source_names = [t[0] for t in tasks]
    coroutines = [t[1] for t in tasks]
    
    results = await asyncio.gather(*coroutines, return_exceptions=True)

    findings: list[tuple[str, str]] = []
    for name, result in zip(source_names, results):
        if isinstance(result, Exception):
            logger.debug(f"[passive] Source {name} failed: {result}")
            continue
        
        cleaned = _clean_subdomains(result, domain)
        for sub in cleaned:
            findings.append((sub, name))

    logger.info(f"[passive] Found {len(set(f[0] for f in findings))} unique subdomains across {len(source_names)} sources")
    return findings


async def _fetch_crtsh(domain: str, timeout: int) -> list[str]:
    query = urllib.parse.quote(f"%.{domain}")
    url = f"https://crt.sh/?q={query}&output=json"
    logger.info(f"[passive:crtsh] Querying certificate transparency for {domain}")

    def request() -> list[str]:
        body = _http_get(url, timeout)
        if not body:
            return []
        try:
            rows = json.loads(body)
        except json.JSONDecodeError:
            return []

        names = []
        for row in rows:
            value = row.get("name_value", "")
            names.extend(value.splitlines())
        return names

    return await asyncio.to_thread(request)


async def _fetch_hackertarget(domain: str, timeout: int) -> list[str]:
    query = urllib.parse.quote(domain)
    url = f"https://api.hackertarget.com/hostsearch/?q={query}"
    logger.info(f"[passive:hackertarget] Querying hostsearch for {domain}")

    def request() -> list[str]:
        body = _http_get(url, timeout)
        if not body or "error" in body.lower():
            return []
        names = []
        for line in body.splitlines():
            host = line.split(",", 1)[0].strip()
            if host:
                names.append(host)
        return names

    return await asyncio.to_thread(request)


async def _fetch_alienvault(domain: str, timeout: int) -> list[str]:
    url = f"https://otx.alienvault.com/api/v1/indicators/domain/{domain}/passive_dns"
    logger.info(f"[passive:alienvault] Querying AlienVault OTX for {domain}")

    def request() -> list[str]:
        body = _http_get(url, timeout)
        if not body: return []
        try:
            data = json.loads(body)
            return [record.get("hostname", "") for record in data.get("passive_dns", [])]
        except: return []

    return await asyncio.to_thread(request)


async def _fetch_urlscan(domain: str, timeout: int) -> list[str]:
    url = f"https://urlscan.io/api/v1/search/?q=domain:{domain}"
    logger.info(f"[passive:urlscan] Querying urlscan.io for {domain}")

    def request() -> list[str]:
        body = _http_get(url, timeout)
        if not body: return []
        try:
            data = json.loads(body)
            return [res.get("page", {}).get("domain", "") for res in data.get("results", [])]
        except: return []

    return await asyncio.to_thread(request)


async def _fetch_wayback(domain: str, timeout: int) -> list[str]:
    url = f"https://web.archive.org/cdx/search/cdx?url=*.{domain}/*&output=json&collapse=urlkey&fl=original"
    logger.info(f"[passive:wayback] Querying Wayback Machine for {domain}")

    def request() -> list[str]:
        body = _http_get(url, timeout)
        if not body: return []
        try:
            data = json.loads(body)
            if not data or len(data) < 2: return []
            # First row is header ["original"]
            subs = set()
            for row in data[1:]:
                original_url = row[0]
                parsed = urllib.parse.urlparse(original_url)
                netloc = parsed.netloc.split(":")[0]
                if netloc: subs.add(netloc)
            return list(subs)
        except: return []

    return await asyncio.to_thread(request)


async def _fetch_rapiddns(domain: str, timeout: int) -> list[str]:
    url = f"https://rapiddns.io/subdomain/{domain}?full=1#result"
    logger.info(f"[passive:rapiddns] Querying RapidDNS for {domain}")

    def request() -> list[str]:
        body = _http_get(url, timeout)
        if not body: return []
        # Simple regex extraction for domain names in the table
        # Look for <td>domain.com</td> pattern
        pattern = re.compile(rf"<td>([a-z0-9.-]+\.{re.escape(domain)})</td>", re.IGNORECASE)
        return pattern.findall(body)

    return await asyncio.to_thread(request)


def _http_get(url: str, timeout: int) -> str:
    context = ssl._create_unverified_context()
    request = urllib.request.Request(url, headers={"User-Agent": USER_AGENT})
    try:
        with urllib.request.urlopen(request, timeout=timeout, context=context) as response:
            return response.read().decode("utf-8", errors="ignore")
    except Exception as e:
        logger.debug(f"[passive] Request failed for {url}: {e}")
        return ""


def _clean_subdomains(values: list[str], domain: str) -> set[str]:
    clean: set[str] = set()
    suffix = f".{domain.lower()}"
    pattern = re.compile(r"^[a-z0-9][a-z0-9.-]*[a-z0-9]$", re.IGNORECASE)

    for value in values:
        if not value: continue
        host = value.strip().lower().lstrip("*.").rstrip(".")
        if not host:
            continue
        if host == domain.lower() or host.endswith(suffix):
            if pattern.match(host):
                clean.add(host)

    return clean
