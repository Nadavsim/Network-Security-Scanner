"""nmap-based service/version detection (with a banner-grab fallback) and NVD CVE lookups."""
from __future__ import annotations

import logging
import socket
import time

import nmap
import requests
import tqdm
from rich.console import Console

from models import Host

logger = logging.getLogger("scanner")
console = Console()

BANNER_GRAB_TIMEOUT = 1.0  # seconds to wait for a service to send an unprompted banner

NVD_URL = "https://services.nvd.nist.gov/rest/json/cves/2.0"
NVD_RATE_LIMIT_DELAY = 1.5  # seconds between real (non-cached) NVD calls

# Color for protocol_inference's CVE lines, by severity - the one place in this module
# that's presentation rather than scanning/lookup logic, see CLAUDE.md.
SEVERITY_COLORS = {
    "CRITICAL": "bold red",
    "HIGH": "dark_orange",
    "MEDIUM": "yellow",
    "LOW": "white",
}
DEFAULT_SEVERITY_COLOR = "white"  # UNKNOWN or any other/unexpected severity string

_EMPTY_SERVICE_INFO = {
    "state": "unknown",
    "service": "unknown",
    "product": "",
    "version": "",
    "extra_info": "",
}


def is_nmap_available() -> bool:
    """Checks once whether the nmap binary can be found (python-nmap searches common paths)."""
    try:
        nmap.PortScanner()
        return True
    except nmap.PortScannerError:
        return False


def grab_banner(ip: str, port: int, timeout: float = BANNER_GRAB_TIMEOUT) -> str:
    """Connects to (ip, port) and returns whatever banner the service sends unprompted, or ""."""
    try:
        with socket.create_connection((ip, port), timeout=timeout) as sock:
            sock.settimeout(timeout)
            data = sock.recv(1024)
        return data.decode(errors="replace").strip()
    except OSError:
        return ""


def detect_protocols_with_banner_grab(host: Host) -> dict[int, dict[str, str]]:
    """Fallback for when nmap isn't installed: grabs a raw banner per open port.

    Less precise than nmap -sV (no structured product/version, so no CVE lookup is
    attempted on these results) but needs nothing beyond a plain socket connection.
    """
    results: dict[int, dict[str, str]] = {}
    if not host.open_ports:
        return results

    for port in tqdm.tqdm(host.open_ports, desc=f"Grabbing banners on {host.ip}", unit="port"):
        banner = grab_banner(host.ip, port)
        info = {**_EMPTY_SERVICE_INFO, "cves": []}
        info["state"] = "open"
        if banner:
            info["service"] = "banner-grab"
            info["extra_info"] = banner
        results[port] = info
    return results


def detect_protocols_with_nmap(host: Host) -> dict[int, dict[str, str]]:
    """Runs nmap -sV against each of host's open ports and returns service details per port.

    Ports are scanned one at a time (rather than batched into a single nmap call) because
    a single unresponsive/timing-out port in a batched scan can suppress results for the
    other ports in that batch.
    """
    results: dict[int, dict[str, str]] = {}
    if not host.open_ports:
        return results

    scanner = nmap.PortScanner()
    for port in tqdm.tqdm(host.open_ports, desc=f"Detecting protocols on {host.ip}", unit="port"):
        results[port] = _scan_single_port_with_nmap(scanner, host.ip, port)
    return results


def _scan_single_port_with_nmap(scanner: nmap.PortScanner, ip: str, port: int) -> dict[str, str]:
    """Runs nmap -sV against one port already confirmed open by tcp_scan's raw connect_ex.

    tcp_scan and nmap probe the port independently, seconds apart, so it's worth flagging
    when they disagree - a wrong/missing state here isn't nmap being definitive, it can mean
    a flaky/rate-limited service, a firewall that treats nmap's specific probe differently
    than a plain connect, or the service simply closed between the two scans.
    """
    try:
        scanner.scan(hosts=ip, ports=str(port), arguments="-sV -n -T3 --version-light --max-retries 1")
        port_info = None
        if ip in scanner.all_hosts() and "tcp" in scanner[ip]:
            port_info = scanner[ip]["tcp"].get(port)

        if port_info:
            state = port_info.get("state", "unknown")
            if state != "open":
                message = (
                    f"tcp_scan found port {port} open, but nmap now reports its state as "
                    f"'{state}' - possibly flaky, or filtered against nmap's own probe."
                )
                print(f"\n[-] Warning: {message}")
                logger.warning(message)
            return {
                "state": state,
                "service": port_info.get("name", "unknown"),
                "product": port_info.get("product", ""),
                "version": port_info.get("version", ""),
                "extra_info": port_info.get("extrainfo", ""),
                "cves": [],
            }

        message = (
            f"tcp_scan found port {port} open, but nmap reported nothing for it at all - "
            "treating it as unconfirmed."
        )
        print(f"\n[-] Warning: {message}")
        logger.warning(message)
    except nmap.PortScannerError as e:
        print(f"\n[-] nmap error on port {port}: {e}")
        logger.error("nmap error on port %d: %s", port, e)
    except Exception as e:  # nmap wrapper can raise several undocumented error types
        print(f"\n[-] Unexpected error on port {port}: {type(e).__name__}: {e}")
        logger.error("Unexpected error on port %d: %s: %s", port, type(e).__name__, e)
    return {**_EMPTY_SERVICE_INFO, "cves": []}


def _extract_cvss(cve_data: dict) -> tuple[float | None, str | None]:
    """Extracts (base_score, base_severity) from a CVE, preferring the newest CVSS version
    available: v3.1, then v3.0, then v2. Not every CVE has v3 metrics.

    NVD's schema puts baseSeverity inside cvssData for v3.x metrics, but as a SIBLING of
    cvssData (not inside it) for v2 metrics - CVSS v2 itself has no baseSeverity concept,
    NVD synthesizes one from the score using v2 thresholds and places it at the metric's
    top level instead. Handled explicitly below rather than assumed to match v3's shape.
    """
    metrics = cve_data.get("metrics", {})

    for key in ("cvssMetricV31", "cvssMetricV30"):
        entries = metrics.get(key)
        if entries:
            cvss_data = entries[0].get("cvssData", {})
            return cvss_data.get("baseScore"), cvss_data.get("baseSeverity")

    entries = metrics.get("cvssMetricV2")
    if entries:
        entry = entries[0]
        return entry.get("cvssData", {}).get("baseScore"), entry.get("baseSeverity")

    return None, None


def sort_cves_by_severity(cves: list[dict]) -> list[dict]:
    """Highest CVSS score first; unscored CVEs (no CVSS metrics yet) sort last, not first."""
    return sorted(cves, key=lambda c: (c["score"] is None, -(c["score"] or 0)))


def lookup_cves(product: str, version: str, cache: dict[tuple[str, str], list[dict]]) -> list[dict]:
    """Queries the NVD for CVEs matching product/version, using cache to avoid repeat calls.

    Each result is a dict: {"id": "CVE-...", "score": float | None, "severity": str | None}.
    Score/severity are None when NVD has no CVSS metrics for that CVE yet (e.g. very recently
    published, awaiting analysis) - not an error, just unscored.

    Only a successful (200) response is cached. A failed lookup (rate limit, network error,
    unexpected status) returns an empty list for this call but does NOT get cached - caching
    a failure the same way as a genuinely-empty result would silently and permanently hide
    real CVEs after a single transient hiccup, since nothing would ever retry a cached entry.
    """
    if not product:
        return []

    key = (product.strip().lower(), (version or "").strip().lower())
    if key in cache:
        return cache[key]

    search_term = f"{product} {version}".strip().replace(" ", "+")
    url = f"{NVD_URL}?keywordSearch={search_term}&resultsPerPage=3"
    cves: list[dict] = []
    succeeded = False

    try:
        headers = {"User-Agent": "Mozilla/5.0 NetworkScanner/1.0"}
        response = requests.get(url, headers=headers, timeout=7)
        if response.status_code == 200:
            succeeded = True
            data = response.json()
            for vuln in data.get("vulnerabilities", []):
                cve_data = vuln.get("cve", {})
                cve_id = cve_data.get("id")
                if cve_id:
                    score, severity = _extract_cvss(cve_data)
                    cves.append({"id": cve_id, "score": score, "severity": severity})
        elif response.status_code == 403:
            print("        [-] NVD API rate limit hit (403). Skipping lookup for this port.")
            logger.warning("NVD API rate limit hit (403) for %s %s", product, version)
        elif response.status_code == 429:
            print("        [-] NVD API too many requests (429). Skipping lookup for this port.")
            logger.warning("NVD API too many requests (429) for %s %s", product, version)
        else:
            print(f"        [-] NVD API returned status {response.status_code}. Skipping.")
            logger.warning("NVD API returned status %d for %s %s", response.status_code, product, version)
    except requests.exceptions.RequestException as e:
        print(f"        [-] NVD request failed: {type(e).__name__}: {e}")
        logger.error("NVD request failed for %s %s: %s: %s", product, version, type(e).__name__, e)

    # Only sleep after an actual network call, never on a cache hit
    time.sleep(NVD_RATE_LIMIT_DELAY)
    if succeeded:
        cache[key] = cves
    return cves


def protocol_inference(host: Host, cve_cache: dict[tuple[str, str], list[dict]], nmap_available: bool = True) -> None:
    """Runs service detection + CVE lookup on host and prints a summary.

    Falls back to banner-grabbing when nmap_available is False (nmap not found on
    this system). Banner-grab results have no structured product/version, so CVE
    lookup is skipped for them.
    """
    if not host.open_ports:
        print(f"[-] No open ports found for {host.ip}")
        return

    if nmap_available:
        host.services = detect_protocols_with_nmap(host)
    else:
        print(f"[-] nmap not available - falling back to banner-grabbing for {host.ip} (no CVE lookup).")
        host.services = detect_protocols_with_banner_grab(host)

    if not host.services:
        print("[-] No protocol/service information found.")
        return

    print(f"\n[+] Protocol inference results for {host.ip}:")
    for port in sorted(host.services.keys()):
        info = host.services[port]
        details = " ".join(part for part in [info["product"], info["version"], info["extra_info"]] if part)

        if not details:
            print(f"    {port}/tcp -> {info['service']}")
            continue

        print(f"    {port}/tcp -> {info['service']} ({details})")
        logger.info("%s:%d/tcp -> %s (%s)", host.ip, port, info["service"], details)
        if info["product"]:
            cves = lookup_cves(info["product"], info["version"], cve_cache)
            cves = sort_cves_by_severity(cves)
            info["cves"] = cves
            if cves:
                for cve in cves:
                    severity_label = cve["severity"] or "UNKNOWN"
                    score_label = f"{cve['score']:.1f}" if cve["score"] is not None else "N/A"
                    color = SEVERITY_COLORS.get(severity_label, DEFAULT_SEVERITY_COLOR)
                    console.print(f"        [{color}][!] {severity_label} ({score_label}): {cve['id']}[/{color}]")
                    logger.info(
                        "%s:%d/tcp CVE found: %s severity=%s score=%s",
                        host.ip, port, cve["id"], severity_label, score_label,
                    )
            else:
                print("        [+] No immediate CVEs found in quick search.")
