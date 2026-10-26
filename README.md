# Network Security Scanner

A Python network reconnaissance tool: ARP host discovery, threaded TCP/UDP port
scanning, nmap-based service/version detection, and automatic NVD CVE lookup for
whatever services are found — with JSON export for the results.

Built as a portfolio project to demonstrate practical security tooling and
systems-level Python (raw sockets, concurrency, rate limiting) rather than just
scripting `nmap` calls.

## Features

- **ARP host discovery** on a local subnet (scapy), with VM-test and live-network modes
- **Threaded TCP port scanning** with shuffled scan order (avoids naive sequential-scan
  detection) and a stealth-oriented rate limiter that paces individual connection
  attempts, not just batches
- **UDP port scanning** with proper ICMP-based state inference (`open` /
  `closed` / `filtered` / `open|filtered`)
- **Adaptive timeout calculation** and best-effort OS fingerprinting via TTL/ICMP
- **Service/version detection** via `nmap -sV`, falling back to raw banner-grabbing
  if `nmap` isn't installed
- **Automatic CVE lookup** against the NVD REST API for any product/version nmap
  identifies, with CVSS-based severity sorting and color-coded output
- **JSON export** of a scan's full results (open ports, services, CVEs)
- Both an **interactive menu** and a **non-interactive CLI mode** for scripting
  (`--target`, `--ports`, `--detect-services`, `--export`, `--rate`)
- A persistent per-session audit log (`logs/scan_<timestamp>.log`), separate from
  the interactive console output
- An optional `scan_config.toml` for tuning scan behavior without touching code

## Why this project

Most "port scanner" portfolio projects are a loop around `socket.connect_ex`. This
one tries to behave like a tool you'd actually use during a pentest engagement:

- Scans are rate-limited and port order is shuffled by default — quiet is the
  default, not an afterthought
- UDP scanning had to be redesigned from a naive `ThreadPoolExecutor` approach after
  two real, reproducible bugs surfaced during testing: `scapy`'s `sr1()` is not
  thread-safe (concurrent calls cross-matched replies between threads and produced
  false positives — a definitely-closed port reported as open), and
  `ThreadPoolExecutor`'s task pre-dequeuing made Ctrl+C hang for 100+ seconds against
  an unresponsive host. UDP scanning is now a plain sequential loop as a result.
- A sync (threaded) vs. async (`asyncio`) TCP scanner were both implemented and
  benchmarked head-to-head (see [BENCHMARK_REPORT.md](BENCHMARK_REPORT.md)) before
  deciding which one to actually wire into the CLI.
- CVE lookups only cache *successful* NVD responses — an early version cached
  rate-limited/failed lookups the same as genuinely-empty ones, which would have
  permanently hidden real CVEs for the rest of a session after one transient 429.

## Requirements

- Python 3.11+ (uses `tomllib` from the standard library)
- [Nmap](https://nmap.org/download.html) installed system-wide and on `PATH`
  (separate from the `python-nmap` pip package, which is just a wrapper around it).
  Without it, service detection falls back to banner-grabbing and CVE lookups are
  skipped.
- Root/Administrator privileges (raw ARP/ICMP/UDP sockets)
- Npcap (Windows) or equivalent packet-capture driver for scapy

## Installation

```bash
git clone https://github.com/Nadavsim/Network-Security-Scanner.git
cd Network-Security-Scanner
pip install -r requirements.txt
```

## Usage

Interactive menu (ARP discovery, host selection, TCP/UDP scans, export):

```bash
python main.py
```

Non-interactive, single-target mode — skips ARP discovery and the menu entirely:

```bash
python main.py --target 192.168.1.16 --ports 1000 --detect-services --export scan.json
```

Run `python main.py --help` for the full flag list. Note: `--ports`, `--interface`,
`--detect-services`, `--export`, and `--rate` all require `--target`; without it,
the tool falls back to the interactive menu with a warning.

Optional tuning via `scan_config.toml` in the working directory (copy
[scan_config.example.toml](scan_config.example.toml) to get started) — everything
except the target itself (chosen via `--target` or the interactive menu) can be
overridden there.

## Testing

```bash
pytest
```

112+ tests covering the scanning logic, config loading, CVE lookup/caching, export,
logging setup, and the CLI's host-scan pipeline — network calls are mocked
throughout, so the suite doesn't require root or a live network.

Benchmark the threaded vs. asyncio TCP scanners against each other:

```bash
python benchmark_scan.py --quick   # fast sanity check
python benchmark_scan.py           # full benchmark, a few minutes
```

## Architecture

How the modules talk to each other, from the entry point down to the network, nmap,
and the NVD API. Dotted lines are side relationships (config/log files, and the
benchmark track that isn't wired into the app).

```mermaid
flowchart TD
    USER(["User at terminal"])

    subgraph ENTRY["Entry point"]
        MAIN["main.py<br/>argparse flags<br/>is_valid_ipv4 check<br/>top-level Ctrl+C / PermissionError handling"]
    end

    subgraph APP["cli.py - ScannerApp (session state + rich output)"]
        INIT["__init__<br/>setup_logging, load_scan_config,<br/>is_nmap_available"]
        MENU["run: menu loop"]
        SINGLE["run_single_target<br/>non-interactive"]
        ARPH["handle_arp_discovery"]
        TCPH["handle_tcp_scan"]
        UDPH["handle_udp_scan"]
        FULL["handle_full_workflow<br/>ARP then TCP"]
        SHOW["show_scan_results<br/>rich Table"]
        EXPH["handle_export_results"]
        SCANHOST["_scan_host<br/>shared per-host pipeline"]
    end

    subgraph CORE["Support modules"]
        CONFIG["config.py<br/>ScanConfig + load_scan_config"]
        LOGSET["logging_setup.py<br/>setup_logging"]
        MODELS["models.py<br/>Host dataclass"]
    end

    subgraph SCAN["network_scanner.py - scapy + sockets"]
        ARP["arp_scan<br/>Layer 2 host discovery"]
        TIMEOUT["calculate_adaptive_timeout"]
        OSG["guess_os_from_ttl<br/>ICMP echo + TTL"]
        TCP["tcp_scan<br/>shuffled ports, thread pool"]
        RL["RateLimiter<br/>stealth pacing"]
        UDP["udp_scan<br/>sequential, ICMP inference"]
    end

    subgraph SVC["service_detection.py"]
        PI["protocol_inference"]
        NMAPD["detect_protocols_with_nmap<br/>one nmap -sV call per port"]
        BANNER["detect_protocols_with_banner_grab<br/>fallback if no nmap"]
        CVE["lookup_cves<br/>cache only on HTTP 200"]
        SORT["sort_cves_by_severity"]
    end

    EXP["export.py<br/>export_hosts_to_json"]

    subgraph EXT["External systems and files"]
        NET[("Target network / hosts")]
        NMAPBIN[["system nmap binary"]]
        NVD[["NVD CVE API v2.0"]]
        TOML[/"scan_config.toml (optional)"/]
        LOGF[/"logs/scan_timestamp.log"/]
        JSONF[/"scan.json"/]
    end

    subgraph SIDE["Benchmark side-track - not wired into the app"]
        ASYNC["network_scanner_async.py<br/>tcp_scan_async + AsyncRateLimiter"]
        BENCH["benchmark_scan.py"]
        REPORT[/"BENCHMARK_REPORT.md"/]
    end

    USER --> MAIN
    MAIN -->|"--target IP"| SINGLE
    MAIN -->|"no --target"| MENU
    MAIN --> INIT

    INIT --> CONFIG
    INIT --> LOGSET
    CONFIG -.->|"reads"| TOML
    LOGSET -.->|"creates"| LOGF

    MENU --> ARPH
    MENU --> TCPH
    MENU --> UDPH
    MENU --> FULL
    MENU --> SHOW
    MENU --> EXPH
    FULL --> ARPH
    FULL --> TCPH

    ARPH --> ARP
    ARP -->|"ARP requests"| NET
    ARP -->|"list of Host"| MODELS
    ARPH --> SHOW

    TCPH --> SCANHOST
    SINGLE --> SCANHOST
    SCANHOST --> TIMEOUT
    SCANHOST --> OSG
    SCANHOST --> TCP
    TIMEOUT -->|"probe latency"| NET
    OSG -->|"ICMP echo"| NET
    TCP --> RL
    RL -->|"paced connect attempts"| NET
    TCP -->|"fills host.open_ports"| MODELS

    UDPH --> UDP
    UDP -->|"UDP probes"| NET
    UDP -->|"fills udp_open_ports and udp_open_or_filtered_ports"| MODELS

    TCPH -->|"user answers y"| PI
    SINGLE -->|"--detect-services"| PI
    PI -->|"nmap installed"| NMAPD
    PI -->|"nmap missing"| BANNER
    NMAPD --> NMAPBIN
    NMAPBIN --> NET
    BANNER -->|"raw socket read"| NET
    PI -->|"product + version found"| CVE
    CVE --> NVD
    CVE --> SORT
    SORT -->|"host.services port cves"| MODELS

    EXPH --> EXP
    SINGLE -->|"--export"| EXP
    MODELS -->|"Host data"| EXP
    EXP --> JSONF

    ASYNC -.->|"compared against"| TCP
    BENCH -.-> ASYNC
    BENCH -.-> TCP
    BENCH -.-> REPORT

    CONFIG -.->|"ScanConfig passed into scans"| SCAN
```

## Project structure

| File | Purpose |
|---|---|
| `main.py` | Entry point, CLI argument parsing, top-level error handling |
| `cli.py` | `ScannerApp` — interactive menu loop and session state |
| `config.py` | `ScanConfig` dataclass and `scan_config.toml` loading |
| `network_scanner.py` | ARP discovery, TCP/UDP port scanning, rate limiting, OS fingerprinting |
| `network_scanner_async.py` | Benchmarked `asyncio` TCP scanner (kept for comparison, not wired into the CLI) |
| `service_detection.py` | nmap/banner-grab service detection, NVD CVE lookup |
| `export.py` | JSON export of scan results |
| `logging_setup.py` | Persistent per-session audit log setup |
| `models.py` | `Host` dataclass |
| `benchmark_scan.py` | Standalone sync-vs-async scanner benchmark harness |
| `tests/` | pytest suite |

## Disclaimer

For use only against systems you own or have explicit authorization to test.
Unauthorized scanning of networks or hosts may be illegal.

## Author

Nadav Simchai
