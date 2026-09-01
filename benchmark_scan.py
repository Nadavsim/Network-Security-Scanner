"""Benchmark harness comparing network_scanner.tcp_scan (threaded) against
network_scanner_async.tcp_scan_async (asyncio) across a few representative
scenarios: throttled vs. unthrottled, small port range vs. the full 65535.

Standalone script, not part of the interactive app - answers the "which is
better for which case" question from CLAUDE.md's planned-next list. Defaults to
scanning 127.0.0.1 so it's runnable out of the box without touching a real
network target. A handful of local TCP listeners are started first so there's
deterministic ground truth for correctness comparison, not just timing - this
is what caught the async false-negative-under-load behavior documented in
CLAUDE.md and network_scanner_async.py.

Usage:
    python benchmark_scan.py                       # full run (a few minutes)
    python benchmark_scan.py --quick                # small ranges, fast sanity check
    python benchmark_scan.py --include-slow-throttled-full   # + a ~55 min scenario
"""
from __future__ import annotations

import argparse
import asyncio
import socket
import time
from dataclasses import dataclass

from config import ScanConfig
from models import Host
from network_scanner import tcp_scan
from network_scanner_async import tcp_scan_async

KNOWN_OPEN_PORTS = [79, 512, 987]


@dataclass
class ScenarioResult:
    label: str
    implementation: str
    elapsed: float
    open_ports: list[int]
    matches_ground_truth: bool


def start_test_listeners(ports: list[int]) -> list[socket.socket]:
    """Binds real local listeners so the benchmark has deterministic ground truth."""
    servers = []
    for port in ports:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        s.bind(("127.0.0.1", port))
        s.listen(50)
        servers.append(s)
    return servers


def stop_test_listeners(servers: list[socket.socket]) -> None:
    for s in servers:
        s.close()


def run_sync(target_ip: str, config: ScanConfig) -> tuple[float, list[int]]:
    host = Host(ip=target_ip, adaptive_timeout=0.2)
    start = time.monotonic()
    tcp_scan(host, config)
    return time.monotonic() - start, host.open_ports


def run_async(target_ip: str, config: ScanConfig) -> tuple[float, list[int]]:
    host = Host(ip=target_ip, adaptive_timeout=0.2)
    start = time.monotonic()
    asyncio.run(tcp_scan_async(host, config))
    return time.monotonic() - start, host.open_ports


def run_scenario(
    label: str, target_ip: str, config: ScanConfig, ground_truth: list[int]
) -> list[ScenarioResult]:
    # Only known listeners actually inside this scenario's scanned range (1..number_of_ports_to_scan-1)
    # count as ground truth here; a subset check (not exact equality) means real services the
    # scan happens to find (e.g. Windows RPC/SMB on 135/445) don't register as a false mismatch -
    # we're only verifying our own controlled listeners were found, not that nothing else was.
    ground_truth_in_range = [p for p in ground_truth if p < config.number_of_ports_to_scan]

    results = []
    for impl_name, run_fn in [("sync/threaded", run_sync), ("async", run_async)]:
        elapsed, open_ports = run_fn(target_ip, config)
        matches = set(ground_truth_in_range).issubset(set(open_ports))
        results.append(ScenarioResult(label, impl_name, elapsed, open_ports, matches))
    return results


def format_results_table(results: list[ScenarioResult]) -> str:
    header = f"{'Scenario':<34} {'Impl':<14} {'Time (s)':>10}  {'Open ports':<28} {'Correct'}"
    lines = [header, "-" * len(header)]
    for r in results:
        correct = "yes" if r.matches_ground_truth else "NO"
        lines.append(
            f"{r.label:<34} {r.implementation:<14} {r.elapsed:>10.2f}  {str(r.open_ports):<28} {correct}"
        )
    return "\n".join(lines)


def build_scenarios(quick: bool, include_slow_throttled_full: bool) -> list[tuple[str, ScanConfig]]:
    small_range = 101 if quick else 1001  # 101 still covers KNOWN_OPEN_PORTS[0] (79)
    full_range = 2001 if quick else 65536

    scenarios = [
        (
            f"small range (1-{small_range - 1}), throttled 20/s",
            ScanConfig(number_of_ports_to_scan=small_range, max_workers=100, max_scans_per_second=20.0),
        ),
        (
            f"small range (1-{small_range - 1}), unthrottled",
            ScanConfig(number_of_ports_to_scan=small_range, max_workers=100, max_scans_per_second=None),
        ),
        (
            f"full range (1-{full_range - 1}), unthrottled",
            ScanConfig(number_of_ports_to_scan=full_range, max_workers=200, max_scans_per_second=None),
        ),
    ]
    if include_slow_throttled_full:
        scenarios.append((
            f"full range (1-{full_range - 1}), throttled 20/s [very slow]",
            ScanConfig(number_of_ports_to_scan=full_range, max_workers=100, max_scans_per_second=20.0),
        ))
    return scenarios


def main() -> None:
    parser = argparse.ArgumentParser(description="Benchmark tcp_scan vs tcp_scan_async.")
    parser.add_argument("--target", default="127.0.0.1", help="Target IP to scan (default: 127.0.0.1).")
    parser.add_argument(
        "--quick", action="store_true",
        help="Use much smaller port ranges for a fast sanity check instead of a real benchmark.",
    )
    parser.add_argument(
        "--include-slow-throttled-full", action="store_true",
        help="Also run the full-range scenario throttled at 20/sec (~55 min at real scale). Off by default.",
    )
    args = parser.parse_args()

    scenarios = build_scenarios(args.quick, args.include_slow_throttled_full)

    print(f"Benchmarking against {args.target} - {len(scenarios)} scenario(s), each run sync then async.")
    print("This can take a few minutes (mostly the unthrottled full-range scenario).\n")

    servers = start_test_listeners(KNOWN_OPEN_PORTS)
    all_results: list[ScenarioResult] = []
    try:
        for label, config in scenarios:
            print(f"=== {label} ===")
            results = run_scenario(label, args.target, config, KNOWN_OPEN_PORTS)
            for r in results:
                print(f"  {r.implementation:<14} {r.elapsed:>8.2f}s  open={r.open_ports}")
            all_results.extend(results)
            print()
    finally:
        stop_test_listeners(servers)

    print(format_results_table(all_results))


if __name__ == "__main__":
    main()
