"""ARP host discovery and TCP port scanning."""
from __future__ import annotations

import logging
import random
import socket
import statistics
import threading
import time
from concurrent.futures import ThreadPoolExecutor, as_completed

import tqdm
from scapy.layers.inet import ICMP, IP, UDP
from scapy.layers.l2 import ARP, Ether
from scapy.sendrecv import sr1, srp

from config import ScanConfig
from models import Host

logger = logging.getLogger("scanner")

# TTL baselines, ordered ascending: an observed TTL is rounded UP to the nearest baseline
# to account for hop-count decrement between the host and us (a real Linux host sending 64
# will arrive as something <= 64, never higher).
TTL_OS_BASELINES = [
    (64, "Linux/Unix"),
    (128, "Windows"),
    (255, "Network device (e.g. Cisco)"),
]

# UDP port states, per-port results from scan_single_port_udp.
UDP_OPEN = "open"                    # got a UDP reply back - a listener answered
UDP_CLOSED = "closed"                # ICMP type 3 code 3 (port unreachable) - no listener
UDP_FILTERED = "filtered"            # other ICMP unreachable code - a firewall/ACL is blocking it
UDP_OPEN_OR_FILTERED = "open|filtered"  # no reply at all - ambiguous, see udp_scan's docstring

DEFAULT_UDP_TIMEOUT = 1.0  # seconds to wait for a UDP reply or ICMP unreachable


def send_arp_request(pdst: str, timeout: float, verbose: bool, iface: str | None) -> tuple:
    """Sends a broadcast ARP request for pdst and returns the (answered, unanswered) pair."""
    packet = Ether(dst="ff:ff:ff:ff:ff:ff") / ARP(pdst=pdst)
    return srp(packet, timeout=timeout, verbose=verbose, iface=iface)


def arp_scan(config: ScanConfig) -> list[Host]:
    """Sends ARP requests across config.target_range and returns discovered hosts."""
    print(f"[*] Starting ARP discovery on {config.target_range}...")
    answered, _ = send_arp_request(
        config.target_range, config.arp_timeout, config.arp_verbose, config.network_interface
    )
    # rcv.psrc = Protocol Source (IP address), rcv.hwsrc = Hardware Source (MAC address)
    hosts = [Host(ip=rcv.psrc, mac=rcv.hwsrc) for _, rcv in answered]
    logger.info("ARP discovery on %s: found %d host(s)", config.target_range, len(hosts))
    return hosts


def calculate_adaptive_timeout(target_ip: str, config: ScanConfig, probes: int = 5) -> float:
    """Measures RTT/jitter to target_ip and derives a jitter-aware socket timeout."""
    print(f"[*] Calculating adaptive timeout for {target_ip}...")
    rtts: list[float] = []

    for _ in range(probes):
        start_time = time.time()
        answered, _ = send_arp_request(target_ip, 1, False, config.network_interface)
        end_time = time.time()
        if answered:
            rtts.append(end_time - start_time)

    if not rtts:
        print("[-] Target unresponsive to timing probes. Falling back to default (0.5s).")
        return 0.5

    avg_rtt = statistics.mean(rtts)
    jitter = statistics.pstdev(rtts)
    # Jitter-aware formula: avg + 3*stddev + small buffer, clamped to a sane range
    adaptive_timeout = avg_rtt + (3 * jitter) + 0.05
    adaptive_timeout = max(0.05, min(adaptive_timeout, 1.5))
    print(
        f"[+] Measured Avg RTT: {avg_rtt:.4f}s | Jitter: {jitter:.4f}s | "
        f"Set Adaptive Timeout to: {adaptive_timeout:.4f}s"
    )
    return adaptive_timeout


def guess_os_from_ttl(ip: str, config: ScanConfig, timeout: float = 1.0) -> str | None:
    """Best-effort, spoofable heuristic: sends one ICMP echo to ip and guesses OS family
    from the reply's TTL, rounded up to the nearest common baseline in TTL_OS_BASELINES.

    Not authoritative - trivially spoofable, and not always accurate even honestly
    reported. Returns None if the host doesn't reply to ICMP (common - many hosts/
    firewalls block it) within timeout.
    """
    reply = sr1(IP(dst=ip) / ICMP(), timeout=timeout, verbose=False)
    if reply is None or not reply.haslayer(IP):
        logger.info("OS guess for %s: no ICMP reply", ip)
        return None

    observed_ttl = reply[IP].ttl
    for baseline, os_name in TTL_OS_BASELINES:
        if observed_ttl <= baseline:
            logger.info("OS guess for %s: %s (TTL=%d)", ip, os_name, observed_ttl)
            return os_name
    return None


def scan_single_port(ip: str, port: int, timeout: float = 0.2) -> int | None:
    """Attempts a TCP connect to (ip, port). Returns the port number if open, else None."""
    sock: socket.socket | None = None
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(timeout)
        if sock.connect_ex((ip, port)) == 0:
            return port
    except OSError:
        pass
    finally:
        if sock is not None:
            sock.close()
    return None


class RateLimiter:
    """Thread-safe pacing gate: acquire() blocks until the next slot at max_per_second opens up.

    Paces the actual rate of connection attempts (regardless of thread count), rather than
    just adding a delay between submitted batches — that's what makes it useful for stealth:
    a burst of `max_workers` connections all firing at once is exactly what naive port-scan
    detection looks for.
    """

    def __init__(self, max_per_second: float):
        self._min_interval = 1.0 / max_per_second
        self._lock = threading.Lock()
        self._next_slot = time.monotonic()

    def acquire(self) -> None:
        with self._lock:
            now = time.monotonic()
            wait = self._next_slot - now
            self._next_slot = max(self._next_slot, now) + self._min_interval
        if wait > 0:
            time.sleep(wait)


def tcp_scan(host: Host, config: ScanConfig) -> None:
    """Scans host.ip across 1..config.number_of_ports_to_scan and stores results on host.

    Note: this function only performs the scan. Any follow-up (e.g. asking whether to
    run protocol inference) is the caller's responsibility — keeping I/O prompts out of
    the scanning logic makes this testable and reusable outside the interactive CLI.
    """
    host.open_ports = []
    ports = list(range(1, config.number_of_ports_to_scan))
    random.shuffle(ports)  # bypass basic firewalls that expect serial, ascending scans

    limiter = RateLimiter(config.max_scans_per_second) if config.max_scans_per_second else None

    def scan_with_pacing(port: int) -> int | None:
        if limiter is not None:
            limiter.acquire()
        return scan_single_port(host.ip, port, host.adaptive_timeout)

    executor = ThreadPoolExecutor(max_workers=config.max_workers)
    try:
        futures = [executor.submit(scan_with_pacing, port) for port in ports]
        for future in tqdm.tqdm(
            as_completed(futures), total=len(futures), desc=f"Scanning {host.ip}", unit="port"
        ):
            open_port = future.result()
            if open_port is not None:
                host.open_ports.append(open_port)
    except KeyboardInterrupt:
        # Plain executor.shutdown() (or the `with` form) defaults to wait=True, which blocks
        # until every already-submitted probe finishes - since every port is submitted up
        # front, that can mean minutes of unresponsive "hang" after Ctrl+C. cancel_futures
        # drops everything not yet started; only the max_workers probes already in flight
        # (each bounded by host.adaptive_timeout) still need to finish naturally.
        print(f"\n[-] Scan of {host.ip} interrupted - cancelling pending probes...")
        executor.shutdown(wait=False, cancel_futures=True)
        host.open_ports.sort()  # keep whatever was found before the interrupt
        logger.warning("TCP scan of %s interrupted; %d open port(s) found so far: %s",
                        host.ip, len(host.open_ports), host.open_ports)
        raise
    else:
        executor.shutdown(wait=True)

    host.open_ports.sort()
    host.scanned = True
    logger.info("TCP scan of %s complete: %d open port(s): %s", host.ip, len(host.open_ports), host.open_ports)


def scan_single_port_udp(ip: str, port: int, timeout: float = DEFAULT_UDP_TIMEOUT) -> str:
    """Sends one empty UDP datagram to (ip, port) and classifies the result.

    UDP has no handshake, so port state has to be inferred from what (if anything) comes
    back - see UDP_OPEN/UDP_CLOSED/UDP_FILTERED/UDP_OPEN_OR_FILTERED above. No iface
    argument for the same reason as guess_os_from_ttl: sr1() is Layer 3 and picks the
    interface via the OS routing table, iface has no effect there.
    """
    reply = sr1(IP(dst=ip) / UDP(dport=port), timeout=timeout, verbose=False)

    if reply is None:
        return UDP_OPEN_OR_FILTERED
    if reply.haslayer(ICMP):
        icmp_layer = reply.getlayer(ICMP)
        if icmp_layer.type == 3 and icmp_layer.code == 3:
            return UDP_CLOSED
        return UDP_FILTERED
    return UDP_OPEN


def udp_scan(host: Host, config: ScanConfig, timeout: float = DEFAULT_UDP_TIMEOUT) -> None:
    """Scans host.ip across 1..config.number_of_ports_to_scan over UDP.

    Only confirmed-open and ambiguous (open|filtered) ports are kept on the host - ports
    confirmed closed or filtered are the expected majority and, like tcp_scan's closed
    ports, aren't interesting enough to store. UDP scanning is inherently much slower and
    less certain than tcp_scan: most operating systems rate-limit the ICMP replies this
    relies on to detect closed ports (e.g. Linux defaults to ~1/sec), and many open UDP
    services simply don't respond to an empty probe at all - hence the large, honestly-
    ambiguous open|filtered bucket rather than a false "open" or "closed" verdict.

    Deliberately sequential (no ThreadPoolExecutor), unlike tcp_scan - scapy's sr1() isn't
    thread-safe (see the module docstring's history of that bug), so concurrent probing was
    already serialized behind a lock; running it through a multi-worker executor anyway just
    means ThreadPoolExecutor pre-dequeues up to max_workers tasks that then queue up behind
    that lock with zero throughput benefit. Worse, those pre-dequeued tasks count as
    "running" to the executor, so cancel_futures can't cancel them on Ctrl+C - they still
    have to drain (one at a time, each up to `timeout` long) before Python's
    concurrent.futures.thread atexit hook lets the interpreter fully exit, which measured
    over a minute of apparent hang after a KeyboardInterrupt was already "handled" with
    max_workers=100 against an unresponsive host. A plain loop on the main thread has none
    of that: config.max_workers is intentionally unused here, and Ctrl+C stops promptly
    after the in-flight probe.
    """
    host.udp_open_ports = []
    host.udp_open_or_filtered_ports = []
    ports = list(range(1, config.number_of_ports_to_scan))
    random.shuffle(ports)

    limiter = RateLimiter(config.max_scans_per_second) if config.max_scans_per_second else None

    try:
        for port in tqdm.tqdm(ports, desc=f"UDP scanning {host.ip}", unit="port"):
            if limiter is not None:
                limiter.acquire()
            state = scan_single_port_udp(host.ip, port, timeout)
            if state == UDP_OPEN:
                host.udp_open_ports.append(port)
            elif state == UDP_OPEN_OR_FILTERED:
                host.udp_open_or_filtered_ports.append(port)
    except KeyboardInterrupt:
        print(f"\n[-] UDP scan of {host.ip} interrupted - stopping after the current port.")
        host.udp_open_ports.sort()
        host.udp_open_or_filtered_ports.sort()
        logger.warning(
            "UDP scan of %s interrupted; %d open, %d open|filtered found so far",
            host.ip, len(host.udp_open_ports), len(host.udp_open_or_filtered_ports),
        )
        raise

    host.udp_open_ports.sort()
    host.udp_open_or_filtered_ports.sort()
    host.udp_scanned = True
    logger.info(
        "UDP scan of %s complete: %d open (%s), %d open|filtered",
        host.ip, len(host.udp_open_ports), host.udp_open_ports, len(host.udp_open_or_filtered_ports),
    )
