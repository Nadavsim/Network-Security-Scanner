"""Parallel asyncio-based implementation of TCP port scanning, kept side-by-side with
network_scanner.py's ThreadPoolExecutor-based tcp_scan for benchmarking.

network_scanner.tcp_scan uses concurrent.futures.Future/as_completed, which are backed
by real OS threads under the hood. asyncio.Future/as_completed share those names but run
on a single thread's event loop via cooperative coroutine suspension instead — this module
is a genuinely separate implementation, not a thin wrapper over the thread-based one.

Not wired into cli.py/main.py yet: this exists to be benchmarked against tcp_scan, not to
replace it.

Fixed bug, found while benchmarking: with the default 0.2s per-port timeout, ~135+
concurrent connection attempts (ordinary scale — well within default max_workers, no
throttling needed to trigger it) could produce false negatives on Windows: a genuinely open
port times out and gets reported closed. Confirmed via instrumentation to be a real
asyncio.TimeoutError, not a swallowed exception — Windows' default ProactorEventLoop (IOCP)
doesn't reliably dispatch every pending connection-completion notification within 0.2s once
~100+ connects are in flight at once, even to loopback. Bisecting the timeout showed 0.2s
fails consistently at this concurrency, 0.5s+ is reliable. network_scanner.tcp_scan
(thread-based) doesn't show this, since each worker gets genuine OS thread scheduling
instead of competing for one event loop.

Fix: scan_single_port_async floors its effective timeout at MIN_TIMEOUT (0.5s) regardless of
what's passed in, trading a slightly slower per-port timeout on genuinely unresponsive hosts
for reliability at realistic concurrency. This is real, useful data for the "which is better
for which case" question this module exists to answer: asyncio's single-event-loop model has
a genuine floor on how short a per-operation timeout can be under concurrent load — not a
one-off bug, but a characteristic worth knowing before defaulting to a short timeout at scale.
"""
from __future__ import annotations

import asyncio
import random
import time

import tqdm.asyncio

from config import ScanConfig
from models import Host

MIN_TIMEOUT = 0.5  # floor: shorter timeouts are unreliable at ordinary concurrency, see module docstring


class AsyncRateLimiter:
    """Async sibling of network_scanner.RateLimiter: same next-slot pacing logic, but
    gates coroutines via asyncio.Lock/asyncio.sleep instead of threading.Lock/time.sleep,
    so a waiting caller suspends without blocking the event loop's other coroutines.
    """

    def __init__(self, max_per_second: float):
        self._min_interval = 1.0 / max_per_second
        self._lock = asyncio.Lock()
        self._next_slot = time.monotonic()

    async def acquire(self) -> None:
        async with self._lock:
            now = time.monotonic()
            wait = self._next_slot - now
            self._next_slot = max(self._next_slot, now) + self._min_interval
        if wait > 0:
            await asyncio.sleep(wait)


async def scan_single_port_async(ip: str, port: int, timeout: float = 0.2) -> int | None:
    """Async sibling of network_scanner.scan_single_port: same open-or-None semantics.

    Unlike a raw socket's connect_ex (which returns an error code), asyncio.open_connection
    raises on failure (e.g. ConnectionRefusedError), so failure is caught via except OSError
    instead of an == 0 check. The effective timeout is floored at MIN_TIMEOUT regardless of
    what's passed in - see the module docstring for why a short timeout is unreliable here.
    """
    effective_timeout = max(timeout, MIN_TIMEOUT)
    try:
        _, writer = await asyncio.wait_for(asyncio.open_connection(ip, port), timeout=effective_timeout)
    except OSError:
        return None

    writer.close()
    try:
        await writer.wait_closed()
    except OSError:
        pass
    return port


async def tcp_scan_async(host: Host, config: ScanConfig) -> None:
    """Async sibling of network_scanner.tcp_scan: same signature, same result shape on
    host (open_ports, scanned), same port-pool-shuffle and rate-limiting semantics —
    just driven by asyncio tasks instead of a ThreadPoolExecutor.
    """
    host.open_ports = []
    ports = list(range(1, config.number_of_ports_to_scan))
    random.shuffle(ports)

    limiter = AsyncRateLimiter(config.max_scans_per_second) if config.max_scans_per_second else None
    semaphore = asyncio.Semaphore(config.max_workers)

    async def scan_with_pacing(port: int) -> int | None:
        async with semaphore:
            if limiter is not None:
                await limiter.acquire()
            return await scan_single_port_async(host.ip, port, host.adaptive_timeout)

    tasks = [asyncio.create_task(scan_with_pacing(port)) for port in ports]
    for coro in tqdm.asyncio.tqdm.as_completed(
        tasks, total=len(tasks), desc=f"Scanning {host.ip} (async)", unit="port"
    ):
        open_port = await coro
        if open_port is not None:
            host.open_ports.append(open_port)

    host.open_ports.sort()
    host.scanned = True
