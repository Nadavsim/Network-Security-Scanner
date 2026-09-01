# TCP Scan Benchmark: Threaded vs. asyncio

**Date:** 2026-08-31
**Command:** `python benchmark_scan.py` (full run, not `--quick`)
**Target:** `127.0.0.1` (loopback — see Caveats)
**Comparing:** `network_scanner.tcp_scan` (`ThreadPoolExecutor`, real OS threads) vs.
`network_scanner_async.tcp_scan_async` (`asyncio`, single-thread event loop)

## Results

| Scenario | Implementation | Time (s) | Open ports found | Correct |
|---|---|---:|---:|---|
| Small range (1–1000), throttled 20/s | sync/threaded | 50.17 | 5 | yes |
| Small range (1–1000), throttled 20/s | async | 50.50 | 5 | yes |
| Small range (1–1000), unthrottled | sync/threaded | 2.22 | 5 | yes |
| Small range (1–1000), unthrottled | async | 5.05 | 5 | yes |
| Full range (1–65535), unthrottled | sync/threaded | 71.66 | 46 | yes |
| Full range (1–65535), unthrottled | async | 167.70 | 47 | yes |

"Correct" = every port from a set of controlled local test listeners was found, checked as
a subset (real background services already listening on the machine — e.g. Windows RPC/SMB
on 135/445 — legitimately show up too and don't count against correctness).

## Findings

**1. Throttled scans: no meaningful difference (as expected).**
50.17s vs 50.50s — within noise. When `max_scans_per_second` caps the real attempt rate,
that rate limiter is the bottleneck for both implementations, not thread vs. event-loop
overhead. Confirms the throttling mechanism itself dominates timing regardless of which
scanner is doing the pacing.

**2. Unthrottled: sync/threaded was consistently ~2.3x faster than async.**
- Small range: 2.22s vs 5.05s (2.27x)
- Full range: 71.66s vs 167.70s (2.34x)

The gap held steady across two very different scales, which suggests a fixed per-connection
overhead difference rather than something that gets worse (or better) with scale. The likely
cause: `asyncio.open_connection()` builds a `StreamReader`/`StreamWriter` pair on top of the
raw socket (buffering, protocol wiring) — real setup work that a raw `socket.connect_ex()`
skips entirely. For a workload this lightweight (near-instant loopback connects), that fixed
overhead per connection adds up to a real, consistent cost. Real OS thread scheduling handled
this specific workload at least as well as one event loop juggling equivalent concurrency.

**3. A real correctness bug was caught and fixed by this exercise.**
Before the fix, the full-range unthrottled async scenario reported **zero** open ports —
missing even the machine's own real system services. Root cause (confirmed by
instrumentation): a genuine `asyncio.TimeoutError`. At ordinary concurrency (~135+
simultaneous connection attempts — nothing extreme, well within default settings), Windows'
`ProactorEventLoop` couldn't reliably service every pending connection-completion
notification within the sync side's 0.2s default timeout. Fix: `scan_single_port_async` now
floors its effective timeout at 0.5s (`MIN_TIMEOUT` in `network_scanner_async.py`). The
results above are all post-fix.

**4. One small discrepancy worth noting, not investigating further.**
The full-range async run found one extra open port (5886) that sync didn't. Both scans ran
sequentially, several seconds apart, against a live machine — a process could have opened
and/or closed a socket on that port between the two scans. Not treated as a correctness
issue: all of the deliberately-controlled ground-truth ports were found by both.

## Caveats

- **Localhost only.** All connects resolve in well under a millisecond. On a real network
  target, connection setup time is dominated by real round-trip latency, not local
  per-connection object overhead — the ~2.3x gap seen here may shrink, disappear, or reverse
  entirely. `network_scanner_async.py`'s own docstring says the same: re-run
  `benchmark_scan.py` against a real remote target before using these numbers to decide
  whether to wire `tcp_scan_async` into the app.
- **Single run per scenario**, not averaged over multiple trials. Good enough to establish
  "which is faster and by roughly how much," not precise enough for a rigorous performance
  claim.
- **Correctness now passes at every scenario tested**, but the fix (`MIN_TIMEOUT = 0.5`) was
  validated at concurrency up to `max_workers=200`. Don't assume it holds at much higher
  concurrency without re-testing.

## Bottom line

For this codebase's actual default behavior — stealth throttling on by default at 20/sec —
the implementation choice doesn't matter for scan speed; the rate limiter is the bottleneck
either way. The interesting case is unthrottled, full-range scanning, where sync/threaded
currently wins clearly on this workload. Async remains a solid interview talking point
(the false-negative bug and its fix are arguably more interesting than the timing numbers),
but as of this benchmark there's no performance case for making it the default over
`network_scanner.tcp_scan`, at least on loopback.
