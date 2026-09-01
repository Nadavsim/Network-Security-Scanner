"""Tests for the asyncio-based parallel scanner (network_scanner_async.py).

Mirrors the scope/rigor of tests/test_network_scanner.py exactly: unit-test the
per-port primitive (scan_single_port_async, sibling of scan_single_port) and the
pacing gate (AsyncRateLimiter, sibling of RateLimiter). tcp_scan_async itself is
deliberately NOT unit-tested here, for the same reason network_scanner.tcp_scan
isn't: it needs a real multi-port network scan, which is slow/flaky for a unit
suite. All tests run via asyncio.run() in plain sync test functions, so no new
test dependency (e.g. pytest-asyncio) is needed.
"""
from __future__ import annotations

import asyncio
from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from network_scanner_async import AsyncRateLimiter, scan_single_port_async

# ---------- scan_single_port_async ----------


def test_scan_single_port_async_open():
    # StreamWriter.close() is sync, wait_closed() is async - mock them precisely so
    # unittest.mock doesn't warn about an unawaited coroutine from a wrong-shaped mock.
    mock_writer = MagicMock()
    mock_writer.wait_closed = AsyncMock()
    with patch(
        "network_scanner_async.asyncio.open_connection",
        new=AsyncMock(return_value=(MagicMock(), mock_writer)),
    ):
        result = asyncio.run(scan_single_port_async("127.0.0.1", 80, timeout=0.1))
    assert result == 80
    mock_writer.close.assert_called_once()
    mock_writer.wait_closed.assert_called_once()


def test_scan_single_port_async_connection_refused():
    with patch(
        "network_scanner_async.asyncio.open_connection",
        new=AsyncMock(side_effect=ConnectionRefusedError()),
    ):
        result = asyncio.run(scan_single_port_async("127.0.0.1", 81, timeout=0.1))
    assert result is None


def test_scan_single_port_async_real_timeout_returns_none_promptly():
    # A connection that never resolves should be cut off by wait_for's timeout,
    # not hang for the full sleep duration.
    async def never_connects(*_args, **_kwargs):
        await asyncio.sleep(10)
        raise AssertionError("should have been cancelled by wait_for's timeout")

    async def run():
        with patch("network_scanner_async.asyncio.open_connection", new=never_connects):
            start = asyncio.get_event_loop().time()
            result = await scan_single_port_async("127.0.0.1", 82, timeout=0.05)
            elapsed = asyncio.get_event_loop().time() - start
        return result, elapsed

    result, elapsed = asyncio.run(run())
    assert result is None
    # timeout=0.05 is below MIN_TIMEOUT, so the real cutoff is ~MIN_TIMEOUT (0.5s), not 10s
    assert elapsed < 2.0


def test_scan_single_port_async_applies_given_timeout_when_above_the_floor():
    with patch("network_scanner_async.asyncio.wait_for", new=AsyncMock(side_effect=OSError())) as mock_wait_for, \
         patch("network_scanner_async.asyncio.open_connection", new=AsyncMock()):
        asyncio.run(scan_single_port_async("127.0.0.1", 80, timeout=0.8))
    assert mock_wait_for.call_args.kwargs["timeout"] == 0.8


def test_scan_single_port_async_floors_timeout_below_min_timeout():
    # A short timeout (e.g. the sync side's default of 0.2s) is unreliable at ordinary
    # concurrency on this event loop - see MIN_TIMEOUT / the module docstring - so it must
    # be raised to MIN_TIMEOUT rather than passed through as-is.
    with patch("network_scanner_async.asyncio.wait_for", new=AsyncMock(side_effect=OSError())) as mock_wait_for, \
         patch("network_scanner_async.asyncio.open_connection", new=AsyncMock()):
        asyncio.run(scan_single_port_async("127.0.0.1", 80, timeout=0.05))
    assert mock_wait_for.call_args.kwargs["timeout"] == pytest.approx(0.5)


# ---------- AsyncRateLimiter ----------


def test_async_rate_limiter_min_interval_derived_from_rate():
    limiter = AsyncRateLimiter(max_per_second=10)
    assert limiter._min_interval == pytest.approx(0.1)


def test_async_rate_limiter_does_not_sleep_when_slot_is_already_open():
    async def run():
        with patch("network_scanner_async.time.monotonic", return_value=100.0), \
             patch("network_scanner_async.asyncio.sleep", new=AsyncMock()) as mock_sleep:
            limiter = AsyncRateLimiter(max_per_second=10)
            await limiter.acquire()
        return mock_sleep

    mock_sleep = asyncio.run(run())
    mock_sleep.assert_not_called()


def test_async_rate_limiter_sleeps_for_exactly_the_remaining_interval():
    async def run():
        with patch("network_scanner_async.time.monotonic", side_effect=[100.0, 100.0, 100.01]), \
             patch("network_scanner_async.asyncio.sleep", new=AsyncMock()) as mock_sleep:
            limiter = AsyncRateLimiter(max_per_second=10)  # min_interval = 0.1
            await limiter.acquire()  # now=100.0, slot=100.0 -> no wait; next slot -> 100.1
            await limiter.acquire()  # now=100.01, slot=100.1 -> wait 0.09
        return mock_sleep

    mock_sleep = asyncio.run(run())
    mock_sleep.assert_called_once()
    assert mock_sleep.call_args[0][0] == pytest.approx(0.09)


def test_async_rate_limiter_does_not_accumulate_lag_after_a_long_gap():
    async def run():
        with patch("network_scanner_async.time.monotonic", side_effect=[100.0, 100.0, 105.0]), \
             patch("network_scanner_async.asyncio.sleep", new=AsyncMock()) as mock_sleep:
            limiter = AsyncRateLimiter(max_per_second=10)  # min_interval = 0.1
            await limiter.acquire()  # now=100.0 -> no wait
            await limiter.acquire()  # now=105.0, way past the 100.1 slot -> no wait either
        return mock_sleep

    mock_sleep = asyncio.run(run())
    mock_sleep.assert_not_called()
