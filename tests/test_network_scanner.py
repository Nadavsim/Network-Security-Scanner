"""Tests for scan_single_port, calculate_adaptive_timeout, guess_os_from_ttl, and
scan_single_port_udp.

All are exercised entirely through mocks: scan_single_port never opens a real socket,
calculate_adaptive_timeout never sends a real ARP packet, and guess_os_from_ttl/
scan_single_port_udp never send real ICMP/UDP packets (all of which would need admin/root
and a real network). This matches the project's existing split of concerns —
network_scanner.send_arp_request is a thin wrapper for exactly this reason.
"""
from __future__ import annotations

from unittest.mock import MagicMock, patch

import pytest
from scapy.layers.inet import ICMP, IP, UDP

from models import Host
from network_scanner import (
    RateLimiter,
    calculate_adaptive_timeout,
    guess_os_from_ttl,
    scan_single_port,
    scan_single_port_udp,
    tcp_scan,
    udp_scan,
)

# ---------- scan_single_port ----------


def test_scan_single_port_open():
    mock_sock = MagicMock()
    mock_sock.connect_ex.return_value = 0
    with patch("network_scanner.socket.socket", return_value=mock_sock):
        result = scan_single_port("127.0.0.1", 80, timeout=0.1)
    assert result == 80
    mock_sock.close.assert_called_once()


def test_scan_single_port_closed():
    mock_sock = MagicMock()
    mock_sock.connect_ex.return_value = 111  # ECONNREFUSED
    with patch("network_scanner.socket.socket", return_value=mock_sock):
        result = scan_single_port("127.0.0.1", 81, timeout=0.1)
    assert result is None
    mock_sock.close.assert_called_once()


def test_scan_single_port_oserror_on_connect_is_swallowed():
    mock_sock = MagicMock()
    mock_sock.connect_ex.side_effect = OSError("boom")
    with patch("network_scanner.socket.socket", return_value=mock_sock):
        result = scan_single_port("127.0.0.1", 82, timeout=0.1)
    assert result is None
    mock_sock.close.assert_called_once()  # still cleaned up despite the error


def test_scan_single_port_oserror_on_socket_creation_is_swallowed():
    with patch("network_scanner.socket.socket", side_effect=OSError("boom")):
        result = scan_single_port("127.0.0.1", 83, timeout=0.1)
    assert result is None


def test_scan_single_port_applies_given_timeout():
    mock_sock = MagicMock()
    mock_sock.connect_ex.return_value = 0
    with patch("network_scanner.socket.socket", return_value=mock_sock):
        scan_single_port("127.0.0.1", 80, timeout=0.37)
    mock_sock.settimeout.assert_called_once_with(0.37)


# ---------- calculate_adaptive_timeout ----------


def test_calculate_adaptive_timeout_no_answers_falls_back_to_default(scan_config):
    with patch("network_scanner.send_arp_request", return_value=([], [])):
        result = calculate_adaptive_timeout("192.168.1.1", scan_config, probes=5)
    assert result == 0.5


def test_calculate_adaptive_timeout_uniform_rtt(scan_config):
    # 5 probes, each RTT exactly 0.1s (zero jitter) -> avg=0.1, jitter=0 -> 0.1+0+0.05=0.15
    timestamps = []
    for _ in range(5):
        timestamps.extend([0.0, 0.1])
    with patch("network_scanner.send_arp_request", return_value=(["answered"], [])), \
         patch("network_scanner.time.time", side_effect=timestamps):
        result = calculate_adaptive_timeout("192.168.1.1", scan_config, probes=5)
    assert result == pytest.approx(0.15)


def test_calculate_adaptive_timeout_with_jitter(scan_config):
    # 2 probes: RTT 0.1 and 0.3 -> avg=0.2, pstdev=0.1 -> 0.2 + 0.3 + 0.05 = 0.55
    timestamps = [0.0, 0.1, 0.0, 0.3]
    with patch("network_scanner.send_arp_request", return_value=(["answered"], [])), \
         patch("network_scanner.time.time", side_effect=timestamps):
        result = calculate_adaptive_timeout("192.168.1.1", scan_config, probes=2)
    assert result == pytest.approx(0.55)


def test_calculate_adaptive_timeout_clamped_to_max(scan_config):
    # 2 probes, RTT 2.0s each -> avg=2.0, jitter=0 -> 2.05 unclamped, but max is 1.5
    timestamps = [0.0, 2.0, 0.0, 2.0]
    with patch("network_scanner.send_arp_request", return_value=(["answered"], [])), \
         patch("network_scanner.time.time", side_effect=timestamps):
        result = calculate_adaptive_timeout("192.168.1.1", scan_config, probes=2)
    assert result == 1.5


def test_calculate_adaptive_timeout_floor_at_min(scan_config):
    # 2 probes, RTT 0.0s each (instantaneous) -> avg=0, jitter=0 -> exactly the 0.05 floor
    timestamps = [0.0, 0.0, 0.0, 0.0]
    with patch("network_scanner.send_arp_request", return_value=(["answered"], [])), \
         patch("network_scanner.time.time", side_effect=timestamps):
        result = calculate_adaptive_timeout("192.168.1.1", scan_config, probes=2)
    assert result == pytest.approx(0.05)


def test_calculate_adaptive_timeout_ignores_unanswered_probes(scan_config):
    # 3 probes: RTT 0.2 (answered), a huge 5.0s gap (unanswered - must NOT count),
    # RTT 0.4 (answered). If the unanswered probe leaked into the average, jitter would
    # blow up and the result would clamp to 1.5 instead of the correct 0.65.
    send_arp_side_effect = [(["answered"], []), ([], []), (["answered"], [])]
    timestamps = [0.0, 0.2, 0.0, 5.0, 0.0, 0.4]
    with patch("network_scanner.send_arp_request", side_effect=send_arp_side_effect), \
         patch("network_scanner.time.time", side_effect=timestamps):
        result = calculate_adaptive_timeout("192.168.1.1", scan_config, probes=3)
    assert result == pytest.approx(0.65)


# ---------- RateLimiter ----------


def test_rate_limiter_min_interval_derived_from_rate():
    limiter = RateLimiter(max_per_second=10)
    assert limiter._min_interval == pytest.approx(0.1)


def test_rate_limiter_does_not_sleep_when_slot_is_already_open():
    with patch("network_scanner.time.monotonic", return_value=100.0), \
         patch("network_scanner.time.sleep") as mock_sleep:
        limiter = RateLimiter(max_per_second=10)
        limiter.acquire()
    mock_sleep.assert_not_called()


def test_rate_limiter_sleeps_for_exactly_the_remaining_interval():
    # monotonic() calls: 1 in __init__, then 1 per acquire()
    with patch("network_scanner.time.monotonic", side_effect=[100.0, 100.0, 100.01]), \
         patch("network_scanner.time.sleep") as mock_sleep:
        limiter = RateLimiter(max_per_second=10)  # min_interval = 0.1
        limiter.acquire()  # now=100.0, slot=100.0 -> no wait; next slot becomes 100.1
        limiter.acquire()  # now=100.01, slot=100.1 -> wait 0.09
    mock_sleep.assert_called_once()
    assert mock_sleep.call_args[0][0] == pytest.approx(0.09)


def test_rate_limiter_does_not_accumulate_lag_after_a_long_gap():
    # A caller that pauses well past the interval shouldn't be penalized on its next call.
    with patch("network_scanner.time.monotonic", side_effect=[100.0, 100.0, 105.0]), \
         patch("network_scanner.time.sleep") as mock_sleep:
        limiter = RateLimiter(max_per_second=10)  # min_interval = 0.1
        limiter.acquire()  # now=100.0 -> no wait
        limiter.acquire()  # now=105.0, way past the 100.1 slot -> no wait either
    mock_sleep.assert_not_called()


# ---------- guess_os_from_ttl ----------


def test_guess_os_from_ttl_no_reply_returns_none(scan_config):
    with patch("network_scanner.sr1", return_value=None):
        result = guess_os_from_ttl("192.168.1.1", scan_config)
    assert result is None


@pytest.mark.parametrize(
    "ttl,expected",
    [
        (64, "Linux/Unix"),       # exact baseline
        (57, "Linux/Unix"),       # a few hops of decrement from a Linux host
        (65, "Windows"),          # just past the Linux baseline -> rounds up
        (128, "Windows"),         # exact baseline
        (120, "Windows"),         # a few hops of decrement from a Windows host
        (200, "Network device (e.g. Cisco)"),
        (255, "Network device (e.g. Cisco)"),  # max possible TTL
    ],
)
def test_guess_os_from_ttl_baselines(scan_config, ttl, expected):
    fake_reply = IP(ttl=ttl) / ICMP()
    with patch("network_scanner.sr1", return_value=fake_reply):
        result = guess_os_from_ttl("192.168.1.1", scan_config)
    assert result == expected


def test_guess_os_from_ttl_passes_dst_and_timeout(scan_config):
    with patch("network_scanner.sr1", return_value=None) as mock_sr1:
        guess_os_from_ttl("192.168.1.1", scan_config, timeout=3.0)

    sent_packet = mock_sr1.call_args[0][0]
    assert sent_packet[IP].dst == "192.168.1.1"
    assert mock_sr1.call_args.kwargs["timeout"] == 3.0


# ---------- scan_single_port_udp ----------


def test_scan_single_port_udp_no_reply_is_open_or_filtered():
    with patch("network_scanner.sr1", return_value=None):
        result = scan_single_port_udp("192.168.1.1", 53)
    assert result == "open|filtered"


def test_scan_single_port_udp_icmp_port_unreachable_is_closed():
    fake_reply = IP() / ICMP(type=3, code=3)
    with patch("network_scanner.sr1", return_value=fake_reply):
        result = scan_single_port_udp("192.168.1.1", 53)
    assert result == "closed"


@pytest.mark.parametrize("code", [1, 2, 9, 10, 13])
def test_scan_single_port_udp_other_icmp_unreachable_codes_are_filtered(code):
    fake_reply = IP() / ICMP(type=3, code=code)
    with patch("network_scanner.sr1", return_value=fake_reply):
        result = scan_single_port_udp("192.168.1.1", 53)
    assert result == "filtered"


def test_scan_single_port_udp_actual_reply_is_open():
    fake_reply = IP() / UDP() / b"some response data"
    with patch("network_scanner.sr1", return_value=fake_reply):
        result = scan_single_port_udp("192.168.1.1", 53)
    assert result == "open"


def test_scan_single_port_udp_passes_dst_port_and_timeout():
    with patch("network_scanner.sr1", return_value=None) as mock_sr1:
        scan_single_port_udp("192.168.1.1", 161, timeout=2.5)

    sent_packet = mock_sr1.call_args[0][0]
    assert sent_packet[IP].dst == "192.168.1.1"
    assert sent_packet[UDP].dport == 161
    assert mock_sr1.call_args.kwargs["timeout"] == 2.5
    # no iface kwarg: sr1 is Layer 3 and scapy warns iface is a no-op there (see docstring)
    assert "iface" not in mock_sr1.call_args.kwargs


# ---------- Ctrl+C handling ----------


def test_tcp_scan_on_keyboard_interrupt_cancels_pending_and_reraises(scan_config):
    host = Host(ip="10.0.0.1", adaptive_timeout=0.1)
    scan_config.number_of_ports_to_scan = 11
    scan_config.max_scans_per_second = None

    mock_executor = MagicMock()
    with patch("network_scanner.ThreadPoolExecutor", return_value=mock_executor), \
         patch("network_scanner.as_completed", side_effect=KeyboardInterrupt):
        with pytest.raises(KeyboardInterrupt):
            tcp_scan(host, scan_config)

    # wait=False + cancel_futures=True: default shutdown() would block until every
    # already-submitted probe drains, which is exactly the hang this is meant to avoid.
    mock_executor.shutdown.assert_called_once_with(wait=False, cancel_futures=True)
    assert host.scanned is False


def test_udp_scan_on_keyboard_interrupt_prints_message_and_reraises(scan_config, capsys):
    # A plain, unhandled KeyboardInterrupt would also satisfy pytest.raises() and leave
    # udp_scanned False on its own - the print is the one thing that only happens if the
    # except block actually ran, so it's what actually distinguishes "handled" from
    # "propagated untouched".
    host = Host(ip="10.0.0.1")
    scan_config.number_of_ports_to_scan = 11
    scan_config.max_scans_per_second = None

    with patch("network_scanner.scan_single_port_udp", side_effect=KeyboardInterrupt):
        with pytest.raises(KeyboardInterrupt):
            udp_scan(host, scan_config)

    assert host.udp_scanned is False
    assert "interrupted" in capsys.readouterr().out


def test_udp_scan_sorts_partial_results_before_reraising(scan_config):
    # Ports are processed in reverse (4, 3, 2, ...) via the mocked shuffle, so the
    # append order is deliberately NOT sorted - if the except block's sort() calls didn't
    # run, host.udp_open_ports would still be [4, 3, 2] (insertion order), not [2, 3, 4].
    host = Host(ip="10.0.0.1")
    scan_config.number_of_ports_to_scan = 5  # ports 1..4
    scan_config.max_scans_per_second = None

    with patch("network_scanner.random.shuffle", side_effect=lambda lst: lst.reverse()), \
         patch(
             "network_scanner.scan_single_port_udp",
             side_effect=["open", "open", "open", KeyboardInterrupt],
         ):
        with pytest.raises(KeyboardInterrupt):
            udp_scan(host, scan_config)

    assert host.udp_open_ports == [2, 3, 4]
