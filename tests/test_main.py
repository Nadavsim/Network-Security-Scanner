"""Tests for main.is_valid_ipv4 and main()'s top-level KeyboardInterrupt handling.

is_valid_ipv4 exists to reject a malformed --target before it ever reaches
network_scanner/scapy, which previously crashed with a raw traceback (a scapy internal
doing DNS resolution via socket.getaddrinfo) on anything that wasn't a real IPv4 address.
"""
from __future__ import annotations

from unittest.mock import patch

import pytest

import main
from main import is_valid_ipv4


@pytest.mark.parametrize(
    "value",
    ["192.168.1.1", "0.0.0.0", "255.255.255.255", "127.0.0.1", "10.0.0.1"],
)
def test_is_valid_ipv4_accepts_real_ipv4_addresses(value):
    assert is_valid_ipv4(value) is True


@pytest.mark.parametrize(
    "value",
    [
        "",
        "not-an-ip",
        "example.com",
        "999.1.1.1",       # octet out of range
        "1.2.3",           # too few octets
        "1.2.3.4.5",       # too many octets
        "::1",             # IPv6
        "2001:db8::1",     # IPv6
        "192.168.1.1 ",    # trailing whitespace
        " 192.168.1.1",    # leading whitespace
    ],
)
def test_is_valid_ipv4_rejects_everything_else(value):
    assert is_valid_ipv4(value) is False


def test_main_catches_keyboard_interrupt_cleanly(capsys, monkeypatch):
    monkeypatch.setattr("sys.argv", ["main.py", "--target", "127.0.0.1"])
    with patch("main.ScannerApp") as mock_app_class:
        mock_app_class.return_value.run_single_target.side_effect = KeyboardInterrupt()
        main.main()  # must not raise or print a traceback

    assert "Interrupted by user" in capsys.readouterr().out
