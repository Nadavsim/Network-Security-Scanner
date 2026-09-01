"""Tests for ScannerApp._scan_host - the shared pipeline step extracted from
handle_tcp_scan/run_single_target so the two entry points can't drift out of
sync. The underlying network calls (calculate_adaptive_timeout, guess_os_from_ttl,
tcp_scan) are all mocked; none of them ever touch a real network here. nmap
availability is also mocked so ScannerApp() construction doesn't depend on
whether nmap happens to be installed on the machine running the tests.
"""
from __future__ import annotations

from unittest.mock import patch

from cli import ScannerApp
from models import Host


def _make_app() -> ScannerApp:
    # setup_logging is mocked too, so constructing a ScannerApp in a test never creates a
    # real scan_<timestamp>.log file on disk as a side effect.
    with patch("cli.is_nmap_available", return_value=True), patch("cli.setup_logging"):
        return ScannerApp()


def test_scan_host_profiles_latency_guesses_os_and_scans():
    app = _make_app()
    host = Host(ip="10.0.0.5")

    with patch("cli.calculate_adaptive_timeout", return_value=0.42) as mock_timeout, \
         patch("cli.guess_os_from_ttl", return_value="Linux/Unix") as mock_os, \
         patch("cli.tcp_scan") as mock_tcp_scan:
        app._scan_host(host)

    mock_timeout.assert_called_once_with("10.0.0.5", app.config)
    mock_os.assert_called_once_with("10.0.0.5", app.config)
    mock_tcp_scan.assert_called_once_with(host, app.config)
    assert host.adaptive_timeout == 0.42
    assert host.guessed_os == "Linux/Unix"


def test_scan_host_handles_no_os_guess(capsys):
    app = _make_app()
    host = Host(ip="10.0.0.6")

    with patch("cli.calculate_adaptive_timeout", return_value=0.5), \
         patch("cli.guess_os_from_ttl", return_value=None), \
         patch("cli.tcp_scan"):
        app._scan_host(host)

    assert host.guessed_os is None
    assert "skipping TTL-based OS guess" in capsys.readouterr().out


def test_scan_host_prints_open_ports_found_by_tcp_scan(capsys):
    app = _make_app()
    host = Host(ip="10.0.0.7")

    def fake_tcp_scan(h, config):
        h.open_ports = [22, 443]
        h.scanned = True

    with patch("cli.calculate_adaptive_timeout", return_value=0.5), \
         patch("cli.guess_os_from_ttl", return_value=None), \
         patch("cli.tcp_scan", side_effect=fake_tcp_scan):
        app._scan_host(host)

    out = capsys.readouterr().out
    assert "Found 2 open ports" in out
    assert "[22, 443]" in out


# ---------- _print_port_table ----------


def test_print_port_table_renders_rows_sorted_by_port(capsys):
    app = _make_app()
    # Deliberately unsorted input - the method must sort by port before rendering.
    app._print_port_table("Test Ports", [(443, "open", "green"), (22, "open", "green")])

    out = capsys.readouterr().out
    assert out.index("22") < out.index("443")


def test_print_port_table_shows_the_state_label_for_each_row(capsys):
    app = _make_app()
    app._print_port_table(
        "Test Ports",
        [(53, "open", "green"), (161, "open|filtered", "yellow")],
    )

    out = capsys.readouterr().out
    assert "open|filtered" in out
    # "open" also appears as a substring of "open|filtered", so count occurrences
    # instead of a plain "in" check to confirm both distinct rows actually rendered.
    assert out.count("open") == 2


def test_print_port_table_prints_nothing_for_empty_rows(capsys):
    app = _make_app()
    app._print_port_table("Test Ports", [])

    assert capsys.readouterr().out == ""
