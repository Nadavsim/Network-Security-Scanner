"""Tests for export.host_to_dict / export.export_hosts_to_json, with a focus on
edge cases: never-scanned hosts, empty lists, ordering, JSON's int-key coercion,
write failures, and non-ASCII/special characters in banner text.
"""
from __future__ import annotations

import json
from datetime import datetime

import pytest

from export import export_hosts_to_json, host_to_dict
from models import Host


def test_host_to_dict_full():
    host = Host(
        ip="192.168.1.5",
        mac="aa:bb:cc:dd:ee:ff",
        open_ports=[22, 80],
        services={
            22: {
                "state": "open", "service": "ssh", "product": "OpenSSH",
                "version": "8.2", "extra_info": "", "cves": ["CVE-2021-1"],
            }
        },
        scanned=True,
        guessed_os="Linux/Unix",
        udp_open_ports=[53],
        udp_open_or_filtered_ports=[161, 500],
        udp_scanned=True,
    )
    assert host_to_dict(host) == {
        "ip": "192.168.1.5",
        "mac": "aa:bb:cc:dd:ee:ff",
        "scanned": True,
        "guessed_os": "Linux/Unix",
        "open_ports": [22, 80],
        "services": {
            22: {
                "state": "open", "service": "ssh", "product": "OpenSSH",
                "version": "8.2", "extra_info": "", "cves": ["CVE-2021-1"],
            }
        },
        "udp_scanned": True,
        "udp_open_ports": [53],
        "udp_open_or_filtered_ports": [161, 500],
    }


def test_host_to_dict_never_scanned_defaults():
    host = Host(ip="192.168.1.6")
    assert host_to_dict(host) == {
        "ip": "192.168.1.6",
        "mac": None,
        "scanned": False,
        "guessed_os": None,
        "open_ports": [],
        "services": {},
        "udp_scanned": False,
        "udp_open_ports": [],
        "udp_open_or_filtered_ports": [],
    }


def test_export_round_trip_matches_host_to_dict(tmp_path):
    host = Host(
        ip="10.0.0.1",
        mac="11:22:33:44:55:66",
        open_ports=[443],
        services={443: {
            "state": "open", "service": "https", "product": "nginx",
            "version": "1.18", "extra_info": "", "cves": [],
        }},
        scanned=True,
    )
    filepath = tmp_path / "out.json"

    export_hosts_to_json([host], str(filepath))

    with open(filepath, encoding="utf-8") as f:
        data = json.load(f)

    assert data["host_count"] == 1
    # host_to_dict's int port key becomes a string key after the JSON round-trip
    expected = host_to_dict(host)
    expected["services"] = {str(k): v for k, v in expected["services"].items()}
    assert data["hosts"] == [expected]

    parsed = datetime.fromisoformat(data["generated_at"])
    assert parsed.tzinfo is not None


def test_export_empty_host_list(tmp_path):
    filepath = tmp_path / "empty.json"
    export_hosts_to_json([], str(filepath))
    with open(filepath, encoding="utf-8") as f:
        data = json.load(f)
    assert data["host_count"] == 0
    assert data["hosts"] == []


def test_export_preserves_host_order(tmp_path):
    hosts = [Host(ip=f"10.0.0.{i}") for i in range(1, 4)]
    filepath = tmp_path / "ordered.json"
    export_hosts_to_json(hosts, str(filepath))
    with open(filepath, encoding="utf-8") as f:
        data = json.load(f)
    assert [h["ip"] for h in data["hosts"]] == ["10.0.0.1", "10.0.0.2", "10.0.0.3"]


def test_export_int_port_keys_become_string_keys_in_json(tmp_path):
    host = Host(ip="10.0.0.5", open_ports=[22], services={22: {"state": "open"}}, scanned=True)
    filepath = tmp_path / "ports.json"
    export_hosts_to_json([host], str(filepath))
    with open(filepath, encoding="utf-8") as f:
        data = json.load(f)
    services = data["hosts"][0]["services"]
    assert "22" in services
    assert 22 not in services  # JSON object keys are always strings, never ints


def test_export_raises_when_parent_directory_missing(tmp_path):
    bad_path = tmp_path / "nonexistent_dir" / "out.json"
    host = Host(ip="10.0.0.9")
    with pytest.raises(OSError):
        export_hosts_to_json([host], str(bad_path))


def test_export_handles_special_and_non_ascii_characters(tmp_path):
    tricky_banner = 'café "quoted" \\backslash �'
    host = Host(
        ip="10.0.0.10",
        open_ports=[21],
        services={21: {
            "state": "open", "service": "ftp", "product": "",
            "version": "", "extra_info": tricky_banner, "cves": [],
        }},
        scanned=True,
    )
    filepath = tmp_path / "special.json"
    export_hosts_to_json([host], str(filepath))
    with open(filepath, encoding="utf-8") as f:
        data = json.load(f)
    assert data["hosts"][0]["services"]["21"]["extra_info"] == tricky_banner
