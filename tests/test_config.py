"""Tests for config.load_scan_config: an optional, on-disk TOML override layer
on top of ScanConfig's code defaults.
"""
from __future__ import annotations

from config import ScanConfig, load_scan_config


def test_missing_file_returns_defaults(tmp_path):
    result = load_scan_config(str(tmp_path / "does_not_exist.toml"))
    assert result == ScanConfig()


def test_valid_overrides_are_applied(tmp_path):
    path = tmp_path / "scan_config.toml"
    path.write_text(
        "arp_timeout = 5.0\n"
        "number_of_ports_to_scan = 100\n"
        "max_workers = 10\n",
        encoding="utf-8",
    )
    result = load_scan_config(str(path))
    assert result.arp_timeout == 5.0
    assert result.number_of_ports_to_scan == 100
    assert result.max_workers == 10
    # everything else stays at the code default
    assert result.arp_verbose == ScanConfig().arp_verbose
    assert result.max_scans_per_second == ScanConfig().max_scans_per_second


def test_zero_max_scans_per_second_means_disabled(tmp_path):
    path = tmp_path / "scan_config.toml"
    path.write_text("max_scans_per_second = 0\n", encoding="utf-8")
    result = load_scan_config(str(path))
    assert result.max_scans_per_second is None


def test_nonzero_max_scans_per_second_is_applied_as_is(tmp_path):
    path = tmp_path / "scan_config.toml"
    path.write_text("max_scans_per_second = 50\n", encoding="utf-8")
    result = load_scan_config(str(path))
    assert result.max_scans_per_second == 50


def test_target_range_and_network_interface_are_not_configurable(tmp_path):
    # These belong to the VM/Live mode menu / --target, not the config file.
    path = tmp_path / "scan_config.toml"
    path.write_text(
        'target_range = "10.0.0.0/24"\n'
        'network_interface = "eth9"\n',
        encoding="utf-8",
    )
    result = load_scan_config(str(path))
    assert result.target_range == ScanConfig().target_range
    assert result.network_interface == ScanConfig().network_interface


def test_unknown_key_is_ignored_but_other_keys_still_apply(tmp_path, capsys):
    path = tmp_path / "scan_config.toml"
    path.write_text(
        'bogus_setting = "oops"\n'
        "arp_timeout = 3.0\n",
        encoding="utf-8",
    )
    result = load_scan_config(str(path))
    assert result.arp_timeout == 3.0
    assert "bogus_setting" in capsys.readouterr().out


def test_malformed_toml_falls_back_to_defaults(tmp_path, capsys):
    path = tmp_path / "scan_config.toml"
    path.write_text("this is not [ valid toml", encoding="utf-8")
    result = load_scan_config(str(path))
    assert result == ScanConfig()
    assert "Failed to parse" in capsys.readouterr().out


def test_empty_file_returns_defaults(tmp_path):
    path = tmp_path / "scan_config.toml"
    path.write_text("", encoding="utf-8")
    result = load_scan_config(str(path))
    assert result == ScanConfig()
