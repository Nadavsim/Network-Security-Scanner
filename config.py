"""Configuration constants and the mutable scan configuration object."""
from __future__ import annotations

import tomllib
from dataclasses import dataclass

# Network presets
VM_TARGET_RANGE = "192.168.56.0/24"
LIVE_TARGET_RANGE = "192.168.7.0/24"
VM_NETWORK_INTERFACE = "VirtualBox Host-Only Ethernet Adapter"
LIVE_NETWORK_INTERFACE: str | None = None

# Scan defaults
DEFAULT_ARP_TIMEOUT = 2.0
DEFAULT_ARP_VERBOSE = False
DEFAULT_NUMBER_OF_PORTS_TO_SCAN = 6001
DEFAULT_MAX_WORKERS = 100
DEFAULT_MAX_SCANS_PER_SECOND = 20.0  # stealth pacing: caps real connection-attempt rate, not just batch size


@dataclass
class ScanConfig:
    """Mutable scan settings for a single session.

    Replaces the old module-level globals (TARGET_RANGE, NETWORK_INTERFACE, etc.)
    so scan settings are passed explicitly instead of read from shared state.
    """

    target_range: str = LIVE_TARGET_RANGE
    network_interface: str | None = LIVE_NETWORK_INTERFACE
    arp_timeout: float = DEFAULT_ARP_TIMEOUT
    arp_verbose: bool = DEFAULT_ARP_VERBOSE
    number_of_ports_to_scan: int = DEFAULT_NUMBER_OF_PORTS_TO_SCAN
    max_workers: int = DEFAULT_MAX_WORKERS
    max_scans_per_second: float | None = DEFAULT_MAX_SCANS_PER_SECOND  # None = no throttling

    def use_vm_mode(self) -> None:
        self.target_range = VM_TARGET_RANGE
        self.network_interface = VM_NETWORK_INTERFACE

    def use_live_mode(self) -> None:
        self.target_range = LIVE_TARGET_RANGE
        self.network_interface = LIVE_NETWORK_INTERFACE


CONFIG_FILE_PATH = "scan_config.toml"

# target_range/network_interface are deliberately excluded: those stay driven by the
# VM/Live mode menu selection (or --target in non-interactive mode), not the config file,
# so there's one source of truth for network targeting instead of two that can disagree.
_CONFIGURABLE_FIELDS = {
    "arp_timeout",
    "arp_verbose",
    "number_of_ports_to_scan",
    "max_workers",
    "max_scans_per_second",
}


def load_scan_config(path: str = CONFIG_FILE_PATH) -> ScanConfig:
    """Builds a ScanConfig from code defaults, optionally overridden by an on-disk TOML file.

    The file is entirely optional — if it's missing, malformed, or contains unknown keys,
    this falls back to (or keeps) the code defaults rather than crashing a security tool
    over a typo in a settings file. As with --rate, 0 for max_scans_per_second means
    "disable throttling" (translated to None) since TOML has no null literal for it.
    """
    config = ScanConfig()

    try:
        with open(path, "rb") as f:
            raw = tomllib.load(f)
    except FileNotFoundError:
        return config
    except tomllib.TOMLDecodeError as e:
        print(f"[-] Failed to parse {path}: {e}. Using default scan settings.")
        return config

    for key, value in raw.items():
        if key not in _CONFIGURABLE_FIELDS:
            print(f"[-] Ignoring unknown setting '{key}' in {path}.")
            continue
        if key == "max_scans_per_second" and value == 0:
            value = None
        setattr(config, key, value)

    return config
