"""Data structures shared across the scanner."""
from __future__ import annotations

from dataclasses import dataclass, field


@dataclass
class Host:
    ip: str
    mac: str | None = None
    open_ports: list[int] = field(default_factory=list)
    services: dict[int, dict[str, str]] = field(default_factory=dict)
    adaptive_timeout: float = 0.5  # Default fallback until measured
    scanned: bool = False  # True once tcp_scan has run against this host
    guessed_os: str | None = None  # Best-effort TTL heuristic; see network_scanner.guess_os_from_ttl
    udp_open_ports: list[int] = field(default_factory=list)  # Confirmed open (got a UDP reply)
    udp_open_or_filtered_ports: list[int] = field(default_factory=list)  # No reply - ambiguous, see udp_scan
    udp_scanned: bool = False  # True once udp_scan has run against this host

    def __repr__(self) -> str:
        return f"Host({self.ip}, MAC: {self.mac})"
