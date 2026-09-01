"""JSON export of scan results."""
from __future__ import annotations

import json
import logging
from datetime import datetime, timezone

from models import Host

logger = logging.getLogger("scanner")


def host_to_dict(host: Host) -> dict:
    """Serializes a Host into a JSON-friendly dict."""
    return {
        "ip": host.ip,
        "mac": host.mac,
        "scanned": host.scanned,
        "guessed_os": host.guessed_os,
        "open_ports": host.open_ports,
        "services": host.services,
        "udp_scanned": host.udp_scanned,
        "udp_open_ports": host.udp_open_ports,
        "udp_open_or_filtered_ports": host.udp_open_or_filtered_ports,
    }


def export_hosts_to_json(hosts: list[Host], filepath: str) -> None:
    """Writes hosts (with any open ports/service info already gathered) to filepath as JSON."""
    report = {
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "host_count": len(hosts),
        "hosts": [host_to_dict(host) for host in hosts],
    }
    with open(filepath, "w", encoding="utf-8") as f:
        json.dump(report, f, indent=2)
    logger.info("Exported %d host(s) to %s", len(hosts), filepath)
