"""Entry point for the network scanner project."""
from __future__ import annotations

import argparse
import ipaddress
import logging

from cli import ScannerApp

logger = logging.getLogger("scanner")


def is_valid_ipv4(value: str) -> bool:
    """True if value is a syntactically valid IPv4 address.

    IPv4-only on purpose: nothing else in this codebase supports IPv6 (network_scanner's
    sockets are hardcoded to socket.AF_INET, scapy's IP()/ARP() layers used throughout are
    v4-specific) - accepting a valid IPv6 address here would just let it fail confusingly
    somewhere deeper in the pipeline instead of failing cleanly at the door. Hostnames are
    also rejected - this project scans concrete targets, not DNS names.
    """
    try:
        ipaddress.IPv4Address(value)
        return True
    except ValueError:
        return False


def build_arg_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="Network scanner: ARP discovery + TCP port scan + nmap service detection."
    )
    parser.add_argument(
        "--target",
        metavar="IP",
        help="Run non-interactively: TCP-scan this IP directly (skips ARP discovery and the menu).",
    )
    parser.add_argument(
        "--ports",
        type=int,
        metavar="N",
        help=(
            "Scan ports 1..N (default: same range as interactive mode); scan order is still "
            "shuffled, same as interactive mode. Requires --target."
        ),
    )
    parser.add_argument(
        "--interface",
        metavar="IFACE",
        help="Network interface for latency probing (default: auto-selected). Requires --target.",
    )
    parser.add_argument(
        "--detect-services",
        action="store_true",
        help="Run nmap service detection + NVD CVE lookup on any open ports found. Requires --target.",
    )
    parser.add_argument(
        "--export",
        metavar="FILE",
        help="Export the scan result to FILE as JSON. Requires --target.",
    )
    parser.add_argument(
        "--rate",
        type=float,
        metavar="PORTS_PER_SEC",
        help=(
            "Cap connection attempts to this many ports/sec (default: same stealth pacing as "
            "interactive mode). Use 0 to disable throttling entirely. Requires --target."
        ),
    )
    return parser


def main() -> None:
    args = build_arg_parser().parse_args()
    print("--- Network Scanner Project Started ---")

    if not args.target and (args.ports or args.interface or args.detect_services or args.export or args.rate is not None):
        print("[-] --ports/--interface/--detect-services/--export/--rate require --target. Ignoring and starting the interactive menu.")

    if args.target and not is_valid_ipv4(args.target):
        print(f"[-] Error: '{args.target}' is not a valid IPv4 address. Hostnames and IPv6 aren't supported.")
        return

    try:
        app = ScannerApp()
        if args.target:
            app.run_single_target(
                args.target,
                ports=args.ports,
                interface=args.interface,
                detect_services=args.detect_services,
                export_path=args.export,
                max_scans_per_second=args.rate,
            )
        else:
            app.run()
    except PermissionError:
        print("[-] Error: You need Root/Admin privileges to run ARP scans.")
        logger.error("Aborted: insufficient privileges for raw ARP/ICMP/UDP sockets.")
    except KeyboardInterrupt:
        # tcp_scan/udp_scan already print their own "interrupted, cancelling" message and
        # re-raise; this is the top-level catch that turns that into a clean exit instead
        # of a raw KeyboardInterrupt traceback (or, for a Ctrl+C outside an active scan -
        # e.g. at an input() prompt - the only message the user sees at all).
        print("\n[-] Interrupted by user. Exiting.")
        logger.warning("Session interrupted by user (Ctrl+C).")


if __name__ == "__main__":
    main()
