"""Interactive menu-driven CLI for the scanner."""
from __future__ import annotations

from typing import Callable

from rich.console import Console
from rich.panel import Panel
from rich.table import Table

from config import load_scan_config
from export import export_hosts_to_json
from logging_setup import setup_logging
from models import Host
from network_scanner import arp_scan, calculate_adaptive_timeout, guess_os_from_ttl, tcp_scan, udp_scan
from service_detection import is_nmap_available, protocol_inference

MenuAction = Callable[[], None] | None
MenuEntry = tuple[str, MenuAction]


class ScannerApp:
    """Holds session state (discovered hosts, config, CVE cache).

    This replaces the old module-level globals (HOSTS, TARGET_RANGE, NETWORK_INTERFACE,
    CVE_CACHE) with instance state, so the scanner no longer relies on `global` statements
    scattered across functions.
    """

    def __init__(self) -> None:
        self.console = Console()
        setup_logging()  # first, so warnings during config loading etc. are captured too
        self.hosts: list[Host] = []
        self.config = load_scan_config()
        self.cve_cache: dict[tuple[str, str], list[dict]] = {}
        self.nmap_available = is_nmap_available()
        if not self.nmap_available:
            self.console.print(
                "[yellow][-] nmap not found - service detection will fall back to "
                "banner-grabbing (no CVE lookup).[/yellow]"
            )

    # ---------- setup ----------

    def configure_scan_mode(self) -> None:
        self.console.print("Select scan mode:")
        self.console.print("1 - VM test")
        self.console.print("2 - Live run")
        choice = input("Choose 1 or 2: ").strip()

        if choice == "1":
            self.config.use_vm_mode()
            self.console.print(
                f"[green][+] VM test mode selected: {self.config.target_range} "
                f"on {self.config.network_interface}[/green]"
            )
        elif choice == "2":
            self.config.use_live_mode()
            self.console.print(f"[green][+] Live run mode selected: {self.config.target_range}[/green]")
        else:
            self.console.print("[yellow][-] Invalid choice. Defaulting to live run mode.[/yellow]")
            self.config.use_live_mode()

    # ---------- actions ----------

    def _print_port_table(self, title: str, rows: list[tuple[int, str, str]]) -> None:
        """Renders a small Port/State table - rows are (port, state_label, color) tuples,
        e.g. [(22, "open", "green")] for TCP or a mix of "open"/"open|filtered" for UDP.
        """
        if not rows:
            return
        table = Table(title=title)
        table.add_column("Port", justify="right")
        table.add_column("State")
        for port, state, color in sorted(rows):
            table.add_row(str(port), f"[{color}]{state}[/{color}]")
        self.console.print(table)

    def _scan_host(self, host: Host) -> None:
        """Shared pipeline step: latency profiling, OS guess, then the TCP port scan itself.

        Used by both the interactive host-picker (handle_tcp_scan) and the non-interactive
        single-target path (run_single_target) so the two can't drift out of sync - they
        used to duplicate this sequence line-for-line.
        """
        self.console.print(f"[cyan][*] Profiling network latency for {host.ip}...[/cyan]")
        host.adaptive_timeout = calculate_adaptive_timeout(host.ip, self.config)

        host.guessed_os = guess_os_from_ttl(host.ip, self.config)
        if host.guessed_os:
            self.console.print(
                f"[cyan][*] Guessed OS (TTL heuristic, best-effort): {host.guessed_os}[/cyan]"
            )
        else:
            self.console.print("[yellow][-] Host unresponsive to ICMP - skipping TTL-based OS guess.[/yellow]")

        self.console.print(
            f"[cyan][*] TCP scanning {host.ip} on the first "
            f"{self.config.number_of_ports_to_scan - 1} ports...[/cyan]"
        )
        tcp_scan(host, self.config)
        if host.open_ports:
            self._print_port_table(
                f"Open TCP Ports on {host.ip}",
                [(port, "open", "green") for port in host.open_ports],
            )
        self.console.print(f"Found {len(host.open_ports)} open ports.\nThe ports are {host.open_ports}")

    def handle_arp_discovery(self) -> None:
        self.configure_scan_mode()
        self.hosts = arp_scan(self.config)
        self.show_scan_results()

    def handle_tcp_scan(self, show_hosts: bool = True) -> None:
        if not self.hosts:
            self.console.print("[yellow][-] Run ARP discovery first so there are hosts to scan.[/yellow]")
            return

        if show_hosts:
            self.show_scan_results()
        str_choice = input("choose what ip you want to scan: ")
        try:
            choice = int(str_choice)
        except ValueError:
            self.console.print("[red]invalid input[/red]")
            return

        if choice < 1 or choice > len(self.hosts):
            self.console.print("[red]invalid IP option[/red]")
            return

        target_host = self.hosts[choice - 1]
        self._scan_host(target_host)

        check_protocol = input("Would you like to check their protocol? (y / anything else to skip): ")
        if check_protocol == "y":
            protocol_inference(target_host, self.cve_cache, self.nmap_available)

    def handle_udp_scan(self, show_hosts: bool = True) -> None:
        if not self.hosts:
            self.console.print("[yellow][-] Run ARP discovery first so there are hosts to scan.[/yellow]")
            return

        if show_hosts:
            self.show_scan_results()
        str_choice = input("choose what ip you want to UDP scan: ")
        try:
            choice = int(str_choice)
        except ValueError:
            self.console.print("[red]invalid input[/red]")
            return

        if choice < 1 or choice > len(self.hosts):
            self.console.print("[red]invalid IP option[/red]")
            return

        target_host = self.hosts[choice - 1]
        self.console.print(
            f"[cyan][*] UDP scanning {target_host.ip} on the first "
            f"{self.config.number_of_ports_to_scan - 1} ports... "
            "(UDP is much slower/less certain than TCP - see CLAUDE.md)[/cyan]"
        )
        udp_scan(target_host, self.config)

        rows = [(port, "open", "green") for port in target_host.udp_open_ports]
        rows += [(port, "open|filtered", "yellow") for port in target_host.udp_open_or_filtered_ports]
        self._print_port_table(f"UDP Port Results on {target_host.ip}", rows)

        self.console.print(
            f"Found {len(target_host.udp_open_ports)} confirmed open UDP port(s): "
            f"{target_host.udp_open_ports}"
        )
        self.console.print(
            f"{len(target_host.udp_open_or_filtered_ports)} port(s) open|filtered "
            "(no reply - inconclusive, common for UDP)"
        )

    def handle_full_workflow(self) -> None:
        self.handle_arp_discovery()
        self.handle_tcp_scan(show_hosts=False)

    def run_single_target(
        self,
        target_ip: str,
        ports: int | None = None,
        interface: str | None = None,
        detect_services: bool = False,
        export_path: str | None = None,
        max_scans_per_second: float | None = None,
    ) -> None:
        """Non-interactive pipeline: TCP-scan one IP directly, skipping ARP discovery and the menu."""
        if interface is not None:
            self.config.network_interface = interface
        if ports is not None:
            self.config.number_of_ports_to_scan = ports + 1
        if max_scans_per_second is not None:
            self.config.max_scans_per_second = max_scans_per_second if max_scans_per_second > 0 else None

        host = Host(ip=target_ip)
        self.hosts = [host]

        self._scan_host(host)

        if detect_services:
            protocol_inference(host, self.cve_cache, self.nmap_available)

        if export_path:
            export_hosts_to_json(self.hosts, export_path)
            self.console.print(f"[green][+] Exported 1 host to {export_path}[/green]")

    def show_scan_results(self) -> None:
        if not self.hosts:
            self.console.print("[yellow][-] No hosts found. Check your permissions (sudo?) or subnet.[/yellow]")
            return

        table = Table(title=f"Discovered Hosts ({len(self.hosts)})")
        table.add_column("#", justify="right")
        table.add_column("IP")
        table.add_column("MAC")
        table.add_column("TCP")
        table.add_column("UDP")
        for i, host in enumerate(self.hosts, start=1):
            tcp_status = "[green]scanned[/green]" if host.scanned else "[dim]not scanned[/dim]"
            udp_status = "[green]scanned[/green]" if host.udp_scanned else "[dim]not scanned[/dim]"
            table.add_row(str(i), host.ip, str(host.mac), tcp_status, udp_status)
        self.console.print(table)

    def handle_export_results(self) -> None:
        if not self.hosts:
            self.console.print("[yellow][-] No scan results to export yet.[/yellow]")
            return

        self.show_scan_results()
        str_choice = input("choose which host to export: ")
        try:
            choice = int(str_choice)
        except ValueError:
            self.console.print("[red]invalid input[/red]")
            return

        if choice < 1 or choice > len(self.hosts):
            self.console.print("[red]invalid IP option[/red]")
            return

        target_host = self.hosts[choice - 1]

        default_name = f"scan_{target_host.ip.replace('.', '_')}.json"
        filepath = input(f"Enter output filename (default: {default_name}): ").strip() or default_name
        if not filepath.endswith(".json"):
            filepath += ".json"

        try:
            export_hosts_to_json([target_host], filepath)
        except OSError as e:
            self.console.print(f"[red][-] Failed to write {filepath}: {e}[/red]")
            return

        self.console.print(f"[green][+] Exported {target_host.ip} to {filepath}[/green]")

    # ---------- menu loop ----------

    def build_menu(self) -> list[MenuEntry]:
        return [
            ("Run ARP discovery", self.handle_arp_discovery),
            ("Run TCP scan on discovered host", self.handle_tcp_scan),
            ("Run UDP scan on discovered host", self.handle_udp_scan),
            ("Run full workflow (ARP then TCP)", self.handle_full_workflow),
            ("Show discovered hosts", self.show_scan_results),
            ("Export scan results to JSON", self.handle_export_results),
            ("Exit", None),
        ]

    def run(self) -> None:
        menu = self.build_menu()
        finished = False
        while not finished:
            menu_text = "\n".join(f"{i} - {label}" for i, (label, _) in enumerate(menu, start=1))
            self.console.print(Panel(menu_text, title="Network Scanner", expand=False))
            choice = input("Please enter the number of command to be executed: ")

            if not choice.isdigit():
                self.console.print("[yellow]Please enter a number[/yellow]")
                continue

            choice_index = int(choice)
            if choice_index < 1 or choice_index > len(menu):
                self.console.print("[yellow]Please enter a number corresponding to the commands[/yellow]")
            elif choice_index == len(menu):
                finished = True
            else:
                action = menu[choice_index - 1][1]
                if action is not None:
                    action()
