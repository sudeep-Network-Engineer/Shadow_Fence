"""ShadowFence CLI interface."""

from __future__ import annotations

import signal
import sys
import threading
import time
from pathlib import Path

import click
from rich.console import Console
from rich.table import Table

from shadowfence import __version__
from shadowfence.alerts.alert_manager import AlertManager
from shadowfence.alerts.email_alert import EmailAlertSender
from shadowfence.capture.pcap_export import PCAPExporter
from shadowfence.capture.sniffer import PacketSniffer
from shadowfence.config import load_config
from shadowfence.dashboard.app import Dashboard
from shadowfence.detection.detectors.firewall import (
    FirewallConfig as FWCfg,
)
from shadowfence.detection.detectors.firewall import (
    FirewallManager,
)
from shadowfence.detection.engine import DetectionEngine
from shadowfence.logging.logger import setup_logger

console = Console()


def print_banner() -> None:
    banner = """
    [bold blue]
    ╔═══════════════════════════════════════════════════╗
    ║                                                   ║
    ║     ███████╗██╗  ██╗ █████╗ ██████╗  ██████╗     ║
    ║     ██╔════╝██║  ██║██╔══██╗██╔══██╗██╔═══██╗    ║
    ║     ███████╗███████║███████║██║  ██║██║   ██║    ║
    ║     ╚════██║██╔══██║██╔══██║██║  ██║██║   ██║    ║
    ║     ███████║██║  ██║██║  ██║██████╔╝╚██████╔╝    ║
    ║     ╚══════╝╚═╝  ╚═╝╚═╝  ╚═╝╚═════╝  ╚═════╝     ║
    ║     [cyan]W   F   E   N   C   E[/cyan]                       ║
    ║     [dim]Advanced Network Intrusion Detection[/dim]        ║
    ║     [dim]v{version} | by Sudeep Patil[/dim]                    ║
    ║                                                   ║
    ╚═══════════════════════════════════════════════════╝
    [/bold blue]
    """.format(version=__version__)
    console.print(banner)


@click.group()
@click.version_option(version=__version__)
def main():
    """ShadowFence - Advanced Network Intrusion Detection System"""
    pass


@main.command()
@click.option("-c", "--config", "config_path", default="config.yaml", help="Path to config file")
@click.option("-i", "--interface", default=None, help="Network interface to monitor")
@click.option("--no-dashboard", is_flag=True, help="Disable the web dashboard")
@click.option("--no-email", is_flag=True, help="Disable email alerts")
@click.option("--rules-dir", default="rules", help="Directory containing detection rules")
@click.option("--pcap", is_flag=True, help="Enable PCAP export")
@click.option("--auto-block", is_flag=True, help="Enable auto firewall blocking (dry-run)")
@click.option("-v", "--verbose", is_flag=True, help="Enable verbose/debug logging")
def start(config_path, interface, no_dashboard, no_email, rules_dir, pcap, auto_block, verbose):
    """Start the ShadowFence IDS engine."""
    print_banner()

    config = load_config(config_path)

    if interface:
        config.interface = interface
    if verbose:
        config.logging.level = "DEBUG"
    if no_email:
        config.alerts.email.enabled = False
    if no_dashboard:
        config.dashboard.enabled = False
    if pcap:
        config.capture.pcap_export = True
    if auto_block:
        config.detection.firewall.enabled = True
        config.detection.firewall.auto_block = True

    logger = setup_logger(config.logging)
    logger.info("ShadowFence starting up...")

    rules_path = Path(rules_dir)
    detection = DetectionEngine(config, rules_dir=rules_path if rules_path.exists() else None)
    alert_manager = AlertManager(config)
    email_sender = EmailAlertSender(config.alerts.email)
    pcap_exporter = PCAPExporter(
        output_dir=config.capture.pcap_dir,
        max_file_size=config.capture.pcap_max_size,
        max_files=config.capture.pcap_max_files,
    ) if config.capture.pcap_export else None
    dashboard = Dashboard(config.dashboard.host, config.dashboard.port) if config.dashboard.enabled else None

    fw_cfg = FWCfg(
        enabled=config.detection.firewall.enabled,
        auto_block=config.detection.firewall.auto_block,
        block_duration=config.detection.firewall.block_duration,
        whitelist=config.detection.firewall.whitelist,
        min_severity_to_block=config.detection.firewall.min_severity_to_block,
        dry_run=config.detection.firewall.dry_run,
    )
    firewall = FirewallManager(fw_cfg)

    detection.register_alert_callback(alert_manager.handle_alert)

    if config.alerts.email.enabled:
        alert_manager.register_callback(email_sender.queue_alert)
    if dashboard:
        alert_manager.register_callback(dashboard.emit_alert)
    if config.detection.firewall.enabled:
        alert_manager.register_callback(firewall.handle_alert)

    def on_packet(parsed_packet):
        detection.analyze(parsed_packet)
        if pcap_exporter:
            pcap_exporter.write_packet(parsed_packet)

    sniffer = PacketSniffer(config, packet_callback=on_packet)

    stats_running = True

    def stats_loop():
        while stats_running:
            time.sleep(1)
            if dashboard:
                capture_stats = sniffer.get_stats()
                alert_stats = alert_manager.get_stats()
                net_map = detection.network_mapper.get_assets()
                dashboard.emit_stats({
                    "capture": capture_stats,
                    "alerts": alert_stats,
                    "network_map": {"devices": len(net_map)},
                })

    stats_thread = threading.Thread(target=stats_loop, daemon=True)

    def shutdown(sig=None, frame=None):
        nonlocal stats_running
        console.print("\n[yellow]Shutting down ShadowFence...[/yellow]")
        stats_running = False
        sniffer.stop()
        email_sender.stop()
        firewall.stop()
        if pcap_exporter:
            summary = pcap_exporter.stop()
            console.print(f"[dim]PCAP: {summary.get('packets', 0)} packets saved[/dim]")
        if dashboard:
            dashboard.stop()

        final_stats = sniffer.get_stats()
        final_alerts = alert_manager.get_stats()
        net_assets = detection.network_mapper.get_assets()

        table = Table(title="Session Summary", border_style="blue")
        table.add_column("Metric", style="cyan")
        table.add_column("Value", style="white")
        table.add_row("Packets Captured", f"{final_stats['packets_captured']:,}")
        table.add_row("Packets Processed", f"{final_stats['packets_processed']:,}")
        table.add_row("Packets Dropped", f"{final_stats['packets_dropped']:,}")
        table.add_row("Total Alerts", f"{final_alerts['total_alerts']:,}")
        table.add_row("Devices Discovered", f"{len(net_assets)}")
        table.add_row("Blocked IPs", f"{len(firewall.get_blocked_ips())}")
        table.add_row("Duration", f"{final_stats.get('elapsed_seconds', 0):.1f}s")
        console.print(table)
        sys.exit(0)

    signal.signal(signal.SIGINT, shutdown)
    signal.signal(signal.SIGTERM, shutdown)

    try:
        if dashboard:
            dashboard.start()
            console.print(f"[green]Dashboard:[/green] http://localhost:{config.dashboard.port}")

        if config.alerts.email.enabled:
            email_sender.start()
            console.print(f"[green]Email alerts:[/green] Enabled -> {', '.join(config.alerts.email.to_addrs)}")

        if pcap_exporter:
            pcap_file = pcap_exporter.start()
            console.print(f"[green]PCAP export:[/green] {pcap_file}")

        if config.detection.firewall.enabled:
            firewall.start()
            mode = "DRY RUN" if config.detection.firewall.dry_run else "LIVE"
            console.print(f"[green]Auto-block:[/green] Enabled ({mode})")

        rule_count = detection.payload.get_rule_count()
        ti_stats = detection.threat_intel.get_stats()
        console.print(f"[green]Signature rules:[/green] {rule_count} loaded")
        if ti_stats["malicious_ips"] > 0:
            console.print(f"[green]Threat intel:[/green] {ti_stats['malicious_ips']} IPs, {ti_stats['malicious_domains']} domains")

        console.print(f"[green]Interface:[/green] {config.interface}")
        console.print(
            "[green]Detectors:[/green] Port Scan, Brute Force, DDoS, "
            "ARP Spoof, DNS Tunnel, Payload, Protocol Anomaly, "
            "Bandwidth Anomaly, SSL/TLS, Threat Intel, Network Map"
        )
        console.print("")
        console.print("[bold green]ShadowFence is now monitoring your network.[/bold green]")
        console.print("[dim]Press Ctrl+C to stop[/dim]\n")

        sniffer.start()
        stats_thread.start()

        while True:
            time.sleep(1)

    except PermissionError:
        console.print("[bold red]ERROR:[/bold red] Root privileges required for packet capture.")
        console.print("Run with: [cyan]sudo shadowfence start[/cyan]")
        sys.exit(1)
    except Exception as e:
        console.print(f"[bold red]ERROR:[/bold red] {e}")
        logger.exception("Fatal error")
        sys.exit(1)


@main.command()
@click.option("-c", "--config", "config_path", default="config.yaml", help="Path to config file")
def status(config_path):
    """Show ShadowFence configuration status."""
    config = load_config(config_path)

    table = Table(title="ShadowFence Configuration", border_style="blue")
    table.add_column("Setting", style="cyan")
    table.add_column("Value", style="white")
    table.add_column("Status", style="green")

    table.add_row("Interface", config.interface, "OK")
    table.add_row("Dashboard", f":{config.dashboard.port}", "Enabled" if config.dashboard.enabled else "Disabled")
    table.add_row("Email Alerts", config.alerts.email.smtp_server, "Enabled" if config.alerts.email.enabled else "Disabled")
    table.add_row("Port Scan", f"threshold={config.detection.port_scan.threshold}", "Enabled" if config.detection.port_scan.enabled else "Disabled")
    table.add_row("Brute Force", f"threshold={config.detection.brute_force.threshold}", "Enabled" if config.detection.brute_force.enabled else "Disabled")
    table.add_row("DDoS", f"SYN={config.detection.ddos.syn_flood_threshold}/s", "Enabled" if config.detection.ddos.enabled else "Disabled")
    table.add_row("ARP Spoof", "-", "Enabled" if config.detection.arp_spoof.enabled else "Disabled")
    table.add_row("DNS Tunnel", f"entropy>{config.detection.dns_tunnel.entropy_threshold}", "Enabled" if config.detection.dns_tunnel.enabled else "Disabled")
    table.add_row("Payload Analysis", f"max={config.detection.payload.max_payload_size}B", "Enabled" if config.detection.payload.enabled else "Disabled")
    table.add_row("Protocol Anomaly", "XMAS/NULL/LAND", "Enabled" if config.detection.protocol_anomaly.enabled else "Disabled")
    table.add_row("Bandwidth Anomaly", f"spike={config.detection.bandwidth_anomaly.spike_multiplier}x", "Enabled" if config.detection.bandwidth_anomaly.enabled else "Disabled")
    table.add_row("SSL/TLS Anomaly", "downgrade/strip", "Enabled" if config.detection.ssl_anomaly.enabled else "Disabled")
    table.add_row("Threat Intel", config.detection.threat_intel.blocklist_path or "no blocklist", "Enabled" if config.detection.threat_intel.enabled else "Disabled")
    table.add_row("Auto Firewall", f"dry_run={config.detection.firewall.dry_run}", "Enabled" if config.detection.firewall.enabled else "Disabled")
    table.add_row("Network Mapper", "passive", "Enabled" if config.detection.network_map.enabled else "Disabled")

    rules_path = Path("rules/default_rules.yaml")
    if rules_path.exists():
        from shadowfence.detection.detectors.payload import PayloadDetector
        pd = PayloadDetector(config.detection.payload)
        count = pd.load_rules(rules_path)
        table.add_row("Signature Rules", f"{count} rules", "Loaded")

    console.print(table)


@main.command()
@click.option("--smtp-server", prompt="SMTP Server", default="smtp.gmail.com")
@click.option("--smtp-port", prompt="SMTP Port", default=587, type=int)
@click.option("--username", prompt="Email Username")
@click.option("--password", prompt="Email Password", hide_input=True)
@click.option("--from-addr", prompt="From Address")
@click.option("--to-addr", prompt="To Address(es) (comma-separated)")
def setup_email(smtp_server, smtp_port, username, password, from_addr, to_addr):
    """Interactive email alert configuration."""
    import smtplib

    console.print("\n[cyan]Testing SMTP connection...[/cyan]")
    try:
        with smtplib.SMTP(smtp_server, smtp_port) as server:
            server.starttls()
            server.login(username, password)
            console.print("[green]SMTP connection successful![/green]")
    except Exception as e:
        console.print(f"[red]SMTP connection failed: {e}[/red]")
        return

    console.print("\n[yellow]Add these settings to your config.yaml:[/yellow]")
    console.print(f"""
alerts:
  email:
    enabled: true
    smtp_server: "{smtp_server}"
    smtp_port: {smtp_port}
    use_tls: true
    username: "{username}"
    password: "{password}"
    from_addr: "{from_addr}"
    to_addrs:
{chr(10).join(f'      - "{addr.strip()}"' for addr in to_addr.split(","))}
""")


@main.command()
@click.argument("rules_file", default="rules/default_rules.yaml")
def validate_rules(rules_file):
    """Validate detection rules file."""
    from shadowfence.config import PayloadConfig
    from shadowfence.detection.detectors.payload import PayloadDetector

    path = Path(rules_file)
    if not path.exists():
        console.print(f"[red]Rules file not found: {rules_file}[/red]")
        return

    detector = PayloadDetector(PayloadConfig())
    count = detector.load_rules(path)
    console.print(f"[green]Successfully loaded {count} detection rules from {rules_file}[/green]")


@main.command()
def list_interfaces():
    """List available network interfaces."""
    try:
        from scapy.all import get_if_list
        interfaces = get_if_list()
        table = Table(title="Network Interfaces", border_style="blue")
        table.add_column("Interface", style="cyan")
        for iface in interfaces:
            table.add_row(iface)
        console.print(table)
    except Exception as e:
        console.print(f"[red]Error listing interfaces: {e}[/red]")


@main.command()
@click.option("-c", "--config", "config_path", default="config.yaml")
def network_map(config_path):
    """Show discovered network topology (requires a running session's data)."""
    from shadowfence.logging.logger import AlertLogger

    al = AlertLogger()
    alerts = al.get_recent_alerts(1000)
    discovery = [a for a in alerts if a.get("type") == "Network Discovery"]

    if not discovery:
        console.print("[yellow]No network discovery data found. Start ShadowFence first.[/yellow]")
        return

    table = Table(title="Discovered Network Assets", border_style="blue")
    table.add_column("IP", style="cyan")
    table.add_column("Type", style="white")
    table.add_column("Details", style="dim")

    for alert in discovery:
        table.add_row(
            alert.get("src_ip", "?"),
            alert.get("subtype", "?"),
            alert.get("description", ""),
        )
    console.print(table)


@main.command()
def list_captures():
    """List saved PCAP capture files."""
    pcap = PCAPExporter()
    captures = pcap.list_captures()
    if not captures:
        console.print("[yellow]No PCAP captures found.[/yellow]")
        return

    table = Table(title="PCAP Captures", border_style="blue")
    table.add_column("File", style="cyan")
    table.add_column("Size", style="white")

    from shadowfence.utils.helpers import format_bytes
    for cap in captures:
        table.add_row(cap["name"], format_bytes(cap["size"]))
    console.print(table)


if __name__ == "__main__":
    main()
