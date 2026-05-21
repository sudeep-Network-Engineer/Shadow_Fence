"""Network topology auto-discovery and asset tracking module.

Passively maps the network by observing traffic to build a live
inventory of devices, services, and connections.
"""

from __future__ import annotations

import time
from dataclasses import dataclass, field
from threading import Lock
from typing import Any

from shadowfence.capture.packet_parser import ParsedPacket
from shadowfence.utils.helpers import is_private_ip


@dataclass
class NetworkAsset:
    ip: str = ""
    mac: str = ""
    first_seen: float = 0.0
    last_seen: float = 0.0
    hostnames: set[str] = field(default_factory=set)
    open_ports: set[int] = field(default_factory=set)
    services: dict[int, str] = field(default_factory=dict)
    os_guess: str = ""
    is_gateway: bool = False
    packets_sent: int = 0
    packets_received: int = 0
    bytes_sent: int = 0
    bytes_received: int = 0
    protocols_used: set[str] = field(default_factory=set)
    connected_to: set[str] = field(default_factory=set)


SERVICE_PORT_MAP = {
    21: "FTP", 22: "SSH", 23: "Telnet", 25: "SMTP",
    53: "DNS", 67: "DHCP", 68: "DHCP", 80: "HTTP",
    110: "POP3", 123: "NTP", 143: "IMAP", 443: "HTTPS",
    445: "SMB", 993: "IMAPS", 995: "POP3S", 1433: "MSSQL",
    3306: "MySQL", 3389: "RDP", 5432: "PostgreSQL",
    5900: "VNC", 6379: "Redis", 8080: "HTTP-Proxy",
    8443: "HTTPS-Alt", 27017: "MongoDB",
}

TTL_OS_MAP = {
    (60, 68): "Linux/Unix",
    (120, 132): "Windows",
    (250, 256): "Cisco/Network Device",
    (30, 35): "Embedded/IoT",
}


class NetworkMapper:
    """Passively discovers and tracks network assets."""

    def __init__(self):
        self._assets: dict[str, NetworkAsset] = {}
        self._lock = Lock()
        self._new_asset_callbacks: list[Any] = []
        self._new_service_callbacks: list[Any] = []

    def register_new_asset_callback(self, cb: Any) -> None:
        self._new_asset_callbacks.append(cb)

    def register_new_service_callback(self, cb: Any) -> None:
        self._new_service_callbacks.append(cb)

    def process_packet(self, packet: ParsedPacket) -> list[dict]:
        """Process a packet to update network map. Returns alerts."""
        alerts: list[dict] = []
        now = time.time()

        with self._lock:
            if packet.src_ip:
                alerts.extend(
                    self._update_asset(
                        packet.src_ip,
                        packet.src_mac,
                        packet,
                        now,
                        is_source=True,
                    )
                )
            if packet.dst_ip and not packet.dst_ip.endswith(".255"):
                alerts.extend(
                    self._update_asset(
                        packet.dst_ip,
                        packet.dst_mac,
                        packet,
                        now,
                        is_source=False,
                    )
                )

            if packet.src_ip and packet.dst_ip:
                if packet.src_ip in self._assets:
                    self._assets[packet.src_ip].connected_to.add(
                        packet.dst_ip
                    )
                if packet.dst_ip in self._assets:
                    self._assets[packet.dst_ip].connected_to.add(
                        packet.src_ip
                    )

        return alerts

    def _update_asset(
        self,
        ip: str,
        mac: str,
        packet: ParsedPacket,
        now: float,
        is_source: bool,
    ) -> list[dict]:
        alerts: list[dict] = []
        is_new = ip not in self._assets

        if is_new:
            asset = NetworkAsset(ip=ip, first_seen=now)
            self._assets[ip] = asset
            if is_private_ip(ip):
                alerts.append({
                    "type": "Network Discovery",
                    "subtype": "New Device",
                    "severity": "info",
                    "src_ip": ip,
                    "dst_ip": "",
                    "description": (
                        f"New device discovered on network: {ip}"
                        f" (MAC: {mac})" if mac else f": {ip}"
                    ),
                    "details": {"ip": ip, "mac": mac},
                })

        asset = self._assets[ip]
        asset.last_seen = now

        if mac and not asset.mac:
            asset.mac = mac

        if is_source:
            asset.packets_sent += 1
            asset.bytes_sent += packet.length
        else:
            asset.packets_received += 1
            asset.bytes_received += packet.length

        if packet.protocol:
            asset.protocols_used.add(packet.protocol)

        if packet.dns_query:
            asset.hostnames.add(packet.dns_query)

        port = packet.dst_port if not is_source else packet.src_port
        if port and packet.is_syn_ack and is_source:
            was_new_port = port not in asset.open_ports
            asset.open_ports.add(port)
            service = SERVICE_PORT_MAP.get(port, f"unknown-{port}")
            asset.services[port] = service
            if was_new_port and is_private_ip(ip):
                alerts.append({
                    "type": "Network Discovery",
                    "subtype": "New Service",
                    "severity": "info",
                    "src_ip": ip,
                    "dst_ip": "",
                    "description": (
                        f"New service on {ip}: "
                        f"{service} (port {port})"
                    ),
                    "details": {
                        "ip": ip,
                        "port": port,
                        "service": service,
                    },
                })

        if packet.ttl > 0 and not asset.os_guess:
            for (low, high), os_name in TTL_OS_MAP.items():
                if low <= packet.ttl <= high:
                    asset.os_guess = os_name
                    break

        if packet.protocol == "ARP" and packet.arp_op == 2:
            if packet.dst_ip == "0.0.0.0" or not packet.arp_dst_ip:
                asset.is_gateway = True

        return alerts

    def get_assets(self) -> dict[str, dict]:
        """Get all discovered assets as serializable dicts."""
        with self._lock:
            result = {}
            for ip, asset in self._assets.items():
                result[ip] = {
                    "ip": asset.ip,
                    "mac": asset.mac,
                    "first_seen": asset.first_seen,
                    "last_seen": asset.last_seen,
                    "hostnames": list(asset.hostnames),
                    "open_ports": sorted(asset.open_ports),
                    "services": asset.services,
                    "os_guess": asset.os_guess,
                    "is_gateway": asset.is_gateway,
                    "packets_sent": asset.packets_sent,
                    "packets_received": asset.packets_received,
                    "bytes_sent": asset.bytes_sent,
                    "bytes_received": asset.bytes_received,
                    "protocols": list(asset.protocols_used),
                    "connections": len(asset.connected_to),
                }
            return result

    def get_topology(self) -> dict:
        """Get network topology as nodes + edges."""
        with self._lock:
            nodes = []
            edges = set()
            for ip, asset in self._assets.items():
                nodes.append({
                    "id": ip,
                    "mac": asset.mac,
                    "os": asset.os_guess,
                    "services": len(asset.open_ports),
                    "is_gateway": asset.is_gateway,
                })
                for peer in asset.connected_to:
                    edge = tuple(sorted([ip, peer]))
                    edges.add(edge)

            return {
                "nodes": nodes,
                "edges": [
                    {"source": e[0], "target": e[1]}
                    for e in edges
                ],
            }
