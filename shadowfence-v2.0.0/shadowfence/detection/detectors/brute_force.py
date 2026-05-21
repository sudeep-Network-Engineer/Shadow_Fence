"""Brute force attack detection module."""

from __future__ import annotations

import time
from collections import defaultdict
from dataclasses import dataclass, field
from threading import Lock

from shadowfence.capture.packet_parser import ParsedPacket
from shadowfence.config import BruteForceConfig

SERVICE_NAMES = {
    21: "FTP",
    22: "SSH",
    23: "Telnet",
    25: "SMTP",
    110: "POP3",
    143: "IMAP",
    389: "LDAP",
    443: "HTTPS",
    993: "IMAPS",
    995: "POP3S",
    1433: "MSSQL",
    3306: "MySQL",
    3389: "RDP",
    5432: "PostgreSQL",
    5900: "VNC",
    6379: "Redis",
    27017: "MongoDB",
}


@dataclass
class BruteForceTracker:
    connection_count: int = 0
    rst_count: int = 0
    fin_count: int = 0
    first_seen: float = 0.0
    last_seen: float = 0.0
    alerted: bool = False
    unique_flags: set[str] = field(default_factory=set)


class BruteForceDetector:
    """Detects brute force login attempts on monitored services."""

    def __init__(self, config: BruteForceConfig):
        self.config = config
        self._trackers: dict[str, BruteForceTracker] = defaultdict(BruteForceTracker)
        self._lock = Lock()

    def analyze(self, packet: ParsedPacket) -> list[dict]:
        """Analyze packet for brute force indicators."""
        if not self.config.enabled:
            return []
        if packet.protocol != "TCP":
            return []
        if packet.dst_port not in self.config.monitored_ports:
            return []

        alerts = []
        now = time.time()
        key = f"{packet.src_ip}:{packet.dst_ip}:{packet.dst_port}"

        with self._lock:
            tracker = self._trackers[key]

            if tracker.first_seen == 0:
                tracker.first_seen = now

            if now - tracker.first_seen > self.config.time_window:
                self._trackers[key] = BruteForceTracker(first_seen=now)
                tracker = self._trackers[key]

            if packet.is_syn:
                tracker.connection_count += 1
            if packet.is_rst:
                tracker.rst_count += 1
            if packet.is_fin:
                tracker.fin_count += 1

            tracker.unique_flags.add(packet.tcp_flags)
            tracker.last_seen = now

            rapid_connections = tracker.connection_count >= self.config.threshold
            high_rst_ratio = (
                tracker.rst_count > tracker.connection_count * 0.5
                and tracker.connection_count > 3
            )

            if (rapid_connections or high_rst_ratio) and not tracker.alerted:
                tracker.alerted = True
                service = SERVICE_NAMES.get(packet.dst_port, f"port {packet.dst_port}")
                alerts.append({
                    "type": "Brute Force",
                    "subtype": f"{service} Brute Force",
                    "severity": self.config.severity,
                    "src_ip": packet.src_ip,
                    "dst_ip": packet.dst_ip,
                    "description": (
                        f"Possible brute force attack on {service} "
                        f"({packet.dst_ip}:{packet.dst_port}) from {packet.src_ip}: "
                        f"{tracker.connection_count} connections, "
                        f"{tracker.rst_count} resets in "
                        f"{now - tracker.first_seen:.1f}s"
                    ),
                    "details": {
                        "service": service,
                        "port": packet.dst_port,
                        "connections": tracker.connection_count,
                        "resets": tracker.rst_count,
                        "fins": tracker.fin_count,
                        "duration": round(now - tracker.first_seen, 2),
                    },
                })

            self._cleanup(now)

        return alerts

    def _cleanup(self, now: float) -> None:
        """Remove expired trackers."""
        expired = [
            k for k, t in self._trackers.items()
            if now - t.last_seen > self.config.time_window * 2
        ]
        for k in expired:
            del self._trackers[k]
