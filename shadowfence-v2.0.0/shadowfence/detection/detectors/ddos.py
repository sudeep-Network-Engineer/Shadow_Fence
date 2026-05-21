"""DDoS / flood attack detection module."""

from __future__ import annotations

import time
from collections import defaultdict
from threading import Lock

from shadowfence.capture.packet_parser import ParsedPacket
from shadowfence.config import DDoSConfig


class DDoSDetector:
    """Detects various flood-based denial of service attacks."""

    def __init__(self, config: DDoSConfig):
        self.config = config
        self._lock = Lock()
        self._syn_counts: dict[str, list[float]] = defaultdict(list)
        self._udp_counts: dict[str, list[float]] = defaultdict(list)
        self._icmp_counts: dict[str, list[float]] = defaultdict(list)
        self._http_counts: dict[str, list[float]] = defaultdict(list)
        self._alerted: dict[str, float] = {}

    def analyze(self, packet: ParsedPacket) -> list[dict]:
        """Analyze packet for DDoS/flood indicators."""
        if not self.config.enabled:
            return []

        alerts = []
        now = time.time()

        with self._lock:
            if packet.protocol == "TCP" and packet.is_syn:
                alerts.extend(self._check_syn_flood(packet, now))
            elif packet.protocol == "UDP":
                alerts.extend(self._check_udp_flood(packet, now))
            elif packet.protocol == "ICMP":
                alerts.extend(self._check_icmp_flood(packet, now))

            if packet.http_method:
                alerts.extend(self._check_http_flood(packet, now))

        return alerts

    def _check_syn_flood(self, packet: ParsedPacket, now: float) -> list[dict]:
        target = packet.dst_ip
        self._syn_counts[target].append(now)
        self._syn_counts[target] = [
            t for t in self._syn_counts[target]
            if now - t <= self.config.time_window
        ]

        rate = len(self._syn_counts[target]) / self.config.time_window
        alert_key = f"syn_flood:{target}"

        if rate >= self.config.syn_flood_threshold and not self._recently_alerted(alert_key, now):
            self._alerted[alert_key] = now
            return [{
                "type": "DDoS",
                "subtype": "SYN Flood",
                "severity": self.config.severity,
                "src_ip": "multiple",
                "dst_ip": target,
                "description": (
                    f"SYN flood detected targeting {target}: "
                    f"{rate:.0f} SYN/s (threshold: {self.config.syn_flood_threshold})"
                ),
                "details": {
                    "rate": round(rate, 1),
                    "threshold": self.config.syn_flood_threshold,
                    "window": self.config.time_window,
                    "total_syns": len(self._syn_counts[target]),
                },
            }]
        return []

    def _check_udp_flood(self, packet: ParsedPacket, now: float) -> list[dict]:
        target = packet.dst_ip
        self._udp_counts[target].append(now)
        self._udp_counts[target] = [
            t for t in self._udp_counts[target]
            if now - t <= self.config.time_window
        ]

        rate = len(self._udp_counts[target]) / self.config.time_window
        alert_key = f"udp_flood:{target}"

        if rate >= self.config.udp_flood_threshold and not self._recently_alerted(alert_key, now):
            self._alerted[alert_key] = now
            return [{
                "type": "DDoS",
                "subtype": "UDP Flood",
                "severity": self.config.severity,
                "src_ip": packet.src_ip,
                "dst_ip": target,
                "description": (
                    f"UDP flood detected targeting {target}: "
                    f"{rate:.0f} pkt/s (threshold: {self.config.udp_flood_threshold})"
                ),
                "details": {
                    "rate": round(rate, 1),
                    "threshold": self.config.udp_flood_threshold,
                },
            }]
        return []

    def _check_icmp_flood(self, packet: ParsedPacket, now: float) -> list[dict]:
        target = packet.dst_ip
        self._icmp_counts[target].append(now)
        self._icmp_counts[target] = [
            t for t in self._icmp_counts[target]
            if now - t <= self.config.time_window
        ]

        rate = len(self._icmp_counts[target]) / self.config.time_window
        alert_key = f"icmp_flood:{target}"

        if rate >= self.config.icmp_flood_threshold and not self._recently_alerted(alert_key, now):
            self._alerted[alert_key] = now
            return [{
                "type": "DDoS",
                "subtype": "ICMP Flood",
                "severity": self.config.severity,
                "src_ip": packet.src_ip,
                "dst_ip": target,
                "description": (
                    f"ICMP flood (ping flood) detected targeting {target}: "
                    f"{rate:.0f} pkt/s (threshold: {self.config.icmp_flood_threshold})"
                ),
                "details": {
                    "rate": round(rate, 1),
                    "threshold": self.config.icmp_flood_threshold,
                },
            }]
        return []

    def _check_http_flood(self, packet: ParsedPacket, now: float) -> list[dict]:
        target = packet.dst_ip
        self._http_counts[target].append(now)
        self._http_counts[target] = [
            t for t in self._http_counts[target]
            if now - t <= self.config.time_window
        ]

        rate = len(self._http_counts[target]) / self.config.time_window
        alert_key = f"http_flood:{target}"

        if rate >= self.config.http_flood_threshold and not self._recently_alerted(alert_key, now):
            self._alerted[alert_key] = now
            return [{
                "type": "DDoS",
                "subtype": "HTTP Flood",
                "severity": self.config.severity,
                "src_ip": packet.src_ip,
                "dst_ip": target,
                "description": (
                    f"HTTP flood detected targeting {target}: "
                    f"{rate:.0f} req/s (threshold: {self.config.http_flood_threshold})"
                ),
                "details": {
                    "rate": round(rate, 1),
                    "threshold": self.config.http_flood_threshold,
                },
            }]
        return []

    def _recently_alerted(self, key: str, now: float) -> bool:
        last = self._alerted.get(key, 0)
        return now - last < self.config.time_window * 3
