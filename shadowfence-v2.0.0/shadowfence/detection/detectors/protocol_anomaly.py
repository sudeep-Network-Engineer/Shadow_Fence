"""Protocol anomaly detection module.

Detects malformed packets, unusual protocol combinations, and suspicious
protocol behavior that deviates from RFC standards.
"""

from __future__ import annotations

import time
from collections import defaultdict
from dataclasses import dataclass
from threading import Lock

from shadowfence.capture.packet_parser import ParsedPacket


@dataclass
class ProtocolAnomalyConfig:
    enabled: bool = True
    severity: str = "medium"
    detect_xmas_scan: bool = True
    detect_null_scan: bool = True
    detect_fin_scan: bool = True
    detect_invalid_flags: bool = True
    detect_land_attack: bool = True
    detect_smurf_attack: bool = True
    detect_fragmentation: bool = True
    detect_ttl_anomaly: bool = True
    ttl_anomaly_threshold: int = 3
    time_window: int = 60


class ProtocolAnomalyDetector:
    """Detects protocol-level anomalies and malformed packet attacks."""

    def __init__(self, config: ProtocolAnomalyConfig):
        self.config = config
        self._ttl_history: dict[str, list[int]] = defaultdict(list)
        self._frag_tracker: dict[str, list[float]] = defaultdict(list)
        self._lock = Lock()
        self._alerted: dict[str, float] = {}

    def analyze(self, packet: ParsedPacket) -> list[dict]:
        if not self.config.enabled:
            return []

        alerts: list[dict] = []
        now = time.time()

        if packet.protocol == "TCP":
            alerts.extend(self._check_tcp_anomalies(packet, now))

        if packet.protocol == "ICMP":
            alerts.extend(self._check_icmp_anomalies(packet, now))

        if packet.src_ip and packet.ttl > 0:
            alerts.extend(self._check_ttl_anomaly(packet, now))

        return alerts

    def _check_tcp_anomalies(
        self, packet: ParsedPacket, now: float
    ) -> list[dict]:
        alerts: list[dict] = []
        flags = packet.tcp_flags

        if self.config.detect_xmas_scan and "F" in flags and "P" in flags and "U" in flags:
            key = f"xmas:{packet.src_ip}:{packet.dst_ip}"
            if not self._recently_alerted(key, now):
                self._alerted[key] = now
                alerts.append({
                    "type": "Protocol Anomaly",
                    "subtype": "XMAS Scan",
                    "severity": "high",
                    "src_ip": packet.src_ip,
                    "dst_ip": packet.dst_ip,
                    "description": (
                        f"XMAS scan detected (FIN+PSH+URG flags): "
                        f"{packet.src_ip}:{packet.src_port} -> "
                        f"{packet.dst_ip}:{packet.dst_port}"
                    ),
                    "details": {
                        "flags": flags,
                        "attack_type": "XMAS scan - all flags set",
                    },
                })

        if self.config.detect_null_scan and flags == "" and packet.protocol == "TCP":
            key = f"null:{packet.src_ip}:{packet.dst_ip}"
            if not self._recently_alerted(key, now):
                self._alerted[key] = now
                alerts.append({
                    "type": "Protocol Anomaly",
                    "subtype": "NULL Scan",
                    "severity": "high",
                    "src_ip": packet.src_ip,
                    "dst_ip": packet.dst_ip,
                    "description": (
                        f"NULL scan detected (no TCP flags set): "
                        f"{packet.src_ip} -> {packet.dst_ip}:{packet.dst_port}"
                    ),
                    "details": {"flags": "none", "attack_type": "TCP NULL scan"},
                })

        if (
            self.config.detect_land_attack
            and packet.src_ip == packet.dst_ip
            and packet.src_port == packet.dst_port
            and packet.src_ip != "127.0.0.1"
        ):
            key = f"land:{packet.src_ip}"
            if not self._recently_alerted(key, now):
                self._alerted[key] = now
                alerts.append({
                    "type": "Protocol Anomaly",
                    "subtype": "LAND Attack",
                    "severity": "critical",
                    "src_ip": packet.src_ip,
                    "dst_ip": packet.dst_ip,
                    "description": (
                        f"LAND attack detected: source and destination "
                        f"are identical ({packet.src_ip}:{packet.src_port})"
                    ),
                    "details": {
                        "attack_type": "LAND attack - src==dst",
                        "ip": packet.src_ip,
                        "port": packet.src_port,
                    },
                })

        return alerts

    def _check_icmp_anomalies(
        self, packet: ParsedPacket, now: float
    ) -> list[dict]:
        alerts: list[dict] = []

        if (
            self.config.detect_smurf_attack
            and packet.dst_ip
            and packet.dst_ip.endswith(".255")
            and packet.icmp_type == 8
        ):
            key = f"smurf:{packet.src_ip}"
            if not self._recently_alerted(key, now):
                self._alerted[key] = now
                alerts.append({
                    "type": "Protocol Anomaly",
                    "subtype": "Smurf Attack",
                    "severity": "critical",
                    "src_ip": packet.src_ip,
                    "dst_ip": packet.dst_ip,
                    "description": (
                        f"Possible Smurf attack: ICMP echo request "
                        f"to broadcast address {packet.dst_ip} "
                        f"from {packet.src_ip}"
                    ),
                    "details": {
                        "attack_type": "Smurf - ICMP to broadcast",
                        "broadcast_addr": packet.dst_ip,
                    },
                })

        return alerts

    def _check_ttl_anomaly(
        self, packet: ParsedPacket, now: float
    ) -> list[dict]:
        if not self.config.detect_ttl_anomaly:
            return []

        alerts: list[dict] = []
        src = packet.src_ip

        with self._lock:
            self._ttl_history[src].append(packet.ttl)
            if len(self._ttl_history[src]) > 50:
                self._ttl_history[src] = self._ttl_history[src][-50:]

            history = self._ttl_history[src]
            if len(history) >= 10:
                unique_ttls = set(history[-10:])
                if len(unique_ttls) >= self.config.ttl_anomaly_threshold:
                    key = f"ttl_anomaly:{src}"
                    if not self._recently_alerted(key, now):
                        self._alerted[key] = now
                        alerts.append({
                            "type": "Protocol Anomaly",
                            "subtype": "TTL Anomaly",
                            "severity": "medium",
                            "src_ip": src,
                            "dst_ip": packet.dst_ip,
                            "description": (
                                f"TTL anomaly from {src}: "
                                f"{len(unique_ttls)} different TTL values "
                                f"in last 10 packets (possible OS spoofing "
                                f"or MITM)"
                            ),
                            "details": {
                                "ttl_values": sorted(unique_ttls),
                                "current_ttl": packet.ttl,
                            },
                        })

        return alerts

    def _recently_alerted(self, key: str, now: float) -> bool:
        last = self._alerted.get(key, 0)
        return now - last < self.config.time_window
