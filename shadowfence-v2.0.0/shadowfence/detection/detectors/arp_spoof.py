"""ARP spoofing detection module."""

from __future__ import annotations

import time
from threading import Lock

from shadowfence.capture.packet_parser import ParsedPacket
from shadowfence.config import ARPSpoofConfig


class ARPSpoofDetector:
    """Detects ARP spoofing / ARP cache poisoning attacks."""

    def __init__(self, config: ARPSpoofConfig):
        self.config = config
        self._arp_table: dict[str, str] = {}
        self._lock = Lock()
        self._alerted: dict[str, float] = {}

    def analyze(self, packet: ParsedPacket) -> list[dict]:
        """Analyze ARP packets for spoofing indicators."""
        if not self.config.enabled:
            return []
        if packet.protocol != "ARP":
            return []
        if packet.arp_op != 2:
            return []

        alerts = []
        now = time.time()
        src_ip = packet.arp_src_ip
        src_mac = packet.arp_src_mac

        with self._lock:
            if src_ip in self._arp_table:
                known_mac = self._arp_table[src_ip]
                if known_mac != src_mac:
                    alert_key = f"arp_spoof:{src_ip}"
                    if not self._recently_alerted(alert_key, now):
                        self._alerted[alert_key] = now
                        alerts.append({
                            "type": "ARP Spoofing",
                            "subtype": "ARP Cache Poisoning",
                            "severity": self.config.severity,
                            "src_ip": src_ip,
                            "dst_ip": packet.arp_dst_ip,
                            "description": (
                                f"ARP spoofing detected: IP {src_ip} changed MAC "
                                f"from {known_mac} to {src_mac}. "
                                f"Possible MITM attack!"
                            ),
                            "details": {
                                "ip": src_ip,
                                "original_mac": known_mac,
                                "new_mac": src_mac,
                                "target_ip": packet.arp_dst_ip,
                            },
                        })

            self._arp_table[src_ip] = src_mac

        return alerts

    def _recently_alerted(self, key: str, now: float) -> bool:
        last = self._alerted.get(key, 0)
        return now - last < 60
