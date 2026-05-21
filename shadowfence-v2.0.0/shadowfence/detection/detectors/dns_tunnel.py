"""DNS tunneling detection module."""

from __future__ import annotations

import time
from collections import defaultdict
from threading import Lock

from shadowfence.capture.packet_parser import ParsedPacket
from shadowfence.config import DNSTunnelConfig
from shadowfence.utils.helpers import calculate_entropy


class DNSTunnelDetector:
    """Detects DNS tunneling based on query patterns, entropy, and rate."""

    def __init__(self, config: DNSTunnelConfig):
        self.config = config
        self._query_timestamps: dict[str, list[float]] = defaultdict(list)
        self._lock = Lock()
        self._alerted: dict[str, float] = {}

    def analyze(self, packet: ParsedPacket) -> list[dict]:
        """Analyze DNS queries for tunneling indicators."""
        if not self.config.enabled:
            return []
        if packet.protocol != "DNS" or not packet.dns_query:
            return []

        alerts = []
        now = time.time()
        query = packet.dns_query
        src = packet.src_ip

        with self._lock:
            self._query_timestamps[src].append(now)
            self._query_timestamps[src] = [
                t for t in self._query_timestamps[src] if now - t <= 60
            ]

            suspicion_score = 0
            reasons = []

            labels = query.split(".")
            subdomain = ".".join(labels[:-2]) if len(labels) > 2 else labels[0]

            if len(subdomain) > self.config.query_length_threshold:
                suspicion_score += 3
                reasons.append(f"long subdomain ({len(subdomain)} chars)")

            entropy = calculate_entropy(subdomain)
            if entropy > self.config.entropy_threshold:
                suspicion_score += 3
                reasons.append(f"high entropy ({entropy:.2f})")

            query_rate = len(self._query_timestamps[src])
            if query_rate > self.config.query_rate_threshold:
                suspicion_score += 2
                reasons.append(f"high query rate ({query_rate}/min)")

            if packet.dns_qtype in (16, 10, 255):
                suspicion_score += 2
                qtype_names = {16: "TXT", 10: "NULL", 255: "ANY"}
                qtype = qtype_names.get(packet.dns_qtype, 'unknown')
                reasons.append(f"unusual record type ({qtype})")

            digit_count = sum(c.isdigit() for c in subdomain)
            if digit_count > 0 and digit_count > len(subdomain) * 0.4:
                suspicion_score += 1
                reasons.append("high numeric ratio in subdomain")

            if suspicion_score >= 4:
                alert_key = f"dns_tunnel:{src}"
                if not self._recently_alerted(alert_key, now):
                    self._alerted[alert_key] = now
                    alerts.append({
                        "type": "DNS Tunneling",
                        "subtype": "Suspicious DNS Activity",
                        "severity": self.config.severity,
                        "src_ip": src,
                        "dst_ip": packet.dst_ip,
                        "description": (
                            f"Possible DNS tunneling from {src}: "
                            f"{', '.join(reasons)}"
                        ),
                        "details": {
                            "query": query,
                            "subdomain_length": len(subdomain),
                            "entropy": round(entropy, 2),
                            "query_rate": query_rate,
                            "suspicion_score": suspicion_score,
                            "indicators": reasons,
                        },
                    })

        return alerts

    def _recently_alerted(self, key: str, now: float) -> bool:
        last = self._alerted.get(key, 0)
        return now - last < 120
