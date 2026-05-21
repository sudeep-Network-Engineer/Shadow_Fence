"""Bandwidth anomaly detection module.

Detects unusual traffic volume spikes, data exfiltration attempts,
and abnormal bandwidth usage patterns using statistical analysis.
"""

from __future__ import annotations

import time
from collections import defaultdict, deque
from dataclasses import dataclass
from threading import Lock

from shadowfence.capture.packet_parser import ParsedPacket
from shadowfence.utils.helpers import format_bytes


@dataclass
class BandwidthAnomalyConfig:
    enabled: bool = True
    severity: str = "high"
    baseline_window: int = 300
    spike_multiplier: float = 5.0
    exfil_threshold_bytes: int = 104857600
    exfil_time_window: int = 300
    connection_burst_threshold: int = 100
    connection_burst_window: int = 10


class BandwidthAnomalyDetector:
    """Detects bandwidth anomalies and data exfiltration patterns."""

    def __init__(self, config: BandwidthAnomalyConfig):
        self.config = config
        self._lock = Lock()
        self._bandwidth_history: deque[tuple[float, int]] = deque(
            maxlen=10000
        )
        self._outbound_tracker: dict[str, list[tuple[float, int]]] = (
            defaultdict(list)
        )
        self._connection_tracker: dict[str, list[float]] = defaultdict(list)
        self._alerted: dict[str, float] = {}
        self._baseline_bps: float = 0.0

    def analyze(self, packet: ParsedPacket) -> list[dict]:
        if not self.config.enabled:
            return []

        alerts: list[dict] = []
        now = time.time()

        with self._lock:
            self._bandwidth_history.append((now, packet.length))
            alerts.extend(self._check_bandwidth_spike(now))
            if packet.src_ip:
                alerts.extend(
                    self._check_data_exfiltration(packet, now)
                )
                alerts.extend(
                    self._check_connection_burst(packet, now)
                )

        return alerts

    def _check_bandwidth_spike(self, now: float) -> list[dict]:
        window = self.config.baseline_window
        recent = [
            (t, s)
            for t, s in self._bandwidth_history
            if now - t <= 10
        ]
        baseline = [
            (t, s)
            for t, s in self._bandwidth_history
            if now - t <= window
        ]

        if len(baseline) < 100:
            return []

        baseline_duration = max(
            now - baseline[0][0], 1
        )
        baseline_bps = sum(s for _, s in baseline) / baseline_duration
        self._baseline_bps = baseline_bps

        if not recent:
            return []

        recent_duration = max(now - recent[0][0], 1)
        current_bps = sum(s for _, s in recent) / recent_duration

        if (
            baseline_bps > 0
            and current_bps > baseline_bps * self.config.spike_multiplier
        ):
            key = "bandwidth_spike"
            if not self._recently_alerted(key, now):
                self._alerted[key] = now
                return [{
                    "type": "Bandwidth Anomaly",
                    "subtype": "Traffic Spike",
                    "severity": self.config.severity,
                    "src_ip": "multiple",
                    "dst_ip": "multiple",
                    "description": (
                        f"Bandwidth spike detected: "
                        f"{format_bytes(int(current_bps))}/s "
                        f"vs baseline {format_bytes(int(baseline_bps))}/s "
                        f"({current_bps / baseline_bps:.1f}x increase)"
                    ),
                    "details": {
                        "current_bps": int(current_bps),
                        "baseline_bps": int(baseline_bps),
                        "multiplier": round(
                            current_bps / baseline_bps, 1
                        ),
                    },
                }]
        return []

    def _check_data_exfiltration(
        self, packet: ParsedPacket, now: float
    ) -> list[dict]:
        src = packet.src_ip
        self._outbound_tracker[src].append((now, packet.length))
        self._outbound_tracker[src] = [
            (t, s)
            for t, s in self._outbound_tracker[src]
            if now - t <= self.config.exfil_time_window
        ]

        total_bytes = sum(
            s for _, s in self._outbound_tracker[src]
        )

        if total_bytes >= self.config.exfil_threshold_bytes:
            key = f"exfil:{src}"
            if not self._recently_alerted(key, now):
                self._alerted[key] = now
                return [{
                    "type": "Data Exfiltration",
                    "subtype": "Large Outbound Transfer",
                    "severity": "critical",
                    "src_ip": src,
                    "dst_ip": packet.dst_ip,
                    "description": (
                        f"Possible data exfiltration from {src}: "
                        f"{format_bytes(total_bytes)} sent in "
                        f"{self.config.exfil_time_window}s"
                    ),
                    "details": {
                        "total_bytes": total_bytes,
                        "formatted": format_bytes(total_bytes),
                        "window": self.config.exfil_time_window,
                        "packet_count": len(
                            self._outbound_tracker[src]
                        ),
                    },
                }]
        return []

    def _check_connection_burst(
        self, packet: ParsedPacket, now: float
    ) -> list[dict]:
        if not packet.is_syn:
            return []

        src = packet.src_ip
        self._connection_tracker[src].append(now)
        self._connection_tracker[src] = [
            t
            for t in self._connection_tracker[src]
            if now - t <= self.config.connection_burst_window
        ]

        count = len(self._connection_tracker[src])
        if count >= self.config.connection_burst_threshold:
            key = f"conn_burst:{src}"
            if not self._recently_alerted(key, now):
                self._alerted[key] = now
                rate = count / self.config.connection_burst_window
                return [{
                    "type": "Bandwidth Anomaly",
                    "subtype": "Connection Burst",
                    "severity": "high",
                    "src_ip": src,
                    "dst_ip": packet.dst_ip,
                    "description": (
                        f"Connection burst from {src}: "
                        f"{count} new connections in "
                        f"{self.config.connection_burst_window}s "
                        f"({rate:.0f}/s)"
                    ),
                    "details": {
                        "connections": count,
                        "rate": round(rate, 1),
                        "window": self.config.connection_burst_window,
                    },
                }]
        return []

    def _recently_alerted(self, key: str, now: float) -> bool:
        last = self._alerted.get(key, 0)
        return now - last < 120
