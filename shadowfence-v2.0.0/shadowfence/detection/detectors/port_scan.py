"""Port scan detection module."""

from __future__ import annotations

import time
from collections import defaultdict
from dataclasses import dataclass, field
from threading import Lock

from shadowfence.capture.packet_parser import ParsedPacket
from shadowfence.config import PortScanConfig


@dataclass
class ScanTracker:
    ports: set[int] = field(default_factory=set)
    first_seen: float = 0.0
    last_seen: float = 0.0
    syn_count: int = 0
    alerted: bool = False


class PortScanDetector:
    """Detects port scanning activity from individual source IPs."""

    def __init__(self, config: PortScanConfig):
        self.config = config
        self._trackers: dict[str, dict[str, ScanTracker]] = defaultdict(dict)
        self._lock = Lock()

    def analyze(self, packet: ParsedPacket) -> list[dict]:
        """Analyze a packet for port scan indicators. Returns list of alerts."""
        if not self.config.enabled:
            return []
        if packet.protocol != "TCP" or not packet.is_syn:
            return []

        alerts = []
        now = time.time()
        src = packet.src_ip
        dst = packet.dst_ip

        with self._lock:
            if dst not in self._trackers[src]:
                self._trackers[src][dst] = ScanTracker(first_seen=now)

            tracker = self._trackers[src][dst]

            if now - tracker.first_seen > self.config.time_window:
                self._trackers[src][dst] = ScanTracker(first_seen=now)
                tracker = self._trackers[src][dst]

            tracker.ports.add(packet.dst_port)
            tracker.syn_count += 1
            tracker.last_seen = now

            if len(tracker.ports) >= self.config.threshold and not tracker.alerted:
                tracker.alerted = True
                scan_type = self._classify_scan(tracker)
                alerts.append({
                    "type": "Port Scan",
                    "subtype": scan_type,
                    "severity": self.config.severity,
                    "src_ip": src,
                    "dst_ip": dst,
                    "description": (
                        f"{scan_type} detected from {src} -> {dst}: "
                        f"{len(tracker.ports)} ports scanned in "
                        f"{now - tracker.first_seen:.1f}s"
                    ),
                    "details": {
                        "ports_scanned": sorted(tracker.ports),
                        "syn_count": tracker.syn_count,
                        "duration": round(now - tracker.first_seen, 2),
                        "scan_rate": round(
                            len(tracker.ports) / max(now - tracker.first_seen, 0.1), 1
                        ),
                    },
                })

            self._cleanup(now)

        return alerts

    def _classify_scan(self, tracker: ScanTracker) -> str:
        """Classify the type of port scan."""
        ports = sorted(tracker.ports)
        if len(ports) < 2:
            return "SYN Scan"

        sequential = sum(
            1 for i in range(len(ports) - 1) if ports[i + 1] - ports[i] == 1
        )
        if sequential > len(ports) * 0.7:
            return "Sequential Port Scan"

        well_known = {
            21, 22, 23, 25, 53, 80, 110, 143, 443, 445,
            993, 995, 3306, 3389, 5432, 8080, 8443,
        }
        if tracker.ports.issubset(well_known):
            return "Service Discovery Scan"

        duration = tracker.last_seen - tracker.first_seen
        if duration > 0 and tracker.syn_count / duration > 100:
            return "Aggressive SYN Scan"

        return "SYN Port Scan"

    def _cleanup(self, now: float) -> None:
        """Remove expired trackers."""
        expired_srcs = []
        for src, targets in self._trackers.items():
            expired_dsts = [
                dst for dst, t in targets.items()
                if now - t.last_seen > self.config.time_window * 2
            ]
            for dst in expired_dsts:
                del targets[dst]
            if not targets:
                expired_srcs.append(src)
        for src in expired_srcs:
            del self._trackers[src]
