"""Central detection engine that orchestrates all detectors."""

from __future__ import annotations

from pathlib import Path
from typing import Any

from shadowfence.capture.packet_parser import ParsedPacket
from shadowfence.config import ShadowFenceConfig
from shadowfence.detection.detectors.arp_spoof import ARPSpoofDetector
from shadowfence.detection.detectors.bandwidth_anomaly import (
    BandwidthAnomalyDetector,
)
from shadowfence.detection.detectors.brute_force import BruteForceDetector
from shadowfence.detection.detectors.ddos import DDoSDetector
from shadowfence.detection.detectors.dns_tunnel import DNSTunnelDetector
from shadowfence.detection.detectors.network_mapper import NetworkMapper
from shadowfence.detection.detectors.payload import PayloadDetector
from shadowfence.detection.detectors.port_scan import PortScanDetector
from shadowfence.detection.detectors.protocol_anomaly import (
    ProtocolAnomalyDetector,
)
from shadowfence.detection.detectors.ssl_anomaly import SSLAnomalyDetector
from shadowfence.detection.detectors.threat_intel import ThreatIntelDetector
from shadowfence.utils.helpers import severity_value


class DetectionEngine:
    """Orchestrates all threat detection modules."""

    def __init__(
        self,
        config: ShadowFenceConfig,
        rules_dir: str | Path | None = None,
    ):
        self.config = config
        self.min_severity = severity_value(
            config.detection.min_severity
        )

        self.port_scan = PortScanDetector(config.detection.port_scan)
        self.brute_force = BruteForceDetector(
            config.detection.brute_force
        )
        self.ddos = DDoSDetector(config.detection.ddos)
        self.arp_spoof = ARPSpoofDetector(config.detection.arp_spoof)
        self.dns_tunnel = DNSTunnelDetector(config.detection.dns_tunnel)
        self.payload = PayloadDetector(config.detection.payload)

        self.protocol_anomaly = ProtocolAnomalyDetector(
            config.detection.protocol_anomaly
        )
        self.bandwidth_anomaly = BandwidthAnomalyDetector(
            config.detection.bandwidth_anomaly
        )
        self.ssl_anomaly = SSLAnomalyDetector(
            enabled=config.detection.ssl_anomaly.enabled
        )
        self.threat_intel = ThreatIntelDetector(
            blocklist_path=(
                config.detection.threat_intel.blocklist_path or None
            ),
            enabled=config.detection.threat_intel.enabled,
        )
        self.network_mapper = NetworkMapper()

        if rules_dir:
            rules_path = Path(rules_dir) / "default_rules.yaml"
            if rules_path.exists():
                self.payload.load_rules(rules_path)

        self._alert_callbacks: list[Any] = []

    def register_alert_callback(self, callback: Any) -> None:
        """Register a callback to be called with each alert."""
        self._alert_callbacks.append(callback)

    def analyze(self, packet: ParsedPacket) -> list[dict]:
        """Run all detectors on a packet and return alerts."""
        if not self.config.detection.enabled:
            return []

        all_alerts: list[dict] = []

        all_alerts.extend(self.port_scan.analyze(packet))
        all_alerts.extend(self.brute_force.analyze(packet))
        all_alerts.extend(self.ddos.analyze(packet))
        all_alerts.extend(self.arp_spoof.analyze(packet))
        all_alerts.extend(self.dns_tunnel.analyze(packet))
        all_alerts.extend(self.payload.analyze(packet))
        all_alerts.extend(self.protocol_anomaly.analyze(packet))
        all_alerts.extend(self.bandwidth_anomaly.analyze(packet))
        all_alerts.extend(self.ssl_anomaly.analyze(packet))
        all_alerts.extend(self.threat_intel.analyze(packet))
        all_alerts.extend(self.network_mapper.process_packet(packet))

        filtered = [
            a
            for a in all_alerts
            if severity_value(a.get("severity", "info"))
            >= self.min_severity
        ]

        for alert in filtered:
            for callback in self._alert_callbacks:
                try:
                    callback(alert)
                except Exception:
                    pass

        return filtered
