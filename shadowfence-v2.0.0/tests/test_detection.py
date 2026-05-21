"""Tests for ShadowFence detection modules."""

from unittest.mock import MagicMock

from shadowfence.capture.packet_parser import ParsedPacket
from shadowfence.config import (
    ARPSpoofConfig,
    BruteForceConfig,
    DDoSConfig,
    DNSTunnelConfig,
    PayloadConfig,
    PortScanConfig,
    ShadowFenceConfig,
)
from shadowfence.detection.detectors.arp_spoof import ARPSpoofDetector
from shadowfence.detection.detectors.brute_force import BruteForceDetector
from shadowfence.detection.detectors.ddos import DDoSDetector
from shadowfence.detection.detectors.dns_tunnel import DNSTunnelDetector
from shadowfence.detection.detectors.payload import PayloadDetector
from shadowfence.detection.detectors.port_scan import PortScanDetector
from shadowfence.detection.engine import DetectionEngine
from shadowfence.utils.helpers import calculate_entropy, format_bytes, is_private_ip


class TestPortScanDetector:
    def test_detects_port_scan(self):
        config = PortScanConfig(threshold=5, time_window=60)
        detector = PortScanDetector(config)
        all_alerts = []

        for port in range(1, 10):
            pkt = ParsedPacket(
                protocol="TCP",
                src_ip="10.0.0.100",
                dst_ip="10.0.0.1",
                dst_port=port,
                is_syn=True,
                tcp_flags="S",
            )
            alerts = detector.analyze(pkt)
            all_alerts.extend(alerts)

        assert len(all_alerts) == 1
        assert all_alerts[0]["type"] == "Port Scan"
        assert all_alerts[0]["severity"] == "high"

    def test_no_alert_below_threshold(self):
        config = PortScanConfig(threshold=10, time_window=60)
        detector = PortScanDetector(config)

        for port in range(1, 5):
            pkt = ParsedPacket(
                protocol="TCP",
                src_ip="10.0.0.100",
                dst_ip="10.0.0.1",
                dst_port=port,
                is_syn=True,
                tcp_flags="S",
            )
            alerts = detector.analyze(pkt)
            assert len(alerts) == 0

    def test_disabled(self):
        config = PortScanConfig(enabled=False)
        detector = PortScanDetector(config)
        pkt = ParsedPacket(protocol="TCP", is_syn=True, dst_port=80)
        assert detector.analyze(pkt) == []


class TestBruteForceDetector:
    def test_detects_brute_force(self):
        config = BruteForceConfig(threshold=5, time_window=120)
        detector = BruteForceDetector(config)
        all_alerts = []

        for _ in range(10):
            pkt = ParsedPacket(
                protocol="TCP",
                src_ip="10.0.0.100",
                dst_ip="10.0.0.1",
                dst_port=22,
                is_syn=True,
                tcp_flags="S",
            )
            alerts = detector.analyze(pkt)
            all_alerts.extend(alerts)

        assert len(all_alerts) == 1
        assert "SSH" in all_alerts[0]["subtype"]

    def test_ignores_non_monitored_ports(self):
        config = BruteForceConfig(monitored_ports=[22, 3389])
        detector = BruteForceDetector(config)

        pkt = ParsedPacket(protocol="TCP", dst_port=8080, is_syn=True)
        assert detector.analyze(pkt) == []


class TestDDoSDetector:
    def test_detects_syn_flood(self):
        config = DDoSConfig(syn_flood_threshold=10, time_window=10)
        detector = DDoSDetector(config)
        all_alerts = []

        for i in range(200):
            pkt = ParsedPacket(
                protocol="TCP",
                src_ip=f"10.0.0.{i % 255}",
                dst_ip="192.168.1.1",
                dst_port=80,
                is_syn=True,
            )
            alerts = detector.analyze(pkt)
            all_alerts.extend(alerts)

        assert len(all_alerts) >= 1
        assert all_alerts[0]["subtype"] == "SYN Flood"


class TestARPSpoofDetector:
    def test_detects_mac_change(self):
        config = ARPSpoofConfig()
        detector = ARPSpoofDetector(config)

        pkt1 = ParsedPacket(
            protocol="ARP",
            arp_op=2,
            arp_src_ip="10.0.0.1",
            arp_src_mac="aa:bb:cc:dd:ee:ff",
            arp_dst_ip="10.0.0.100",
        )
        assert detector.analyze(pkt1) == []

        pkt2 = ParsedPacket(
            protocol="ARP",
            arp_op=2,
            arp_src_ip="10.0.0.1",
            arp_src_mac="11:22:33:44:55:66",
            arp_dst_ip="10.0.0.100",
        )
        alerts = detector.analyze(pkt2)
        assert len(alerts) == 1
        assert alerts[0]["type"] == "ARP Spoofing"


class TestDNSTunnelDetector:
    def test_detects_suspicious_dns(self):
        config = DNSTunnelConfig(
            query_length_threshold=20,
            entropy_threshold=2.5,
            query_rate_threshold=5,
        )
        detector = DNSTunnelDetector(config)

        long_subdomain = "a1b2c3d4e5f6g7h8i9j0k1l2m3n4o5p6q7r8s9t0"
        pkt = ParsedPacket(
            protocol="DNS",
            src_ip="10.0.0.100",
            dst_ip="8.8.8.8",
            dns_query=f"{long_subdomain}.evil.com",
            dns_qtype=16,
        )
        alerts = detector.analyze(pkt)
        assert len(alerts) == 1
        assert alerts[0]["type"] == "DNS Tunneling"


class TestPayloadDetector:
    def test_detects_sql_injection(self, tmp_path):
        rules_file = tmp_path / "rules.yaml"
        rules_file.write_text("""
rules:
  - name: "SQL Injection"
    description: "Test SQL injection rule"
    severity: critical
    protocol: tcp
    pattern: "(?i)(union\\\\s+select|' or 1=1)"
    enabled: true
""")
        config = PayloadConfig()
        detector = PayloadDetector(config, rules_path=rules_file)

        pkt = ParsedPacket(
            protocol="TCP",
            src_ip="10.0.0.100",
            dst_ip="10.0.0.1",
            dst_port=80,
            payload_str="GET /search?q=' or 1=1-- HTTP/1.1",
        )
        alerts = detector.analyze(pkt)
        assert len(alerts) == 1
        assert alerts[0]["type"] == "Signature Match"


class TestHelpers:
    def test_format_bytes(self):
        assert format_bytes(0) == "0 B"
        assert "KB" in format_bytes(1024)
        assert "MB" in format_bytes(1048576)

    def test_is_private_ip(self):
        assert is_private_ip("192.168.1.1")
        assert is_private_ip("10.0.0.1")
        assert is_private_ip("172.16.0.1")
        assert not is_private_ip("8.8.8.8")

    def test_calculate_entropy(self):
        assert calculate_entropy("") == 0.0
        assert calculate_entropy("aaaa") == 0.0
        assert calculate_entropy("abcd") > 1.0


class TestDetectionEngine:
    def test_engine_runs_all_detectors(self):
        config = ShadowFenceConfig()
        engine = DetectionEngine(config)

        callback = MagicMock()
        engine.register_alert_callback(callback)

        config.detection.port_scan.threshold = 3
        engine.port_scan.config.threshold = 3

        for port in range(1, 10):
            pkt = ParsedPacket(
                protocol="TCP",
                src_ip="10.0.0.100",
                dst_ip="10.0.0.1",
                dst_port=port,
                is_syn=True,
                tcp_flags="S",
            )
            engine.analyze(pkt)

        assert callback.call_count >= 1
