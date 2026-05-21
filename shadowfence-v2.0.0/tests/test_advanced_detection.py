"""Tests for advanced detection modules."""

from shadowfence.capture.packet_parser import ParsedPacket
from shadowfence.detection.detectors.bandwidth_anomaly import (
    BandwidthAnomalyConfig,
    BandwidthAnomalyDetector,
)
from shadowfence.detection.detectors.network_mapper import NetworkMapper
from shadowfence.detection.detectors.protocol_anomaly import (
    ProtocolAnomalyConfig,
    ProtocolAnomalyDetector,
)
from shadowfence.detection.detectors.ssl_anomaly import SSLAnomalyDetector
from shadowfence.detection.detectors.threat_intel import ThreatIntelDetector


class TestProtocolAnomalyDetector:
    def test_detects_land_attack(self):
        config = ProtocolAnomalyConfig()
        detector = ProtocolAnomalyDetector(config)

        pkt = ParsedPacket(
            protocol="TCP",
            src_ip="10.0.0.1",
            dst_ip="10.0.0.1",
            src_port=80,
            dst_port=80,
            tcp_flags="S",
        )
        alerts = detector.analyze(pkt)
        assert len(alerts) == 1
        assert alerts[0]["subtype"] == "LAND Attack"

    def test_detects_xmas_scan(self):
        config = ProtocolAnomalyConfig()
        detector = ProtocolAnomalyDetector(config)

        pkt = ParsedPacket(
            protocol="TCP",
            src_ip="10.0.0.100",
            dst_ip="10.0.0.1",
            tcp_flags="FPU",
        )
        alerts = detector.analyze(pkt)
        assert len(alerts) == 1
        assert alerts[0]["subtype"] == "XMAS Scan"

    def test_detects_smurf_attack(self):
        config = ProtocolAnomalyConfig()
        detector = ProtocolAnomalyDetector(config)

        pkt = ParsedPacket(
            protocol="ICMP",
            src_ip="10.0.0.100",
            dst_ip="10.0.0.255",
            icmp_type=8,
        )
        alerts = detector.analyze(pkt)
        assert len(alerts) == 1
        assert alerts[0]["subtype"] == "Smurf Attack"


class TestBandwidthAnomalyDetector:
    def test_detects_connection_burst(self):
        config = BandwidthAnomalyConfig(
            connection_burst_threshold=5,
            connection_burst_window=60,
        )
        detector = BandwidthAnomalyDetector(config)
        all_alerts = []

        for i in range(10):
            pkt = ParsedPacket(
                protocol="TCP",
                src_ip="10.0.0.100",
                dst_ip="10.0.0.1",
                dst_port=80 + i,
                is_syn=True,
                length=64,
            )
            alerts = detector.analyze(pkt)
            all_alerts.extend(alerts)

        burst_alerts = [
            a for a in all_alerts
            if a.get("subtype") == "Connection Burst"
        ]
        assert len(burst_alerts) >= 1


class TestThreatIntelDetector:
    def test_detects_malicious_ip(self):
        detector = ThreatIntelDetector(enabled=True)
        detector._malicious_ips.add("198.51.100.1")

        pkt = ParsedPacket(
            protocol="TCP",
            src_ip="198.51.100.1",
            dst_ip="10.0.0.1",
            dst_port=80,
        )
        alerts = detector.analyze(pkt)
        assert len(alerts) == 1
        assert alerts[0]["type"] == "Threat Intelligence"

    def test_detects_malicious_domain(self):
        detector = ThreatIntelDetector(enabled=True)
        detector._malicious_domains.add("evil.com")

        pkt = ParsedPacket(
            protocol="DNS",
            src_ip="10.0.0.100",
            dst_ip="8.8.8.8",
            dns_query="payload.evil.com",
        )
        alerts = detector.analyze(pkt)
        assert len(alerts) == 1
        assert alerts[0]["subtype"] == "Known Malicious Domain"

    def test_blocklist_loading(self, tmp_path):
        blocklist = tmp_path / "blocklist.json"
        blocklist.write_text(
            '{"ips": ["1.2.3.4", "5.6.7.8"], '
            '"domains": ["bad.com"]}'
        )
        detector = ThreatIntelDetector(
            blocklist_path=blocklist, enabled=True
        )
        stats = detector.get_stats()
        assert stats["malicious_ips"] == 2
        assert stats["malicious_domains"] == 1


class TestSSLAnomalyDetector:
    def test_detects_cleartext_on_443(self):
        detector = SSLAnomalyDetector(enabled=True)
        pkt = ParsedPacket(
            protocol="TCP",
            src_ip="10.0.0.100",
            dst_ip="10.0.0.1",
            dst_port=443,
            payload=b"GET /login HTTP/1.1\r\nHost: example.com",
            payload_str="GET /login HTTP/1.1\r\nHost: example.com",
        )
        alerts = detector.analyze(pkt)
        assert len(alerts) == 1
        assert alerts[0]["subtype"] == "SSL Stripping"


class TestNetworkMapper:
    def test_discovers_new_device(self):
        mapper = NetworkMapper()
        pkt = ParsedPacket(
            protocol="TCP",
            src_ip="192.168.1.100",
            src_mac="aa:bb:cc:dd:ee:ff",
            dst_ip="192.168.1.1",
            dst_port=80,
        )
        alerts = mapper.process_packet(pkt)
        discovery = [
            a for a in alerts
            if a.get("type") == "Network Discovery"
        ]
        assert len(discovery) >= 1

        assets = mapper.get_assets()
        assert "192.168.1.100" in assets
        assert assets["192.168.1.100"]["mac"] == "aa:bb:cc:dd:ee:ff"

    def test_topology(self):
        mapper = NetworkMapper()
        for i in range(5):
            pkt = ParsedPacket(
                protocol="TCP",
                src_ip=f"192.168.1.{100 + i}",
                dst_ip="192.168.1.1",
                dst_port=80,
            )
            mapper.process_packet(pkt)

        topo = mapper.get_topology()
        assert len(topo["nodes"]) >= 5
        assert len(topo["edges"]) >= 4
