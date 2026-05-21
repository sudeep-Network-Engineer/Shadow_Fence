"""Configuration loader for ShadowFence."""

from __future__ import annotations

import os
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

import yaml


@dataclass
class CaptureConfig:
    promiscuous: bool = True
    snap_length: int = 65535
    buffer_size: int = 2097152
    filter: str = ""
    pcap_export: bool = False
    pcap_dir: str = "captures"
    pcap_max_size: int = 104857600
    pcap_max_files: int = 10


@dataclass
class PortScanConfig:
    enabled: bool = True
    threshold: int = 15
    time_window: int = 60
    severity: str = "high"


@dataclass
class BruteForceConfig:
    enabled: bool = True
    threshold: int = 10
    time_window: int = 120
    monitored_ports: list[int] = field(
        default_factory=lambda: [
            22, 23, 3389, 5900, 21, 3306, 5432, 1433, 27017,
        ]
    )
    severity: str = "high"


@dataclass
class DDoSConfig:
    enabled: bool = True
    syn_flood_threshold: int = 500
    udp_flood_threshold: int = 1000
    icmp_flood_threshold: int = 200
    http_flood_threshold: int = 300
    time_window: int = 10
    severity: str = "critical"


@dataclass
class ARPSpoofConfig:
    enabled: bool = True
    severity: str = "critical"


@dataclass
class DNSTunnelConfig:
    enabled: bool = True
    query_length_threshold: int = 50
    query_rate_threshold: int = 100
    entropy_threshold: float = 3.5
    severity: str = "high"


@dataclass
class PayloadConfig:
    enabled: bool = True
    max_payload_size: int = 8192
    severity: str = "medium"


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


@dataclass
class SSLAnomalyConfig:
    enabled: bool = True


@dataclass
class ThreatIntelConfig:
    enabled: bool = True
    blocklist_path: str = ""
    auto_update: bool = False


@dataclass
class FirewallConfig:
    enabled: bool = False
    auto_block: bool = False
    block_duration: int = 3600
    whitelist: list[str] = field(
        default_factory=lambda: ["127.0.0.1", "::1"]
    )
    min_severity_to_block: str = "high"
    max_blocks: int = 1000
    log_file: str = "firewall_actions.log"
    dry_run: bool = True


@dataclass
class NetworkMapConfig:
    enabled: bool = True


@dataclass
class DetectionConfig:
    enabled: bool = True
    min_severity: str = "low"
    port_scan: PortScanConfig = field(default_factory=PortScanConfig)
    brute_force: BruteForceConfig = field(
        default_factory=BruteForceConfig
    )
    ddos: DDoSConfig = field(default_factory=DDoSConfig)
    arp_spoof: ARPSpoofConfig = field(
        default_factory=ARPSpoofConfig
    )
    dns_tunnel: DNSTunnelConfig = field(
        default_factory=DNSTunnelConfig
    )
    payload: PayloadConfig = field(default_factory=PayloadConfig)
    protocol_anomaly: ProtocolAnomalyConfig = field(
        default_factory=ProtocolAnomalyConfig
    )
    bandwidth_anomaly: BandwidthAnomalyConfig = field(
        default_factory=BandwidthAnomalyConfig
    )
    ssl_anomaly: SSLAnomalyConfig = field(
        default_factory=SSLAnomalyConfig
    )
    threat_intel: ThreatIntelConfig = field(
        default_factory=ThreatIntelConfig
    )
    firewall: FirewallConfig = field(
        default_factory=FirewallConfig
    )
    network_map: NetworkMapConfig = field(
        default_factory=NetworkMapConfig
    )


@dataclass
class EmailConfig:
    enabled: bool = False
    smtp_server: str = "smtp.gmail.com"
    smtp_port: int = 587
    use_tls: bool = True
    username: str = ""
    password: str = ""
    from_addr: str = ""
    to_addrs: list[str] = field(default_factory=list)
    min_interval: int = 300
    batch_interval: int = 60
    include_packet_dump: bool = True


@dataclass
class WebhookConfig:
    enabled: bool = False
    url: str = ""
    method: str = "POST"
    headers: dict[str, str] = field(
        default_factory=lambda: {"Content-Type": "application/json"}
    )


@dataclass
class AlertConfig:
    console: dict[str, Any] = field(
        default_factory=lambda: {"enabled": True, "colors": True}
    )
    email: EmailConfig = field(default_factory=EmailConfig)
    webhook: WebhookConfig = field(default_factory=WebhookConfig)


@dataclass
class DashboardConfig:
    enabled: bool = True
    host: str = "0.0.0.0"
    port: int = 8443
    max_events: int = 10000
    update_interval: int = 1000


@dataclass
class LoggingConfig:
    level: str = "INFO"
    file: str = "shadowfence.log"
    max_size: int = 52428800
    backup_count: int = 5
    log_packets: bool = False


@dataclass
class PerformanceConfig:
    worker_threads: int = 4
    packet_queue_size: int = 10000
    batch_processing: bool = True
    batch_size: int = 100


@dataclass
class ShadowFenceConfig:
    interface: str = "any"
    capture: CaptureConfig = field(default_factory=CaptureConfig)
    detection: DetectionConfig = field(
        default_factory=DetectionConfig
    )
    alerts: AlertConfig = field(default_factory=AlertConfig)
    dashboard: DashboardConfig = field(
        default_factory=DashboardConfig
    )
    logging: LoggingConfig = field(default_factory=LoggingConfig)
    performance: PerformanceConfig = field(
        default_factory=PerformanceConfig
    )


def _merge_dataclass(dc: Any, data: dict[str, Any]) -> None:
    """Recursively merge dictionary values into a dataclass."""
    for key, value in data.items():
        if not hasattr(dc, key):
            continue
        current = getattr(dc, key)
        if isinstance(value, dict) and hasattr(
            current, "__dataclass_fields__"
        ):
            _merge_dataclass(current, value)
        else:
            setattr(dc, key, value)


def load_config(
    config_path: str | Path | None = None,
) -> ShadowFenceConfig:
    """Load configuration from YAML, falling back to defaults."""
    config = ShadowFenceConfig()

    if config_path is None:
        config_path = os.environ.get(
            "SHADOWFENCE_CONFIG", "config.yaml"
        )

    path = Path(config_path)
    if path.exists():
        with open(path) as f:
            data = yaml.safe_load(f) or {}
        if "interface" in data:
            config.interface = data["interface"]
        sections = [
            "capture", "detection", "alerts",
            "dashboard", "logging", "performance",
        ]
        for section in sections:
            if section in data:
                section_obj = getattr(config, section)
                if isinstance(data[section], dict):
                    _merge_dataclass(section_obj, data[section])

    env_smtp = os.environ.get("SHADOWFENCE_SMTP_SERVER")
    env_smtp_user = os.environ.get("SHADOWFENCE_SMTP_USER")
    env_smtp_pass = os.environ.get("SHADOWFENCE_SMTP_PASS")
    env_email_from = os.environ.get("SHADOWFENCE_EMAIL_FROM")
    env_email_to = os.environ.get("SHADOWFENCE_EMAIL_TO")

    if env_smtp:
        config.alerts.email.smtp_server = env_smtp
    if env_smtp_user:
        config.alerts.email.username = env_smtp_user
    if env_smtp_pass:
        config.alerts.email.password = env_smtp_pass
    if env_email_from:
        config.alerts.email.from_addr = env_email_from
    if env_email_to:
        config.alerts.email.to_addrs = [
            a.strip() for a in env_email_to.split(",")
        ]

    return config
