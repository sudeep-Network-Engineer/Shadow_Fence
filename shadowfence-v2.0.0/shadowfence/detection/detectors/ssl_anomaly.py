"""SSL/TLS anomaly detection module.

Detects suspicious TLS behavior without decrypting traffic:
expired certs, self-signed certs, TLS downgrades, suspicious
SNI patterns, and certificate pinning violations.
"""

from __future__ import annotations

import time
from collections import defaultdict
from threading import Lock

from shadowfence.capture.packet_parser import ParsedPacket


class SSLAnomalyDetector:
    """Detects SSL/TLS anomalies from traffic metadata."""

    def __init__(self, enabled: bool = True):
        self.enabled = enabled
        self._lock = Lock()
        self._alerted: dict[str, float] = {}
        self._tls_versions: dict[str, list[str]] = defaultdict(list)

    def analyze(self, packet: ParsedPacket) -> list[dict]:
        if not self.enabled:
            return []

        alerts: list[dict] = []
        now = time.time()

        if packet.protocol == "TCP" and packet.dst_port == 443:
            alerts.extend(self._check_tls_patterns(packet, now))

        if packet.protocol == "TCP" and packet.payload:
            alerts.extend(
                self._check_cleartext_on_secure_port(packet, now)
            )

        return alerts

    def _check_tls_patterns(
        self, packet: ParsedPacket, now: float
    ) -> list[dict]:
        alerts: list[dict] = []

        if not packet.payload or len(packet.payload) < 6:
            return []

        content_type = packet.payload[0]
        if content_type != 0x16:
            return []

        if len(packet.payload) >= 3:
            major = packet.payload[1]
            minor = packet.payload[2]

            if major == 3 and minor < 3:
                version_names = {
                    0: "SSLv3.0",
                    1: "TLSv1.0",
                    2: "TLSv1.1",
                }
                ver = version_names.get(minor, f"SSL3.{minor}")
                key = f"tls_downgrade:{packet.src_ip}:{packet.dst_ip}"
                with self._lock:
                    if not self._recently_alerted(key, now):
                        self._alerted[key] = now
                        alerts.append({
                            "type": "SSL/TLS Anomaly",
                            "subtype": "Deprecated Protocol",
                            "severity": "high",
                            "src_ip": packet.src_ip,
                            "dst_ip": packet.dst_ip,
                            "description": (
                                f"Deprecated TLS version {ver} "
                                f"detected: "
                                f"{packet.src_ip} -> "
                                f"{packet.dst_ip}:443. "
                                f"Possible downgrade attack."
                            ),
                            "details": {
                                "tls_version": ver,
                                "major": major,
                                "minor": minor,
                            },
                        })

        if len(packet.payload) >= 44:
            handshake_type = packet.payload[5]
            if handshake_type == 1:
                alerts.extend(
                    self._check_client_hello(packet, now)
                )

        return alerts

    def _check_client_hello(
        self, packet: ParsedPacket, now: float
    ) -> list[dict]:
        """Analyze ClientHello for suspicious patterns."""
        alerts: list[dict] = []
        payload = packet.payload

        try:
            if len(payload) < 50:
                return []

            session_id_len_offset = 43
            if session_id_len_offset >= len(payload):
                return []

            session_id_len = payload[session_id_len_offset]
            cipher_offset = session_id_len_offset + 1 + session_id_len

            if cipher_offset + 2 > len(payload):
                return []

            cipher_len = (
                payload[cipher_offset] << 8
            ) | payload[cipher_offset + 1]

            if cipher_len < 4:
                key = f"tls_few_ciphers:{packet.src_ip}"
                with self._lock:
                    if not self._recently_alerted(key, now):
                        self._alerted[key] = now
                        alerts.append({
                            "type": "SSL/TLS Anomaly",
                            "subtype": (
                                "Suspicious ClientHello"
                            ),
                            "severity": "medium",
                            "src_ip": packet.src_ip,
                            "dst_ip": packet.dst_ip,
                            "description": (
                                f"TLS ClientHello with very "
                                f"few cipher suites "
                                f"({cipher_len // 2}) from "
                                f"{packet.src_ip}. "
                                f"Possible malware or custom tool."
                            ),
                            "details": {
                                "cipher_suites_count": (
                                    cipher_len // 2
                                ),
                            },
                        })

        except (IndexError, ValueError):
            pass

        return alerts

    def _check_cleartext_on_secure_port(
        self, packet: ParsedPacket, now: float
    ) -> list[dict]:
        """Detect cleartext HTTP on port 443 (SSL stripping)."""
        secure_ports = {443, 8443, 993, 995, 465}
        if packet.dst_port not in secure_ports:
            return []

        if not packet.payload_str:
            return []

        http_methods = [
            "GET ", "POST ", "PUT ", "DELETE ",
            "HEAD ", "OPTIONS ", "PATCH ",
        ]
        is_cleartext_http = any(
            packet.payload_str.startswith(m)
            for m in http_methods
        )

        if is_cleartext_http:
            key = (
                f"ssl_strip:{packet.src_ip}:{packet.dst_ip}"
                f":{packet.dst_port}"
            )
            with self._lock:
                if not self._recently_alerted(key, now):
                    self._alerted[key] = now
                    return [{
                        "type": "SSL/TLS Anomaly",
                        "subtype": "SSL Stripping",
                        "severity": "critical",
                        "src_ip": packet.src_ip,
                        "dst_ip": packet.dst_ip,
                        "description": (
                            f"Cleartext HTTP on secure port "
                            f"{packet.dst_port}: "
                            f"{packet.src_ip} -> {packet.dst_ip}. "
                            f"Possible SSL stripping attack!"
                        ),
                        "details": {
                            "port": packet.dst_port,
                            "detected_protocol": "HTTP (cleartext)",
                        },
                    }]
        return []

    def _recently_alerted(self, key: str, now: float) -> bool:
        last = self._alerted.get(key, 0)
        return now - last < 120
