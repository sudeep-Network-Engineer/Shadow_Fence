"""Threat intelligence integration module.

Checks packet IPs against known malicious IP lists and maintains
a local threat intelligence database.
"""

from __future__ import annotations

import json
import logging
import time
from pathlib import Path
from threading import Lock

from shadowfence.capture.packet_parser import ParsedPacket

logger = logging.getLogger("shadowfence.threat_intel")


class ThreatIntelDetector:
    """Checks traffic against threat intelligence feeds."""

    def __init__(
        self,
        blocklist_path: str | Path | None = None,
        enabled: bool = True,
    ):
        self.enabled = enabled
        self._malicious_ips: set[str] = set()
        self._malicious_domains: set[str] = set()
        self._malicious_cidrs: list[tuple[int, int]] = []
        self._custom_watchlist: dict[str, str] = {}
        self._lock = Lock()
        self._alerted: dict[str, float] = {}

        if blocklist_path:
            self.load_blocklist(blocklist_path)

    def load_blocklist(self, path: str | Path) -> int:
        """Load a blocklist file (JSON or plain text, one IP per line)."""
        path = Path(path)
        if not path.exists():
            return 0

        count = 0
        try:
            content = path.read_text().strip()
            if content.startswith("{") or content.startswith("["):
                data = json.loads(content)
                if isinstance(data, dict):
                    for ip in data.get("ips", []):
                        self._malicious_ips.add(ip.strip())
                        count += 1
                    for domain in data.get("domains", []):
                        self._malicious_domains.add(
                            domain.strip().lower()
                        )
                        count += 1
                elif isinstance(data, list):
                    for item in data:
                        self._malicious_ips.add(str(item).strip())
                        count += 1
            else:
                for line in content.splitlines():
                    line = line.strip()
                    if line and not line.startswith("#"):
                        self._malicious_ips.add(line)
                        count += 1
        except Exception as e:
            logger.error(f"Failed to load blocklist: {e}")

        logger.info(f"Loaded {count} threat intelligence entries")
        return count

    def add_to_watchlist(self, ip: str, reason: str) -> None:
        """Add an IP to the custom watchlist."""
        with self._lock:
            self._custom_watchlist[ip] = reason

    def remove_from_watchlist(self, ip: str) -> None:
        """Remove an IP from the watchlist."""
        with self._lock:
            self._custom_watchlist.pop(ip, None)

    def analyze(self, packet: ParsedPacket) -> list[dict]:
        if not self.enabled:
            return []

        alerts: list[dict] = []
        now = time.time()

        for ip in [packet.src_ip, packet.dst_ip]:
            if not ip:
                continue

            if ip in self._malicious_ips:
                key = f"threat_intel:{ip}"
                with self._lock:
                    if not self._recently_alerted(key, now):
                        self._alerted[key] = now
                        direction = (
                            "from" if ip == packet.src_ip else "to"
                        )
                        alerts.append({
                            "type": "Threat Intelligence",
                            "subtype": "Known Malicious IP",
                            "severity": "critical",
                            "src_ip": packet.src_ip,
                            "dst_ip": packet.dst_ip,
                            "description": (
                                f"Traffic {direction} known malicious "
                                f"IP {ip} detected "
                                f"({packet.protocol} "
                                f"{packet.src_ip}:{packet.src_port} -> "
                                f"{packet.dst_ip}:{packet.dst_port})"
                            ),
                            "details": {
                                "malicious_ip": ip,
                                "direction": direction,
                                "protocol": packet.protocol,
                            },
                        })

            if ip in self._custom_watchlist:
                key = f"watchlist:{ip}"
                with self._lock:
                    if not self._recently_alerted(key, now):
                        self._alerted[key] = now
                        alerts.append({
                            "type": "Threat Intelligence",
                            "subtype": "Watchlist Match",
                            "severity": "high",
                            "src_ip": packet.src_ip,
                            "dst_ip": packet.dst_ip,
                            "description": (
                                f"Watchlisted IP {ip} detected: "
                                f"{self._custom_watchlist[ip]}"
                            ),
                            "details": {
                                "watchlisted_ip": ip,
                                "reason": self._custom_watchlist[ip],
                            },
                        })

        if packet.dns_query:
            domain = packet.dns_query.lower()
            for mal_domain in self._malicious_domains:
                if domain == mal_domain or domain.endswith(
                    f".{mal_domain}"
                ):
                    key = f"threat_domain:{domain}"
                    with self._lock:
                        if not self._recently_alerted(key, now):
                            self._alerted[key] = now
                            alerts.append({
                                "type": "Threat Intelligence",
                                "subtype": "Known Malicious Domain",
                                "severity": "critical",
                                "src_ip": packet.src_ip,
                                "dst_ip": packet.dst_ip,
                                "description": (
                                    f"DNS query to known malicious "
                                    f"domain: {domain} from "
                                    f"{packet.src_ip}"
                                ),
                                "details": {
                                    "domain": domain,
                                    "matched_rule": mal_domain,
                                },
                            })
                    break

        return alerts

    def _recently_alerted(self, key: str, now: float) -> bool:
        last = self._alerted.get(key, 0)
        return now - last < 300

    def get_stats(self) -> dict:
        return {
            "malicious_ips": len(self._malicious_ips),
            "malicious_domains": len(self._malicious_domains),
            "watchlist_entries": len(self._custom_watchlist),
        }
