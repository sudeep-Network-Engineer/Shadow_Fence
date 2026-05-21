"""Payload / signature-based detection module."""

from __future__ import annotations

import re
import time
from pathlib import Path
from threading import Lock
from typing import Any

import yaml

from shadowfence.capture.packet_parser import ParsedPacket
from shadowfence.config import PayloadConfig


class PayloadDetector:
    """Detects threats using signature-based pattern matching on packet payloads."""

    def __init__(self, config: PayloadConfig, rules_path: str | Path | None = None):
        self.config = config
        self._rules: list[dict[str, Any]] = []
        self._compiled_rules: list[tuple[dict[str, Any], re.Pattern]] = []
        self._lock = Lock()
        self._alerted: dict[str, float] = {}

        if rules_path:
            self.load_rules(rules_path)

    def load_rules(self, rules_path: str | Path) -> int:
        """Load detection rules from a YAML file. Returns count of loaded rules."""
        path = Path(rules_path)
        if not path.exists():
            return 0

        with open(path) as f:
            data = yaml.safe_load(f) or {}

        rules = data.get("rules", [])
        self._rules = []
        self._compiled_rules = []

        for rule in rules:
            if not rule.get("enabled", True):
                continue
            pattern_str = rule.get("pattern", "")
            if not pattern_str:
                continue
            try:
                compiled = re.compile(pattern_str, re.IGNORECASE | re.DOTALL)
                self._rules.append(rule)
                self._compiled_rules.append((rule, compiled))
            except re.error:
                continue

        return len(self._compiled_rules)

    def analyze(self, packet: ParsedPacket) -> list[dict]:
        """Analyze packet payload against loaded signatures."""
        if not self.config.enabled:
            return []
        if not packet.payload_str:
            return []

        alerts = []
        now = time.time()
        payload = packet.payload_str[: self.config.max_payload_size]

        for rule, pattern in self._compiled_rules:
            rule_proto = rule.get("protocol", "any")
            if rule_proto != "any" and rule_proto.upper() != packet.protocol:
                continue

            rule_dst_port = rule.get("dst_port")
            if rule_dst_port is not None and rule_dst_port != packet.dst_port:
                continue

            match = pattern.search(payload)
            if match:
                alert_key = f"payload:{rule['name']}:{packet.src_ip}:{packet.dst_ip}"

                with self._lock:
                    if not self._recently_alerted(alert_key, now):
                        self._alerted[alert_key] = now
                        matched_text = match.group(0)[:100]
                        alerts.append({
                            "type": "Signature Match",
                            "subtype": rule["name"],
                            "severity": rule.get("severity", self.config.severity),
                            "src_ip": packet.src_ip,
                            "dst_ip": packet.dst_ip,
                            "description": (
                                f"{rule['name']}: {rule.get('description', 'Pattern matched')} "
                                f"| {packet.src_ip}:{packet.src_port} -> "
                                f"{packet.dst_ip}:{packet.dst_port}"
                            ),
                            "details": {
                                "rule_name": rule["name"],
                                "matched_pattern": matched_text,
                                "action": rule.get("action", "alert"),
                                "protocol": packet.protocol,
                                "src_port": packet.src_port,
                                "dst_port": packet.dst_port,
                            },
                        })

        return alerts

    def _recently_alerted(self, key: str, now: float) -> bool:
        last = self._alerted.get(key, 0)
        return now - last < 30

    def get_rule_count(self) -> int:
        return len(self._compiled_rules)
