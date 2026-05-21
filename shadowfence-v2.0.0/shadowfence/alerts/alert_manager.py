"""Central alert management system."""

from __future__ import annotations

import threading
from collections import deque
from typing import Any

from shadowfence.config import ShadowFenceConfig
from shadowfence.logging.logger import AlertLogger
from shadowfence.utils.helpers import severity_color, timestamp_now

try:
    from rich.console import Console
    from rich.panel import Panel
    from rich.text import Text

    HAS_RICH = True
except ImportError:
    HAS_RICH = False


class AlertManager:
    """Manages alert routing, rate limiting, and dispatch."""

    def __init__(self, config: ShadowFenceConfig):
        self.config = config
        self.alert_logger = AlertLogger()
        self._recent_alerts: deque[dict] = deque(maxlen=config.dashboard.max_events)
        self._alert_count = 0
        self._lock = threading.Lock()
        self._alert_callbacks: list[Any] = []
        self._console = Console() if HAS_RICH else None

    def register_callback(self, callback: Any) -> None:
        """Register a callback for real-time alert notifications."""
        self._alert_callbacks.append(callback)

    def handle_alert(self, alert: dict) -> None:
        """Process and dispatch a security alert."""
        alert["timestamp"] = timestamp_now()
        alert["id"] = self._alert_count

        with self._lock:
            self._alert_count += 1
            self._recent_alerts.append(alert)

        self.alert_logger.log_alert(alert)

        if self.config.alerts.console.get("enabled", True):
            self._console_alert(alert)

        for callback in self._alert_callbacks:
            try:
                callback(alert)
            except Exception:
                pass

    def _console_alert(self, alert: dict) -> None:
        """Print alert to console with rich formatting."""
        severity = alert.get("severity", "info")
        alert_type = alert.get("type", "Unknown")
        description = alert.get("description", "")
        src = alert.get("src_ip", "?")
        dst = alert.get("dst_ip", "?")

        if HAS_RICH and self._console:
            color = severity_color(severity)
            title = f"[{color}][{severity.upper()}] {alert_type}[/{color}]"
            body = Text()
            body.append(f"{description}\n", style="white")
            body.append(f"Source: {src}  |  Target: {dst}", style="dim")
            self._console.print(Panel(body, title=title, border_style=color))
        else:
            print(f"[{severity.upper()}] {alert_type}: {description} ({src} -> {dst})")

    def get_recent_alerts(self, count: int = 100) -> list[dict]:
        """Get recent alerts."""
        with self._lock:
            return list(self._recent_alerts)[-count:]

    def get_stats(self) -> dict:
        """Get alert statistics."""
        with self._lock:
            alerts = list(self._recent_alerts)

        severity_counts: dict[str, int] = {}
        type_counts: dict[str, int] = {}
        for a in alerts:
            sev = a.get("severity", "unknown")
            severity_counts[sev] = severity_counts.get(sev, 0) + 1
            atype = a.get("type", "unknown")
            type_counts[atype] = type_counts.get(atype, 0) + 1

        return {
            "total_alerts": self._alert_count,
            "recent_count": len(alerts),
            "by_severity": severity_counts,
            "by_type": type_counts,
        }
