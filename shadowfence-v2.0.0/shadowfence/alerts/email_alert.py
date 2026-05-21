"""Email alert system for ShadowFence."""

from __future__ import annotations

import json
import logging
import smtplib
import threading
import time
from collections import deque
from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText

from shadowfence.config import EmailConfig

logger = logging.getLogger("shadowfence.email")


class EmailAlertSender:
    """Sends email alerts with rate limiting and batching."""

    def __init__(self, config: EmailConfig):
        self.config = config
        self._pending: deque[dict] = deque(maxlen=1000)
        self._last_sent: dict[str, float] = {}
        self._lock = threading.Lock()
        self._running = False
        self._thread: threading.Thread | None = None

    def start(self) -> None:
        """Start the email batch sender thread."""
        if not self.config.enabled:
            return
        if not self.config.to_addrs:
            logger.warning("Email alerts enabled but no recipients configured")
            return
        self._running = True
        self._thread = threading.Thread(target=self._batch_loop, daemon=True)
        self._thread.start()
        logger.info("Email alert sender started")

    def stop(self) -> None:
        """Stop the email sender and flush pending alerts."""
        self._running = False
        if self._thread and self._thread.is_alive():
            self._thread.join(timeout=10)
        with self._lock:
            if self._pending:
                self._send_batch(list(self._pending))
                self._pending.clear()

    def queue_alert(self, alert: dict) -> None:
        """Queue an alert for email notification."""
        if not self.config.enabled:
            return

        alert_type = alert.get("type", "unknown")
        now = time.time()

        with self._lock:
            last = self._last_sent.get(alert_type, 0)
            if now - last < self.config.min_interval:
                return
            self._pending.append(alert)

    def _batch_loop(self) -> None:
        """Background loop to batch and send alerts."""
        while self._running:
            time.sleep(self.config.batch_interval)
            with self._lock:
                if self._pending:
                    batch = list(self._pending)
                    self._pending.clear()
                else:
                    batch = []

            if batch:
                self._send_batch(batch)

    def _send_batch(self, alerts: list[dict]) -> None:
        """Send a batch of alerts as a single email digest."""
        if not alerts:
            return

        try:
            msg = MIMEMultipart("alternative")
            msg["From"] = self.config.from_addr
            msg["To"] = ", ".join(self.config.to_addrs)

            critical_count = sum(1 for a in alerts if a.get("severity") == "critical")
            high_count = sum(1 for a in alerts if a.get("severity") == "high")

            if critical_count:
                msg["Subject"] = (
                    f"[CRITICAL] ShadowFence: {critical_count} critical alert(s) detected"
                )
            elif high_count:
                msg["Subject"] = (
                    f"[HIGH] ShadowFence: {high_count} high-severity alert(s) detected"
                )
            else:
                msg["Subject"] = (
                    f"[ALERT] ShadowFence: {len(alerts)} security alert(s) detected"
                )

            text_body = self._build_text_body(alerts)
            html_body = self._build_html_body(alerts)

            msg.attach(MIMEText(text_body, "plain"))
            msg.attach(MIMEText(html_body, "html"))

            with smtplib.SMTP(self.config.smtp_server, self.config.smtp_port) as server:
                if self.config.use_tls:
                    server.starttls()
                if self.config.username and self.config.password:
                    server.login(self.config.username, self.config.password)
                server.sendmail(
                    self.config.from_addr,
                    self.config.to_addrs,
                    msg.as_string(),
                )

            for a in alerts:
                self._last_sent[a.get("type", "unknown")] = time.time()

            logger.info(f"Email alert sent: {len(alerts)} alert(s) to {len(self.config.to_addrs)} recipient(s)")

        except Exception as e:
            logger.error(f"Failed to send email alert: {e}")

    def _build_text_body(self, alerts: list[dict]) -> str:
        """Build plain text email body."""
        lines = [
            "=" * 60,
            "ShadowFence - Security Alert Digest",
            "=" * 60,
            f"Total alerts: {len(alerts)}",
            "",
        ]

        for i, alert in enumerate(alerts, 1):
            lines.extend([
                f"--- Alert #{i} ---",
                f"  Type:     {alert.get('type', 'Unknown')} ({alert.get('subtype', '')})",
                f"  Severity: {alert.get('severity', 'unknown').upper()}",
                f"  Time:     {alert.get('timestamp', 'N/A')}",
                f"  Source:   {alert.get('src_ip', '?')}",
                f"  Target:   {alert.get('dst_ip', '?')}",
                f"  Details:  {alert.get('description', '')}",
                "",
            ])

            if self.config.include_packet_dump and "details" in alert:
                lines.append(f"  Technical: {json.dumps(alert['details'], indent=4)}")
                lines.append("")

        lines.extend([
            "=" * 60,
            "This alert was generated by ShadowFence IDS.",
            "Review your dashboard for more details.",
        ])

        return "\n".join(lines)

    def _build_html_body(self, alerts: list[dict]) -> str:
        """Build HTML email body with styling."""
        severity_colors = {
            "critical": "#dc2626",
            "high": "#ea580c",
            "medium": "#ca8a04",
            "low": "#2563eb",
            "info": "#6b7280",
        }

        alert_rows = ""
        for alert in alerts:
            sev = alert.get("severity", "info")
            color = severity_colors.get(sev, "#6b7280")
            alert_rows += f"""
            <tr>
                <td style="padding:10px;border-bottom:1px solid #e5e7eb;">
                    <span style="background:{color};color:white;padding:2px 8px;border-radius:4px;font-size:12px;font-weight:bold;">
                        {sev.upper()}
                    </span>
                </td>
                <td style="padding:10px;border-bottom:1px solid #e5e7eb;font-weight:bold;">{alert.get('type', 'Unknown')}</td>
                <td style="padding:10px;border-bottom:1px solid #e5e7eb;">{alert.get('src_ip', '?')}</td>
                <td style="padding:10px;border-bottom:1px solid #e5e7eb;">{alert.get('dst_ip', '?')}</td>
                <td style="padding:10px;border-bottom:1px solid #e5e7eb;font-size:13px;">{alert.get('description', '')}</td>
            </tr>"""

        return f"""
        <html>
        <body style="font-family:-apple-system,BlinkMacSystemFont,'Segoe UI',Roboto,sans-serif;background:#f9fafb;padding:20px;">
            <div style="max-width:900px;margin:0 auto;background:white;border-radius:12px;box-shadow:0 1px 3px rgba(0,0,0,0.1);overflow:hidden;">
                <div style="background:linear-gradient(135deg,#1e3a5f,#2563eb);padding:24px 32px;color:white;">
                    <h1 style="margin:0;font-size:24px;">ShadowFence Alert Digest</h1>
                    <p style="margin:8px 0 0;opacity:0.85;">{len(alerts)} security alert(s) detected on your network</p>
                </div>
                <div style="padding:24px;">
                    <table style="width:100%;border-collapse:collapse;">
                        <thead>
                            <tr style="background:#f3f4f6;">
                                <th style="padding:10px;text-align:left;font-size:13px;">Severity</th>
                                <th style="padding:10px;text-align:left;font-size:13px;">Type</th>
                                <th style="padding:10px;text-align:left;font-size:13px;">Source</th>
                                <th style="padding:10px;text-align:left;font-size:13px;">Target</th>
                                <th style="padding:10px;text-align:left;font-size:13px;">Description</th>
                            </tr>
                        </thead>
                        <tbody>{alert_rows}</tbody>
                    </table>
                </div>
                <div style="background:#f3f4f6;padding:16px 32px;text-align:center;font-size:13px;color:#6b7280;">
                    Generated by <strong>ShadowFence</strong> Intrusion Detection System
                </div>
            </div>
        </body>
        </html>"""
