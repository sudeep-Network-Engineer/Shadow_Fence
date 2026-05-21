"""Automated firewall response module.

Integrates with iptables (Linux) and Windows Firewall to automatically
block malicious IPs detected by the IDS. Includes auto-unblock timer.
"""

from __future__ import annotations

import logging
import platform
import subprocess
import time
from dataclasses import dataclass, field
from threading import Lock, Thread

logger = logging.getLogger("shadowfence.firewall")


@dataclass
class FirewallConfig:
    enabled: bool = False
    auto_block: bool = False
    block_duration: int = 3600
    whitelist: list[str] = field(
        default_factory=lambda: [
            "127.0.0.1", "::1",
        ]
    )
    min_severity_to_block: str = "high"
    max_blocks: int = 1000
    log_file: str = "firewall_actions.log"
    dry_run: bool = True


class FirewallManager:
    """Manages automated firewall rules based on IDS alerts."""

    def __init__(self, config: FirewallConfig):
        self.config = config
        self._blocked_ips: dict[str, float] = {}
        self._block_reasons: dict[str, str] = {}
        self._lock = Lock()
        self._os = platform.system().lower()
        self._cleanup_running = False
        self._cleanup_thread: Thread | None = None
        self._action_log: list[dict] = []

    def start(self) -> None:
        """Start the firewall manager with auto-cleanup."""
        if not self.config.enabled:
            return
        self._cleanup_running = True
        self._cleanup_thread = Thread(
            target=self._cleanup_loop, daemon=True
        )
        self._cleanup_thread.start()
        logger.info(
            f"Firewall manager started "
            f"(dry_run={self.config.dry_run}, "
            f"auto_block={self.config.auto_block})"
        )

    def stop(self) -> None:
        """Stop and optionally unblock all IPs."""
        self._cleanup_running = False
        if self._cleanup_thread:
            self._cleanup_thread.join(timeout=5)

    def handle_alert(self, alert: dict) -> None:
        """Process an alert and optionally block the source IP."""
        if not self.config.enabled or not self.config.auto_block:
            return

        severity = alert.get("severity", "info")
        severity_rank = {
            "info": 0, "low": 1, "medium": 2,
            "high": 3, "critical": 4,
        }
        min_rank = severity_rank.get(
            self.config.min_severity_to_block, 3
        )

        if severity_rank.get(severity, 0) < min_rank:
            return

        src_ip = alert.get("src_ip", "")
        if not src_ip or src_ip == "multiple":
            return

        self.block_ip(
            src_ip,
            reason=f"{alert.get('type', 'Unknown')}: "
            f"{alert.get('subtype', '')}",
        )

    def block_ip(self, ip: str, reason: str = "IDS alert") -> bool:
        """Block an IP address using the system firewall."""
        with self._lock:
            if ip in self.config.whitelist:
                logger.warning(f"Skipping whitelist IP: {ip}")
                return False

            if ip in self._blocked_ips:
                return False

            if len(self._blocked_ips) >= self.config.max_blocks:
                logger.warning("Max firewall blocks reached")
                return False

            success = self._execute_block(ip)
            if success:
                self._blocked_ips[ip] = time.time()
                self._block_reasons[ip] = reason
                self._log_action("BLOCK", ip, reason)
                logger.info(f"Blocked IP: {ip} ({reason})")
            return success

    def unblock_ip(self, ip: str) -> bool:
        """Unblock a previously blocked IP."""
        with self._lock:
            if ip not in self._blocked_ips:
                return False

            success = self._execute_unblock(ip)
            if success:
                del self._blocked_ips[ip]
                self._block_reasons.pop(ip, None)
                self._log_action("UNBLOCK", ip, "expired/manual")
                logger.info(f"Unblocked IP: {ip}")
            return success

    def _execute_block(self, ip: str) -> bool:
        """Execute the actual firewall block command."""
        if self.config.dry_run:
            logger.info(f"[DRY RUN] Would block: {ip}")
            return True

        try:
            if self._os == "linux":
                cmd = [
                    "iptables", "-A", "INPUT",
                    "-s", ip, "-j", "DROP",
                ]
                subprocess.run(
                    cmd, check=True, capture_output=True
                )
                cmd_out = [
                    "iptables", "-A", "OUTPUT",
                    "-d", ip, "-j", "DROP",
                ]
                subprocess.run(
                    cmd_out, check=True, capture_output=True
                )
            elif self._os == "windows":
                cmd = [
                    "netsh", "advfirewall", "firewall", "add",
                    "rule",
                    f"name=ShadowFence_Block_{ip}",
                    "dir=in", "action=block",
                    f"remoteip={ip}",
                ]
                subprocess.run(
                    cmd, check=True, capture_output=True
                )
            return True
        except subprocess.CalledProcessError as e:
            logger.error(f"Firewall block failed for {ip}: {e}")
            return False
        except FileNotFoundError:
            logger.error(
                "Firewall command not found. "
                "Root/admin privileges may be required."
            )
            return False

    def _execute_unblock(self, ip: str) -> bool:
        """Execute the actual firewall unblock command."""
        if self.config.dry_run:
            logger.info(f"[DRY RUN] Would unblock: {ip}")
            return True

        try:
            if self._os == "linux":
                subprocess.run(
                    [
                        "iptables", "-D", "INPUT",
                        "-s", ip, "-j", "DROP",
                    ],
                    check=True,
                    capture_output=True,
                )
                subprocess.run(
                    [
                        "iptables", "-D", "OUTPUT",
                        "-d", ip, "-j", "DROP",
                    ],
                    check=True,
                    capture_output=True,
                )
            elif self._os == "windows":
                subprocess.run(
                    [
                        "netsh", "advfirewall", "firewall",
                        "delete", "rule",
                        f"name=ShadowFence_Block_{ip}",
                    ],
                    check=True,
                    capture_output=True,
                )
            return True
        except subprocess.CalledProcessError as e:
            logger.error(f"Firewall unblock failed for {ip}: {e}")
            return False

    def _cleanup_loop(self) -> None:
        """Periodically unblock expired IPs."""
        while self._cleanup_running:
            time.sleep(60)
            now = time.time()
            with self._lock:
                expired = [
                    ip
                    for ip, blocked_at in self._blocked_ips.items()
                    if now - blocked_at > self.config.block_duration
                ]
            for ip in expired:
                self.unblock_ip(ip)

    def _log_action(
        self, action: str, ip: str, reason: str
    ) -> None:
        """Log a firewall action."""
        entry = {
            "time": time.strftime("%Y-%m-%d %H:%M:%S"),
            "action": action,
            "ip": ip,
            "reason": reason,
        }
        self._action_log.append(entry)
        try:
            with open(self.config.log_file, "a") as f:
                f.write(
                    f"{entry['time']} | {action} | "
                    f"{ip} | {reason}\n"
                )
        except Exception:
            pass

    def get_blocked_ips(self) -> list[dict]:
        """Get list of currently blocked IPs."""
        with self._lock:
            result = []
            now = time.time()
            for ip, blocked_at in self._blocked_ips.items():
                remaining = max(
                    0,
                    self.config.block_duration
                    - (now - blocked_at),
                )
                result.append({
                    "ip": ip,
                    "blocked_at": blocked_at,
                    "reason": self._block_reasons.get(ip, ""),
                    "remaining_seconds": int(remaining),
                })
            return result

    def get_action_log(self, count: int = 50) -> list[dict]:
        """Get recent firewall actions."""
        return self._action_log[-count:]
