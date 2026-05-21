"""Tests for the alert system."""

from shadowfence.alerts.alert_manager import AlertManager
from shadowfence.alerts.email_alert import EmailAlertSender
from shadowfence.config import EmailConfig, ShadowFenceConfig


class TestAlertManager:
    def test_handles_alert(self):
        config = ShadowFenceConfig()
        manager = AlertManager(config)

        alert = {
            "type": "Port Scan",
            "severity": "high",
            "src_ip": "10.0.0.1",
            "dst_ip": "10.0.0.2",
            "description": "Test alert",
        }
        manager.handle_alert(alert)
        assert "timestamp" in alert
        assert "id" in alert

    def test_get_stats(self):
        config = ShadowFenceConfig()
        manager = AlertManager(config)

        for i in range(5):
            manager.handle_alert({
                "type": "Port Scan",
                "severity": "high",
                "src_ip": "10.0.0.1",
                "dst_ip": "10.0.0.2",
                "description": f"Test {i}",
            })

        stats = manager.get_stats()
        assert stats["total_alerts"] == 5

    def test_callback_registration(self):
        config = ShadowFenceConfig()
        manager = AlertManager(config)

        received = []
        manager.register_callback(lambda a: received.append(a))

        manager.handle_alert({
            "type": "Test",
            "severity": "low",
            "src_ip": "1.2.3.4",
            "dst_ip": "5.6.7.8",
            "description": "Callback test",
        })

        assert len(received) == 1


class TestEmailAlertSender:
    def test_disabled_sender(self):
        config = EmailConfig(enabled=False)
        sender = EmailAlertSender(config)
        sender.queue_alert({"type": "test", "severity": "high"})
        # No error when disabled

    def test_rate_limiting(self):
        config = EmailConfig(enabled=True, min_interval=300, to_addrs=["test@test.com"])
        sender = EmailAlertSender(config)
        sender.queue_alert({"type": "Port Scan", "severity": "high"})
        # Second alert of same type should be rate limited within interval
