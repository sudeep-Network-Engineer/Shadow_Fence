"""Logging system for ShadowFence."""

from __future__ import annotations

import json
import logging
import sys
from logging.handlers import RotatingFileHandler
from pathlib import Path

from shadowfence.config import LoggingConfig


def setup_logger(config: LoggingConfig, name: str = "shadowfence") -> logging.Logger:
    """Set up and configure the application logger."""
    logger = logging.getLogger(name)
    logger.setLevel(getattr(logging, config.level.upper(), logging.INFO))

    if logger.handlers:
        return logger

    fmt = logging.Formatter(
        "%(asctime)s | %(levelname)-8s | %(name)s | %(message)s",
        datefmt="%Y-%m-%d %H:%M:%S",
    )

    console = logging.StreamHandler(sys.stdout)
    console.setLevel(logging.INFO)
    console.setFormatter(fmt)
    logger.addHandler(console)

    if config.file:
        log_path = Path(config.file)
        log_path.parent.mkdir(parents=True, exist_ok=True)
        file_handler = RotatingFileHandler(
            str(log_path),
            maxBytes=config.max_size,
            backupCount=config.backup_count,
        )
        file_handler.setLevel(getattr(logging, config.level.upper(), logging.INFO))
        file_handler.setFormatter(fmt)
        logger.addHandler(file_handler)

    return logger


class AlertLogger:
    """Logs security alerts to a structured JSON log file."""

    def __init__(self, log_dir: str | Path = "."):
        self.log_path = Path(log_dir) / "alerts.jsonl"
        self.log_path.parent.mkdir(parents=True, exist_ok=True)

    def log_alert(self, alert: dict) -> None:
        """Append an alert to the JSONL alert log."""
        try:
            with open(self.log_path, "a") as f:
                f.write(json.dumps(alert, default=str) + "\n")
        except Exception:
            pass

    def get_recent_alerts(self, count: int = 100) -> list[dict]:
        """Read the most recent alerts from the log."""
        if not self.log_path.exists():
            return []
        alerts = []
        try:
            with open(self.log_path) as f:
                for line in f:
                    line = line.strip()
                    if line:
                        try:
                            alerts.append(json.loads(line))
                        except json.JSONDecodeError:
                            pass
        except Exception:
            pass
        return alerts[-count:]
