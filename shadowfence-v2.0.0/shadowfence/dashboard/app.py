"""Real-time web dashboard for ShadowFence."""

from __future__ import annotations

import json
import logging
import threading
from pathlib import Path
from typing import Any

from flask import Flask, render_template
from flask_socketio import SocketIO

logger = logging.getLogger("shadowfence.dashboard")


class Dashboard:
    """Real-time web dashboard using Flask + SocketIO."""

    def __init__(self, host: str = "0.0.0.0", port: int = 8443):
        self.host = host
        self.port = port
        template_dir = str(Path(__file__).parent / "templates")
        static_dir = str(Path(__file__).parent / "static")

        self.app = Flask(
            __name__,
            template_folder=template_dir,
            static_folder=static_dir,
        )
        self.app.config["SECRET_KEY"] = "shadowfence-dashboard"
        self.socketio = SocketIO(self.app, async_mode="gevent", cors_allowed_origins="*")
        self._stats_ref: dict[str, Any] | None = None
        self._alert_stats_ref: dict[str, Any] | None = None
        self._setup_routes()
        self._thread: threading.Thread | None = None

    def _setup_routes(self) -> None:
        @self.app.route("/")
        def index():
            return render_template("index.html")

        @self.app.route("/api/stats")
        def api_stats():
            return json.dumps(self._stats_ref or {})

        @self.app.route("/api/alerts")
        def api_alerts():
            return json.dumps(self._alert_stats_ref or {})

    def set_stats_source(self, stats_getter: Any, alert_stats_getter: Any) -> None:
        """Set references to stats data sources."""
        self._stats_ref = stats_getter
        self._alert_stats_ref = alert_stats_getter

    def emit_alert(self, alert: dict) -> None:
        """Push a real-time alert to all connected dashboard clients."""
        try:
            self.socketio.emit("new_alert", alert)
        except Exception:
            pass

    def emit_stats(self, stats: dict) -> None:
        """Push stats update to all connected clients."""
        try:
            self.socketio.emit("stats_update", stats)
        except Exception:
            pass

    def start(self) -> None:
        """Start the dashboard in a background thread."""
        self._thread = threading.Thread(target=self._run, daemon=True)
        self._thread.start()
        logger.info(f"Dashboard started at http://{self.host}:{self.port}")

    def _run(self) -> None:
        self.socketio.run(
            self.app,
            host=self.host,
            port=self.port,
            debug=False,
            log_output=False,
            use_reloader=False,
        )

    def stop(self) -> None:
        """Stop the dashboard."""
        pass
