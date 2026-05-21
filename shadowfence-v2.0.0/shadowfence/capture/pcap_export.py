"""PCAP export and forensic capture module.

Provides packet capture export to standard PCAP format for
forensic analysis, evidence preservation, and replay.
"""

from __future__ import annotations

import logging
import time
from pathlib import Path
from threading import Lock

from scapy.utils import PcapWriter

from shadowfence.capture.packet_parser import ParsedPacket

logger = logging.getLogger("shadowfence.pcap")


class PCAPExporter:
    """Exports captured packets to PCAP files for forensic analysis."""

    def __init__(
        self,
        output_dir: str | Path = "captures",
        max_file_size: int = 104857600,
        rotate: bool = True,
        max_files: int = 10,
    ):
        self.output_dir = Path(output_dir)
        self.output_dir.mkdir(parents=True, exist_ok=True)
        self.max_file_size = max_file_size
        self.rotate = rotate
        self.max_files = max_files
        self._lock = Lock()
        self._writer: PcapWriter | None = None
        self._current_file: Path | None = None
        self._current_size: int = 0
        self._packet_count: int = 0
        self._alert_captures: dict[str, PcapWriter] = {}

    def start(self) -> str:
        """Start a new capture file. Returns the file path."""
        with self._lock:
            filename = (
                f"capture_{time.strftime('%Y%m%d_%H%M%S')}.pcap"
            )
            filepath = self.output_dir / filename
            self._writer = PcapWriter(
                str(filepath), append=True, sync=True
            )
            self._current_file = filepath
            self._current_size = 0
            self._packet_count = 0
            logger.info(f"PCAP capture started: {filepath}")
            return str(filepath)

    def write_packet(self, packet: ParsedPacket) -> None:
        """Write a packet to the current capture file."""
        if not self._writer or not packet.raw_packet:
            return

        with self._lock:
            try:
                self._writer.write(packet.raw_packet)
                self._packet_count += 1
                self._current_size += packet.length

                if (
                    self.rotate
                    and self._current_size >= self.max_file_size
                ):
                    self._rotate_file()
            except Exception as e:
                logger.error(f"PCAP write error: {e}")

    def capture_alert_context(
        self,
        alert: dict,
        packets: list[ParsedPacket],
        context_name: str | None = None,
    ) -> str | None:
        """Save packets related to an alert for forensic analysis."""
        if not packets:
            return None

        try:
            name = context_name or alert.get("type", "alert")
            name = name.replace(" ", "_").lower()
            ts = time.strftime("%Y%m%d_%H%M%S")
            filename = f"alert_{name}_{ts}.pcap"
            filepath = self.output_dir / filename

            writer = PcapWriter(str(filepath), append=True, sync=True)
            for pkt in packets:
                if pkt.raw_packet:
                    writer.write(pkt.raw_packet)
            writer.close()

            logger.info(
                f"Alert PCAP saved: {filepath} "
                f"({len(packets)} packets)"
            )
            return str(filepath)
        except Exception as e:
            logger.error(f"Alert PCAP export error: {e}")
            return None

    def stop(self) -> dict:
        """Stop capture and close files. Returns capture summary."""
        with self._lock:
            summary = {
                "file": (
                    str(self._current_file) if self._current_file
                    else None
                ),
                "packets": self._packet_count,
                "size": self._current_size,
            }
            if self._writer:
                self._writer.close()
                self._writer = None
            for writer in self._alert_captures.values():
                try:
                    writer.close()
                except Exception:
                    pass
            self._alert_captures.clear()
            logger.info(
                f"PCAP capture stopped: "
                f"{self._packet_count} packets, "
                f"{self._current_size} bytes"
            )
            return summary

    def _rotate_file(self) -> None:
        """Rotate to a new capture file."""
        if self._writer:
            self._writer.close()

        if self.max_files > 0:
            self._cleanup_old_files()

        filename = (
            f"capture_{time.strftime('%Y%m%d_%H%M%S')}.pcap"
        )
        filepath = self.output_dir / filename
        self._writer = PcapWriter(
            str(filepath), append=True, sync=True
        )
        self._current_file = filepath
        self._current_size = 0
        logger.info(f"PCAP rotated to: {filepath}")

    def _cleanup_old_files(self) -> None:
        """Remove oldest capture files if over limit."""
        pcaps = sorted(
            self.output_dir.glob("capture_*.pcap"),
            key=lambda p: p.stat().st_mtime,
        )
        while len(pcaps) >= self.max_files:
            oldest = pcaps.pop(0)
            try:
                oldest.unlink()
                logger.info(f"Removed old PCAP: {oldest}")
            except Exception:
                pass

    def list_captures(self) -> list[dict]:
        """List all captured PCAP files."""
        result = []
        for pcap in sorted(self.output_dir.glob("*.pcap")):
            stat = pcap.stat()
            result.append({
                "file": str(pcap),
                "name": pcap.name,
                "size": stat.st_size,
                "modified": stat.st_mtime,
            })
        return result
