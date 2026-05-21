"""Packet capture engine for ShadowFence."""

from __future__ import annotations

import threading
import time
from collections.abc import Callable
from queue import Full, Queue
from typing import Any

from scapy.all import sniff
from scapy.packet import Packet

from shadowfence.capture.packet_parser import ParsedPacket, parse_packet
from shadowfence.config import ShadowFenceConfig


class PacketSniffer:
    """High-performance packet capture engine using scapy."""

    def __init__(
        self,
        config: ShadowFenceConfig,
        packet_callback: Callable[[ParsedPacket], None] | None = None,
    ):
        self.config = config
        self.packet_callback = packet_callback
        self.packet_queue: Queue[ParsedPacket] = Queue(
            maxsize=config.performance.packet_queue_size
        )
        self._running = False
        self._capture_thread: threading.Thread | None = None
        self._worker_threads: list[threading.Thread] = []
        self._stop_event = threading.Event()

        # Statistics
        self.stats = {
            "packets_captured": 0,
            "packets_processed": 0,
            "packets_dropped": 0,
            "bytes_captured": 0,
            "start_time": 0.0,
            "protocols": {"TCP": 0, "UDP": 0, "ICMP": 0, "ARP": 0, "DNS": 0, "Other": 0},
        }
        self._stats_lock = threading.Lock()

    def start(self) -> None:
        """Start the packet capture engine."""
        if self._running:
            return

        self._running = True
        self._stop_event.clear()
        self.stats["start_time"] = time.time()

        for i in range(self.config.performance.worker_threads):
            t = threading.Thread(target=self._worker, name=f"worker-{i}", daemon=True)
            t.start()
            self._worker_threads.append(t)

        self._capture_thread = threading.Thread(target=self._capture, name="capture", daemon=True)
        self._capture_thread.start()

    def stop(self) -> None:
        """Stop the packet capture engine."""
        self._running = False
        self._stop_event.set()
        if self._capture_thread and self._capture_thread.is_alive():
            self._capture_thread.join(timeout=5)
        for t in self._worker_threads:
            if t.is_alive():
                t.join(timeout=2)
        self._worker_threads.clear()

    def _capture(self) -> None:
        """Run the scapy sniffer."""
        try:
            kwargs: dict[str, Any] = {
                "prn": self._on_packet,
                "store": False,
            }
            iface = self.config.interface
            if iface and iface != "any":
                kwargs["iface"] = iface
            if self.config.capture.filter:
                kwargs["filter"] = self.config.capture.filter
            kwargs["stop_filter"] = lambda _: self._stop_event.is_set()

            sniff(**kwargs)
        except PermissionError:
            raise PermissionError(
                "Root/sudo privileges are required for packet capture. "
                "Run with: sudo shadowfence start"
            )
        except Exception as e:
            if self._running:
                raise RuntimeError(f"Capture error: {e}") from e

    def _on_packet(self, packet: Packet) -> None:
        """Handle each captured packet."""
        parsed = parse_packet(packet, time.time())

        with self._stats_lock:
            self.stats["packets_captured"] += 1
            self.stats["bytes_captured"] += parsed.length
            proto = parsed.protocol if parsed.protocol in self.stats["protocols"] else "Other"
            self.stats["protocols"][proto] += 1

        try:
            self.packet_queue.put_nowait(parsed)
        except Full:
            with self._stats_lock:
                self.stats["packets_dropped"] += 1

    def _worker(self) -> None:
        """Process packets from the queue."""
        batch: list[ParsedPacket] = []
        perf = self.config.performance
        batch_size = perf.batch_size if perf.batch_processing else 1

        while self._running or not self.packet_queue.empty():
            try:
                pkt = self.packet_queue.get(timeout=0.5)
                batch.append(pkt)

                if len(batch) >= batch_size:
                    self._process_batch(batch)
                    batch = []
            except Exception:
                if batch:
                    self._process_batch(batch)
                    batch = []
                if self._stop_event.is_set() and self.packet_queue.empty():
                    break

        if batch:
            self._process_batch(batch)

    def _process_batch(self, batch: list[ParsedPacket]) -> None:
        """Process a batch of packets."""
        for pkt in batch:
            with self._stats_lock:
                self.stats["packets_processed"] += 1
            if self.packet_callback:
                try:
                    self.packet_callback(pkt)
                except Exception:
                    pass

    def get_stats(self) -> dict[str, Any]:
        """Get current capture statistics."""
        with self._stats_lock:
            stats = dict(self.stats)
            stats["protocols"] = dict(self.stats["protocols"])
        elapsed = time.time() - stats["start_time"] if stats["start_time"] > 0 else 0
        stats["elapsed_seconds"] = elapsed
        stats["pps"] = stats["packets_captured"] / elapsed if elapsed > 0 else 0
        return stats
