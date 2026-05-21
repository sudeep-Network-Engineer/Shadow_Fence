"""Utility functions for ShadowFence."""

from __future__ import annotations

import math
import time
from collections import Counter
from datetime import datetime, timezone


def timestamp_now() -> str:
    """Return current UTC timestamp as ISO string."""
    return datetime.now(timezone.utc).isoformat()


def epoch_now() -> float:
    """Return current epoch time."""
    return time.time()


def format_bytes(num_bytes: int) -> str:
    """Format byte count to human-readable string."""
    if num_bytes == 0:
        return "0 B"
    units = ["B", "KB", "MB", "GB", "TB"]
    i = int(math.floor(math.log(num_bytes, 1024)))
    i = min(i, len(units) - 1)
    value = num_bytes / (1024**i)
    return f"{value:.1f} {units[i]}"


def format_pps(packets: int, seconds: float) -> str:
    """Format packets per second."""
    if seconds <= 0:
        return "0 pps"
    pps = packets / seconds
    if pps >= 1_000_000:
        return f"{pps / 1_000_000:.1f}M pps"
    if pps >= 1_000:
        return f"{pps / 1_000:.1f}K pps"
    return f"{pps:.0f} pps"


def ip_to_int(ip: str) -> int:
    """Convert dotted IP string to integer."""
    parts = ip.split(".")
    if len(parts) != 4:
        return 0
    return sum(int(p) << (8 * (3 - i)) for i, p in enumerate(parts))


def is_private_ip(ip: str) -> bool:
    """Check if an IP is in a private range."""
    val = ip_to_int(ip)
    private_ranges = [
        (ip_to_int("10.0.0.0"), ip_to_int("10.255.255.255")),
        (ip_to_int("172.16.0.0"), ip_to_int("172.31.255.255")),
        (ip_to_int("192.168.0.0"), ip_to_int("192.168.255.255")),
        (ip_to_int("127.0.0.0"), ip_to_int("127.255.255.255")),
    ]
    return any(start <= val <= end for start, end in private_ranges)


def calculate_entropy(data: str) -> float:
    """Calculate Shannon entropy of a string."""
    if not data:
        return 0.0
    counts = Counter(data)
    length = len(data)
    entropy = 0.0
    for count in counts.values():
        probability = count / length
        if probability > 0:
            entropy -= probability * math.log2(probability)
    return entropy


SEVERITY_LEVELS = {
    "info": 0,
    "low": 1,
    "medium": 2,
    "high": 3,
    "critical": 4,
}


def severity_value(severity: str) -> int:
    """Get numeric value for severity level."""
    return SEVERITY_LEVELS.get(severity.lower(), 0)


def severity_color(severity: str) -> str:
    """Get terminal color code for severity level."""
    colors = {
        "info": "blue",
        "low": "cyan",
        "medium": "yellow",
        "high": "red",
        "critical": "bold red",
    }
    return colors.get(severity.lower(), "white")


def truncate(text: str, max_length: int = 200) -> str:
    """Truncate text to max length with ellipsis."""
    if len(text) <= max_length:
        return text
    return text[: max_length - 3] + "..."
