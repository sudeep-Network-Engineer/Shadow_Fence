"""Packet parsing and normalization for ShadowFence."""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any

from scapy.layers.dns import DNS, DNSQR
from scapy.layers.http import HTTPRequest, HTTPResponse
from scapy.layers.inet import ICMP, IP, TCP, UDP
from scapy.layers.l2 import ARP, Ether
from scapy.packet import Packet, Raw


@dataclass
class ParsedPacket:
    """Normalized representation of a captured packet."""

    timestamp: float = 0.0
    src_mac: str = ""
    dst_mac: str = ""
    src_ip: str = ""
    dst_ip: str = ""
    src_port: int = 0
    dst_port: int = 0
    protocol: str = ""
    length: int = 0
    ttl: int = 0
    flags: str = ""
    payload: bytes = b""
    payload_str: str = ""
    raw_packet: Packet | None = None

    # Protocol-specific fields
    tcp_flags: str = ""
    icmp_type: int = 0
    icmp_code: int = 0

    # ARP fields
    arp_op: int = 0
    arp_src_ip: str = ""
    arp_dst_ip: str = ""
    arp_src_mac: str = ""
    arp_dst_mac: str = ""

    # DNS fields
    dns_query: str = ""
    dns_qtype: int = 0

    # HTTP fields
    http_method: str = ""
    http_host: str = ""
    http_path: str = ""
    http_user_agent: str = ""
    http_status: int = 0

    # Metadata
    is_syn: bool = False
    is_syn_ack: bool = False
    is_rst: bool = False
    is_fin: bool = False
    is_ack: bool = False

    extra: dict[str, Any] = field(default_factory=dict)


def parse_packet(packet: Packet, timestamp: float | None = None) -> ParsedPacket:
    """Parse a scapy packet into a normalized ParsedPacket."""
    parsed = ParsedPacket()
    parsed.raw_packet = packet
    parsed.timestamp = timestamp or (packet.time if hasattr(packet, "time") else 0.0)
    parsed.length = len(packet)

    if packet.haslayer(Ether):
        ether = packet[Ether]
        parsed.src_mac = ether.src
        parsed.dst_mac = ether.dst

    if packet.haslayer(ARP):
        arp = packet[ARP]
        parsed.protocol = "ARP"
        parsed.arp_op = arp.op
        parsed.arp_src_ip = arp.psrc
        parsed.arp_dst_ip = arp.pdst
        parsed.arp_src_mac = arp.hwsrc
        parsed.arp_dst_mac = arp.hwdst
        parsed.src_ip = arp.psrc
        parsed.dst_ip = arp.pdst
        return parsed

    if packet.haslayer(IP):
        ip = packet[IP]
        parsed.src_ip = ip.src
        parsed.dst_ip = ip.dst
        parsed.ttl = ip.ttl

    if packet.haslayer(TCP):
        tcp = packet[TCP]
        parsed.protocol = "TCP"
        parsed.src_port = tcp.sport
        parsed.dst_port = tcp.dport
        parsed.tcp_flags = str(tcp.flags)
        parsed.is_syn = tcp.flags.S and not tcp.flags.A
        parsed.is_syn_ack = bool(tcp.flags.S and tcp.flags.A)
        parsed.is_rst = bool(tcp.flags.R)
        parsed.is_fin = bool(tcp.flags.F)
        parsed.is_ack = bool(tcp.flags.A)
    elif packet.haslayer(UDP):
        udp = packet[UDP]
        parsed.protocol = "UDP"
        parsed.src_port = udp.sport
        parsed.dst_port = udp.dport
    elif packet.haslayer(ICMP):
        icmp = packet[ICMP]
        parsed.protocol = "ICMP"
        parsed.icmp_type = icmp.type
        parsed.icmp_code = icmp.code

    if packet.haslayer(DNS):
        parsed.protocol = "DNS"
        dns = packet[DNS]
        if dns.haslayer(DNSQR):
            qr = dns[DNSQR]
            parsed.dns_query = qr.qname.decode("utf-8", errors="ignore").rstrip(".")
            parsed.dns_qtype = qr.qtype

    if packet.haslayer(HTTPRequest):
        http = packet[HTTPRequest]
        parsed.http_method = (
            http.Method.decode("utf-8", errors="ignore") if hasattr(http, "Method") else ""
        )
        parsed.http_host = (
            http.Host.decode("utf-8", errors="ignore") if hasattr(http, "Host") else ""
        )
        parsed.http_path = (
            http.Path.decode("utf-8", errors="ignore") if hasattr(http, "Path") else ""
        )
        if hasattr(http, "User_Agent") and http.User_Agent:
            parsed.http_user_agent = http.User_Agent.decode("utf-8", errors="ignore")
    elif packet.haslayer(HTTPResponse):
        http_resp = packet[HTTPResponse]
        if hasattr(http_resp, "Status_Code") and http_resp.Status_Code:
            try:
                parsed.http_status = int(http_resp.Status_Code)
            except (ValueError, TypeError):
                pass

    if packet.haslayer(Raw):
        raw = packet[Raw].load
        parsed.payload = raw[:8192]
        try:
            parsed.payload_str = raw[:8192].decode("utf-8", errors="replace")
        except Exception:
            parsed.payload_str = ""

    return parsed
