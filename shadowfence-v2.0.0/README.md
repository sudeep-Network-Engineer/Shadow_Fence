# ShadowFence

**Advanced Network Intrusion Detection System (NIDS)**

A powerful, real-time network intrusion detection system with 11 detection engines, automated firewall response, PCAP forensics, email alerts, and a live web dashboard.

**Author:** Sudeep Patil | Network Security Engineer

![Python](https://img.shields.io/badge/python-3.10+-blue)
![License](https://img.shields.io/badge/license-MIT-green)
![Platform](https://img.shields.io/badge/platform-Linux%20%7C%20Windows-lightgrey)

---

## Features

### Detection Engines (11 Total)

| Engine | Description | Severity |
|--------|-------------|----------|
| **Port Scan Detection** | Detects SYN scans, sequential scans, service discovery, aggressive scans | High |
| **Brute Force Detection** | Monitors SSH, RDP, FTP, MySQL, PostgreSQL, VNC + 10 more services | High |
| **DDoS / Flood Detection** | SYN flood, UDP flood, ICMP flood, HTTP flood with rate analysis | Critical |
| **ARP Spoofing Detection** | Detects MAC-IP binding changes indicating MITM attacks | Critical |
| **DNS Tunneling Detection** | Shannon entropy analysis, query rate monitoring, subdomain inspection | High |
| **Payload / Signature Analysis** | 20+ regex rules: SQLi, XSS, command injection, reverse shells, crypto miners | Medium |
| **Protocol Anomaly Detection** | XMAS scan, NULL scan, LAND attack, Smurf attack, TTL anomaly | Medium-Critical |
| **Bandwidth Anomaly Detection** | Traffic spike detection, data exfiltration alerts, connection burst monitoring | High-Critical |
| **SSL/TLS Anomaly Detection** | Deprecated TLS versions, SSL stripping, suspicious ClientHello | High-Critical |
| **Threat Intelligence** | IP/domain blocklist matching, custom watchlist, malicious domain detection | Critical |
| **Network Topology Mapper** | Passive device discovery, service detection, OS fingerprinting, topology graph | Info |

### Additional Capabilities

- **Automated Firewall Response** — auto-block attacker IPs via iptables (Linux) or netsh (Windows)
- **PCAP Forensic Export** — save captured packets to standard PCAP format for Wireshark analysis
- **Email Alerts** — HTML-formatted digest emails with severity-colored tables and rate limiting
- **Real-time Web Dashboard** — live monitoring with protocol charts, alert feed, and severity stats
- **Threat Intelligence Feeds** — load malicious IP/domain blocklists (JSON or plain text)
- **Network Asset Tracking** — passive discovery of devices, open ports, services, and OS types

---

## Table of Contents

- [Installation](#installation)
  - [Linux (Ubuntu/Debian)](#linux-ubuntudebian)
  - [Linux (Fedora/CentOS/RHEL)](#linux-fedoracentosrhel)
  - [Windows](#windows)
  - [macOS](#macos)
- [Quick Start](#quick-start)
- [Connecting to Your Network](#connecting-to-your-network)
  - [Linux Network Setup](#linux-network-setup)
  - [Windows Network Setup](#windows-network-setup)
  - [WiFi Monitoring](#wifi-monitoring)
  - [Remote Network Monitoring](#remote-network-monitoring)
- [Email Alerts Setup](#email-alerts-setup)
- [Configuration Guide](#configuration-guide)
- [CLI Commands](#cli-commands)
- [Custom Detection Rules](#custom-detection-rules)
- [Threat Intelligence](#threat-intelligence)
- [Automated Firewall Response](#automated-firewall-response)
- [PCAP Forensics](#pcap-forensics)
- [Project Structure](#project-structure)
- [How It Works](#how-it-works)
- [Testing](#testing)
- [License](#license)

---

## Installation

### Linux (Ubuntu/Debian)

```bash
# 1. Install system dependencies
sudo apt update
sudo apt install -y python3 python3-pip python3-venv libpcap-dev

# 2. Clone or extract the project
git clone https://github.com/YOUR_USERNAME/shadowfence.git
cd shadowfence

# 3. Create virtual environment (recommended)
python3 -m venv venv
source venv/bin/activate

# 4. Install ShadowFence
pip install -e .

# 5. Verify installation
shadowfence --version

# 6. Start monitoring (requires root for packet capture)
sudo $(which shadowfence) start
```

### Linux (Fedora/CentOS/RHEL)

```bash
# 1. Install system dependencies
sudo dnf install -y python3 python3-pip libpcap-devel

# 2. Clone and install
git clone https://github.com/YOUR_USERNAME/shadowfence.git
cd shadowfence
python3 -m venv venv
source venv/bin/activate
pip install -e .

# 3. Start monitoring
sudo $(which shadowfence) start
```

### Windows

```powershell
# 1. Install Python 3.10+ from https://www.python.org/downloads/
#    IMPORTANT: Check "Add Python to PATH" during installation

# 2. Install Npcap (required for packet capture)
#    Download from: https://npcap.com/#download
#    During installation, check "Install Npcap in WinPcap API-compatible Mode"

# 3. Open PowerShell as Administrator
# 4. Clone or extract the project
git clone https://github.com/YOUR_USERNAME/shadowfence.git
cd shadowfence

# 5. Create virtual environment
python -m venv venv
.\venv\Scripts\Activate.ps1

# 6. Install ShadowFence
pip install -e .

# 7. List available interfaces to find yours
shadowfence list-interfaces

# 8. Start monitoring (must run as Administrator)
shadowfence start -i "Ethernet"
# or for WiFi:
shadowfence start -i "Wi-Fi"
```

> **Windows Notes:**
> - You MUST install [Npcap](https://npcap.com/#download) with WinPcap compatibility mode
> - Run PowerShell/Command Prompt as **Administrator** for packet capture
> - Use `shadowfence list-interfaces` to find your interface name
> - Windows interface names are like `Ethernet`, `Wi-Fi`, `Local Area Connection`

### macOS

```bash
# 1. Install dependencies
brew install python3 libpcap

# 2. Clone and install
git clone https://github.com/YOUR_USERNAME/shadowfence.git
cd shadowfence
python3 -m venv venv
source venv/bin/activate
pip install -e .

# 3. Start monitoring
sudo $(which shadowfence) start -i en0
```

---

## Quick Start

```bash
# Basic monitoring (all interfaces)
sudo shadowfence start

# Monitor specific interface
sudo shadowfence start -i eth0

# Monitor with PCAP export
sudo shadowfence start --pcap

# Monitor with auto-block (dry-run mode)
sudo shadowfence start --auto-block

# Monitor without dashboard
sudo shadowfence start --no-dashboard

# Verbose/debug mode
sudo shadowfence start -v

# Custom config file
sudo shadowfence start -c /path/to/config.yaml

# Combine options
sudo shadowfence start -i eth0 --pcap --auto-block -v
```

After starting, open **http://localhost:8443** in your browser for the real-time dashboard.

---

## Connecting to Your Network

### Linux Network Setup

#### Find Your Interface

```bash
# List all network interfaces
ip link show

# Or use ShadowFence's built-in command
shadowfence list-interfaces

# Common interface names:
# eth0       - Wired Ethernet
# ens33      - Wired Ethernet (modern naming)
# wlan0      - WiFi
# wlp2s0     - WiFi (modern naming)
# lo         - Loopback (localhost)
# docker0    - Docker bridge
# any        - All interfaces (default)
```

#### Monitor Wired Connection

```bash
# Find your wired interface
ip addr show | grep "state UP"

# Start monitoring on it
sudo shadowfence start -i eth0
```

#### Monitor WiFi

```bash
# Find WiFi interface
iwconfig 2>/dev/null | grep "IEEE"

# Start monitoring
sudo shadowfence start -i wlan0
```

#### Monitor All Traffic

```bash
# Use 'any' to capture from all interfaces
sudo shadowfence start -i any
```

#### Filter Specific Traffic

Edit `config.yaml`:

```yaml
capture:
  # Only monitor web traffic
  filter: "tcp port 80 or tcp port 443"

  # Only monitor a specific subnet
  filter: "net 192.168.1.0/24"

  # Exclude your own traffic
  filter: "not host 192.168.1.100"

  # Monitor DNS only
  filter: "udp port 53"
```

### Windows Network Setup

#### Step 1: Install Npcap

1. Download Npcap from https://npcap.com/#download
2. Run the installer **as Administrator**
3. Check these options during install:
   - "Install Npcap in WinPcap API-compatible Mode"
   - "Support raw 802.11 traffic" (for WiFi monitoring)
4. Complete installation and reboot if prompted

#### Step 2: Find Your Interface

```powershell
# Open PowerShell as Administrator
shadowfence list-interfaces

# Or use Windows commands
Get-NetAdapter | Format-Table Name, Status, InterfaceDescription
```

#### Step 3: Start Monitoring

```powershell
# Monitor Ethernet
shadowfence start -i "Ethernet"

# Monitor WiFi
shadowfence start -i "Wi-Fi"

# Monitor by adapter description (if name doesn't work)
shadowfence start -i "Intel(R) Wi-Fi 6 AX201"
```

#### Windows Firewall Notes

If ShadowFence can't capture packets:

```powershell
# Check if Npcap is installed
Get-Service npcap

# Allow ShadowFence through Windows Firewall
New-NetFirewallRule -DisplayName "ShadowFence" -Direction Inbound -Action Allow -Program "C:\path\to\python.exe"

# Run as Administrator (required for raw packet capture)
Start-Process powershell -Verb RunAs
```

### WiFi Monitoring

#### Linux WiFi Monitor Mode (Advanced)

For deeper WiFi monitoring, you can put your adapter in monitor mode:

```bash
# Check if your adapter supports monitor mode
iw list | grep monitor

# Enable monitor mode (replaces normal WiFi connection)
sudo ip link set wlan0 down
sudo iw wlan0 set monitor control
sudo ip link set wlan0 up

# Start ShadowFence on monitor interface
sudo shadowfence start -i wlan0

# To restore normal mode when done:
sudo ip link set wlan0 down
sudo iw wlan0 set type managed
sudo ip link set wlan0 up
sudo systemctl restart NetworkManager
```

> **Note:** Monitor mode disconnects you from WiFi. Use a separate interface or wired connection for your main connection.

### Remote Network Monitoring

#### Monitor a Remote Server

```bash
# SSH tunnel the dashboard to your local machine
ssh -L 8443:localhost:8443 user@remote-server

# On the remote server:
sudo shadowfence start -i eth0

# Access dashboard locally at http://localhost:8443
```

#### Monitor Docker Network

```bash
# Find Docker bridge interface
docker network ls
ip addr show docker0

# Monitor Docker traffic
sudo shadowfence start -i docker0

# Or monitor a specific Docker network
sudo shadowfence start -i br-$(docker network ls -q -f name=mynetwork)
```

#### Monitor VPN Traffic

```bash
# Find VPN interface
ip addr show | grep -E "tun|wg|ppp"

# Monitor VPN (OpenVPN)
sudo shadowfence start -i tun0

# Monitor VPN (WireGuard)
sudo shadowfence start -i wg0
```

---

## Email Alerts Setup

### Gmail Setup

1. **Enable 2-Factor Authentication** on your Google Account
2. **Generate an App Password:**
   - Go to https://myaccount.google.com/apppasswords
   - Select "Mail" → "Other (Custom name)" → enter "ShadowFence"
   - Copy the 16-character app password
3. **Configure ShadowFence:**

```yaml
# In config.yaml
alerts:
  email:
    enabled: true
    smtp_server: "smtp.gmail.com"
    smtp_port: 587
    use_tls: true
    username: "your-email@gmail.com"
    password: "xxxx xxxx xxxx xxxx"    # App password from step 2
    from_addr: "your-email@gmail.com"
    to_addrs:
      - "alert-recipient@gmail.com"
      - "team-security@company.com"
    min_interval: 300                   # Min 5 minutes between emails
    batch_interval: 60                  # Batch alerts for 60 seconds
```

Or use the interactive setup:

```bash
shadowfence setup-email
```

### Outlook / Office 365

```yaml
alerts:
  email:
    enabled: true
    smtp_server: "smtp.office365.com"
    smtp_port: 587
    use_tls: true
    username: "your-email@outlook.com"
    password: "your-password"
    from_addr: "your-email@outlook.com"
    to_addrs:
      - "security@company.com"
```

### Environment Variables (Recommended for Security)

Instead of storing credentials in config.yaml, use environment variables:

```bash
# Linux
export SHADOWFENCE_SMTP_SERVER="smtp.gmail.com"
export SHADOWFENCE_SMTP_USER="your-email@gmail.com"
export SHADOWFENCE_SMTP_PASS="xxxx xxxx xxxx xxxx"
export SHADOWFENCE_EMAIL_FROM="your-email@gmail.com"
export SHADOWFENCE_EMAIL_TO="alert1@gmail.com,alert2@gmail.com"

sudo -E shadowfence start   # -E preserves environment
```

```powershell
# Windows PowerShell
$env:SHADOWFENCE_SMTP_SERVER = "smtp.gmail.com"
$env:SHADOWFENCE_SMTP_USER = "your-email@gmail.com"
$env:SHADOWFENCE_SMTP_PASS = "xxxx xxxx xxxx xxxx"
$env:SHADOWFENCE_EMAIL_FROM = "your-email@gmail.com"
$env:SHADOWFENCE_EMAIL_TO = "alert1@gmail.com,alert2@gmail.com"

shadowfence start
```

---

## Configuration Guide

The full configuration file is `config.yaml`. Here are the key sections:

### Detection Thresholds

```yaml
detection:
  min_severity: low          # Filter: critical, high, medium, low, info

  port_scan:
    threshold: 15            # Ports before alert (lower = more sensitive)
    time_window: 60

  brute_force:
    threshold: 10            # Attempts before alert
    time_window: 120
    monitored_ports: [22, 23, 3389, 5900, 21, 3306, 5432, 1433, 27017]

  ddos:
    syn_flood_threshold: 500
    udp_flood_threshold: 1000
    icmp_flood_threshold: 200
    http_flood_threshold: 300
    time_window: 10

  protocol_anomaly:
    detect_xmas_scan: true
    detect_null_scan: true
    detect_land_attack: true
    detect_smurf_attack: true
    detect_ttl_anomaly: true

  bandwidth_anomaly:
    spike_multiplier: 5.0            # 5x baseline = spike
    exfil_threshold_bytes: 104857600 # 100MB = exfiltration alert
    connection_burst_threshold: 100

  ssl_anomaly:
    enabled: true

  threat_intel:
    blocklist_path: "rules/example_blocklist.json"

  firewall:
    enabled: true
    auto_block: true
    dry_run: true            # Set false for real blocking (CAUTION!)
    block_duration: 3600
    whitelist: ["127.0.0.1", "::1", "192.168.1.1"]

  network_map:
    enabled: true
```

### PCAP Export

```yaml
capture:
  pcap_export: true
  pcap_dir: "captures"
  pcap_max_size: 104857600   # 100MB per file
  pcap_max_files: 10
```

---

## CLI Commands

| Command | Description |
|---------|-------------|
| `shadowfence start` | Start the IDS engine |
| `shadowfence status` | Show configuration and detector status |
| `shadowfence setup-email` | Interactive email configuration |
| `shadowfence validate-rules <file>` | Validate detection rules file |
| `shadowfence list-interfaces` | List available network interfaces |
| `shadowfence list-captures` | List saved PCAP files |
| `shadowfence network-map` | Show discovered network devices |

### Start Options

| Flag | Description |
|------|-------------|
| `-c, --config <file>` | Path to config file (default: `config.yaml`) |
| `-i, --interface <name>` | Network interface to monitor |
| `--no-dashboard` | Disable web dashboard |
| `--no-email` | Disable email alerts |
| `--rules-dir <dir>` | Detection rules directory |
| `--pcap` | Enable PCAP forensic export |
| `--auto-block` | Enable automatic firewall blocking (dry-run) |
| `-v, --verbose` | Enable debug logging |

---

## Custom Detection Rules

Create rules in `rules/default_rules.yaml`:

```yaml
rules:
  - name: "Detect SSH Tunneling"
    description: "Detects SSH tunnel patterns in traffic"
    severity: high
    protocol: tcp
    dst_port: 22
    pattern: "SSH-2\\.0.*OpenSSH.*tunnel"
    action: alert
    enabled: true

  - name: "Detect Cryptocurrency Mining"
    description: "Detects crypto mining pool connections"
    severity: critical
    protocol: tcp
    pattern: "stratum\\+tcp|mining\\.pool|xmrig"
    action: alert
    enabled: true
```

Validate your rules:

```bash
shadowfence validate-rules rules/default_rules.yaml
```

---

## Threat Intelligence

### Using Blocklists

Create a blocklist file (`blocklist.json`):

```json
{
    "ips": [
        "198.51.100.1",
        "203.0.113.50"
    ],
    "domains": [
        "malware-c2.example.com",
        "phishing.example.net"
    ]
}
```

Or use a plain text file (`blocklist.txt`):

```
# Known malicious IPs
198.51.100.1
203.0.113.50
192.0.2.100
```

Configure in `config.yaml`:

```yaml
detection:
  threat_intel:
    enabled: true
    blocklist_path: "rules/blocklist.json"
```

### Community Blocklists

You can download community threat intelligence feeds:

```bash
# Download abuse.ch blocklist
curl -o rules/blocklist.txt https://feodotracker.abuse.ch/downloads/ipblocklist.txt

# Update config to use it
# threat_intel:
#   blocklist_path: "rules/blocklist.txt"
```

---

## Automated Firewall Response

ShadowFence can automatically block malicious IPs using your system's firewall.

### Enable (Dry Run — logs actions without blocking)

```yaml
detection:
  firewall:
    enabled: true
    auto_block: true
    dry_run: true              # SAFE: only logs what would be blocked
    block_duration: 3600       # Auto-unblock after 1 hour
    min_severity_to_block: high
    whitelist:
      - "127.0.0.1"
      - "::1"
      - "192.168.1.1"         # Add your gateway!
```

### Enable (Live Blocking — Use with Caution)

```yaml
detection:
  firewall:
    enabled: true
    auto_block: true
    dry_run: false             # LIVE: actually blocks IPs via iptables/netsh
    whitelist:
      - "127.0.0.1"
      - "::1"
      - "192.168.1.1"
      - "192.168.1.0/24"      # Whitelist your entire LAN
```

> **WARNING:** Setting `dry_run: false` will modify your system firewall rules. Always whitelist your gateway and trusted IPs to avoid locking yourself out.

### How It Works

- **Linux:** Uses `iptables -A INPUT -s <IP> -j DROP` and `iptables -A OUTPUT -d <IP> -j DROP`
- **Windows:** Uses `netsh advfirewall firewall add rule` with `action=block`
- Blocked IPs are automatically unblocked after `block_duration` seconds
- All actions are logged to `firewall_actions.log`

---

## PCAP Forensics

### Enable PCAP Export

```bash
# Command line
sudo shadowfence start --pcap

# Or in config.yaml
capture:
  pcap_export: true
  pcap_dir: "captures"
```

### Analyze with Wireshark

```bash
# List captured files
shadowfence list-captures

# Open in Wireshark
wireshark captures/capture_20250115_143022.pcap

# Or use tshark for CLI analysis
tshark -r captures/capture_20250115_143022.pcap -Y "tcp.flags.syn==1"
```

---

## Project Structure

```
shadowfence/
├── config.yaml                          # Main configuration file
├── pyproject.toml                       # Python package configuration
├── requirements.txt                     # Python dependencies
├── README.md                            # This documentation
├── LICENSE                              # MIT License
├── rules/
│   ├── default_rules.yaml               # 20+ detection signatures
│   └── example_blocklist.json           # Example threat intel feed
├── shadowfence/
│   ├── __init__.py                      # Package version
│   ├── __main__.py                      # python -m shadowfence support
│   ├── cli.py                           # CLI interface (click)
│   ├── config.py                        # Configuration loader
│   ├── capture/
│   │   ├── packet_parser.py             # Deep packet inspection
│   │   ├── sniffer.py                   # Multi-threaded packet capture
│   │   └── pcap_export.py               # PCAP forensic export
│   ├── detection/
│   │   ├── engine.py                    # Detection orchestrator
│   │   └── detectors/
│   │       ├── port_scan.py             # Port scan detection
│   │       ├── brute_force.py           # Brute force detection
│   │       ├── ddos.py                  # DDoS/flood detection
│   │       ├── arp_spoof.py             # ARP spoofing detection
│   │       ├── dns_tunnel.py            # DNS tunneling detection
│   │       ├── payload.py               # Signature-based detection
│   │       ├── protocol_anomaly.py      # Protocol anomaly detection
│   │       ├── bandwidth_anomaly.py     # Bandwidth & exfiltration
│   │       ├── ssl_anomaly.py           # SSL/TLS anomaly detection
│   │       ├── threat_intel.py          # Threat intelligence feeds
│   │       ├── firewall.py              # Automated firewall response
│   │       └── network_mapper.py        # Network topology mapper
│   ├── alerts/
│   │   ├── alert_manager.py             # Central alert routing
│   │   └── email_alert.py              # HTML email alerts
│   ├── dashboard/
│   │   ├── app.py                       # Flask + WebSocket server
│   │   ├── templates/index.html         # Dashboard UI
│   │   └── static/
│   │       ├── css/style.css            # Dark theme styles
│   │       └── js/dashboard.js          # Real-time chart updates
│   ├── logging/
│   │   └── logger.py                    # Structured JSONL logging
│   └── utils/
│       └── helpers.py                   # Utility functions
└── tests/
    ├── test_detection.py                # Core detector tests
    ├── test_alerts.py                   # Alert system tests
    └── test_advanced_detection.py       # Advanced detector tests
```

---

## How It Works

```
┌──────────────┐     ┌──────────────┐     ┌───────────────────────────────────┐
│   Network    │────>│   Packet     │────>│       Detection Engine            │
│  Interface   │     │   Capture    │     │                                   │
│  (scapy)     │     │   & Parser   │     │  ┌─────────────┐ ┌────────────┐  │
└──────────────┘     └──────────────┘     │  │  Port Scan   │ │  DDoS      │  │
                           │              │  │  Brute Force │ │  ARP Spoof │  │
                     ┌─────▼──────┐       │  │  DNS Tunnel  │ │  Payload   │  │
                     │   PCAP     │       │  │  Protocol    │ │  Bandwidth │  │
                     │   Export   │       │  │  SSL/TLS     │ │  Threat    │  │
                     └────────────┘       │  │  Network Map │ │  Intel     │  │
                                          │  └─────────────┘ └────────────┘  │
                                          └────────────┬──────────────────────┘
                                                       │
                         ┌─────────────────────────────┼──────────────────┐
                         │                             │                  │
                   ┌─────▼──────┐             ┌───────▼──────┐    ┌─────▼──────┐
                   │  Alert     │             │  Dashboard   │    │  Firewall  │
                   │  Manager   │             │  (WebSocket) │    │  Response  │
                   └─────┬──────┘             └──────────────┘    └────────────┘
                         │
               ┌─────────┼──────────┐
               │         │          │
        ┌──────▼──┐ ┌────▼───┐ ┌───▼────┐
        │ Console │ │ Email  │ │Webhook │
        │ (Rich)  │ │ (SMTP) │ │ (HTTP) │
        └─────────┘ └────────┘ └────────┘
```

### Detection Pipeline

1. **Packet Capture** — Scapy captures raw packets from the network interface
2. **Packet Parsing** — Deep inspection extracts protocol headers, flags, payloads
3. **PCAP Export** — Optionally saves raw packets for forensic analysis
4. **Detection Engine** — All 11 detectors analyze each packet in parallel
5. **Alert Generation** — Threats generate alerts with severity, type, source, description
6. **Alert Routing** — Alerts are sent to console, email, webhook, dashboard, and firewall
7. **Firewall Response** — Optionally blocks malicious IPs via iptables/netsh
8. **Dashboard Update** — Real-time WebSocket pushes updates to the web UI

---

## Testing

```bash
# Run all tests
pytest -v

# Run with coverage
pytest -v --cov=shadowfence

# Run specific test module
pytest tests/test_advanced_detection.py -v

# Lint check
ruff check .
```

---

## Author

**Sudeep Patil** — Network Security Engineer

- Designed and developed all 11 detection engines
- Built real-time dashboard, email alerting, and automated firewall response
- Architected the packet capture pipeline and threat intelligence integration

---

## License

MIT License. Copyright (c) 2025 Sudeep Patil. See [LICENSE](LICENSE) for details.
