# NACleaver

**Professional-grade Network Access Control bypass framework for authorized penetration testing.**

[![Python 3.10+](https://img.shields.io/badge/python-3.10+-blue.svg)](https://www.python.org/downloads/)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](LICENSE)
[![Platform: Linux](https://img.shields.io/badge/platform-linux-lightgrey.svg)](https://kernel.org)
[![Requires: root](https://img.shields.io/badge/requires-root-red.svg)](#requirements)
[![Quality and security checks](https://github.com/BridgerAlderson/NACleaver/actions/workflows/ci.yml/badge.svg)](https://github.com/BridgerAlderson/NACleaver/actions/workflows/ci.yml)

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
  - [doctor — Environment Preflight](#doctor--environment-preflight)
  - [recover — Crash Recovery](#recover--crash-recovery)
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

**Validation status:** The network operations are implemented, not simulated, and the automated
code checks pass on Python 3.14. Live switch, RADIUS, and NAC behavior has **not yet been validated
in a wired lab**. Treat this snapshot as a team-testing baseline, not as a guarantee of bypass or
production readiness. Run `doctor` on each test host, use engagement-approved verification targets,
and compare results with switch/RADIUS/NAC logs before reporting a finding.

**What it does:**

| Module | Technique |
|---|---|
| `doctor` | Validates runtime, privileges, interface capabilities, and mode dependencies without sending assessment traffic |
| `recon` | Fingerprints the NAC type in use before attempting any bypass |
| `mab` | Harvests authorized MAC addresses and impersonates them |
| `dot1x` | Attempts 802.1X authentication with PEAP, TTLS, PWD, MD5, TLS, FAST, TEAP, SIM, AKA, and AKA' |
| `relay` | Physically inserts between switch and authorized endpoint; transparently relays 802.1X |
| `posture` | Detects posture gates and runs an explicit engagement-specific HTTP workflow when configured |
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
│   ├── fingerprints.py       # Data-driven product signatures
│   ├── doctor.py             # Non-invasive environment preflight
│   ├── mab.py                # MAB bypass
│   ├── dot1x.py              # 802.1X bypass
│   ├── relay.py              # Transparent relay (multiprocessing)
│   ├── posture.py            # Posture bypass
│   └── utils.py              # Shared helpers, Cleanup registry
├── modules/
│   └── post_auth.py          # Post-bypass enumeration
└── data/
    ├── oui_seed.py           # Built-in OUI seed entries
    └── oui.db                # SQLite OUI database (auto-created)
```

### The `auto` pipeline

When NAC type is unknown, `auto` runs the full attack chain:

```
  run_recon()
      │
      ├─ OPEN ──────────────────→ keep verified interface access
      ├─ DOT1X ─────────────────→ run_dot1x() → optional relay fallback
      ├─ DHCP_ONLY / QUARANTINE ─→ run_mab_bypass() → dot1x → relay
      ├─ UNKNOWN ────────────────→ run_mab_bypass() → dot1x → relay
      └─ CAPTIVE_PORTAL ─────────→ detect_and_bypass_posture()
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
EAPOL frames are removed from kernel bridging by two interface-scoped `ebtables -t broute`
rules and relayed manually by two `multiprocessing.Process` instances — one per direction.
Each capture socket enables Linux `PACKET_IGNORE_OUTGOING`; relay startup fails closed if the
kernel cannot suppress locally transmitted frames, preventing EAPOL echo loops. When an
EAP-Success frame is detected on the switch-facing interface, a DHCP lease is requested on the
bridge interface. Forwarding remains active through access verification and post-auth work so
subsequent EAPOL exchanges can still pass; normal cleanup stops both workers before removing the
bridge. Worker PIDs and process start times are journaled for crash recovery. IPv4 DHCP and IPv6
SLAAC/DHCPv6 addressing are both supported.

---

## Requirements

### Python

- Python **3.10 or later** (required; uses union type syntax and structural pattern features)

```
scapy>=2.5.0
rich>=13.0.0
netifaces>=0.11.0
pyyaml>=6.0.0
requests>=2.31.0
```

### System tools

NACleaver resolves the exact tools required by the selected command before creating a cleanup
journal or changing interface state. Missing required tools fail fast with exit status `1`.
`doctor` remains the non-invasive way to inspect all required and optional capabilities.

| Tool | Used by | Install |
|---|---|---|
| `wpa_supplicant` | dot1x | `apt install wpasupplicant` |
| `wpa_cli` | dot1x | included with wpasupplicant |
| `nmcli` | dot1x (fallback) | `apt install network-manager` |
| `dhclient` | mab, dot1x, relay | `apt install isc-dhcp-client` |
| `ip` | all | `apt install iproute2` |
| `ebtables` | relay | `apt install ebtables` |
| `pkill` | cleanup/process isolation | `apt install procps` |
| `ethtool` | permanent-MAC recovery fallback | `apt install ethtool` |

### Platform

- **Kali Linux** (primary target)
- Any Debian/Ubuntu-based Linux with the above tools installed
- Assessment commands require a **root** shell. `doctor` can run unprivileged so it can report
  missing capabilities instead of exiting immediately.

---

## Installation

```bash
git clone https://github.com/BridgerAlderson/NACleaver.git
cd NACleaver

# Install the exact runtime versions used by the code-checked baseline
python3 -m pip install -r requirements.lock

# Contributors/CI: install the locked test, lint, SAST, and audit toolchain
python3 -m pip install -r requirements-dev.lock

# Install system tools (Kali/Debian)
apt install -y wpasupplicant network-manager isc-dhcp-client \
               iproute2 ebtables procps ethtool
```

No build step, no compilation. Run directly:

```bash
sudo python3 nacleaver.py --help
```

Use the same interpreter for installation and execution. If dependencies are installed in a
virtual environment, run `sudo .venv/bin/python nacleaver.py ...`; `sudo python3` does not
automatically use that environment. Commands that need packet capture fail early with an
actionable message when Scapy is missing from the selected interpreter.

---

## Quick Start

```bash
# 0. Validate the exact runtime and interface before touching the segment
sudo python3 nacleaver.py -i eth0 doctor --mode recon

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

# Recover a MAC left spoofed by an older/untracked run
sudo python3 nacleaver.py -i eth0 restore-mac

# Replay persistent cleanup state after a crash or SIGKILL
sudo python3 nacleaver.py recover
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

### `doctor` — Environment Preflight

Checks the exact interpreter and host capabilities that a mode needs without sending discovery,
authentication, or bypass traffic. It reports required versus optional checks for Linux, Python,
root privileges, link/carrier state, command dependencies, Scapy, `SO_BINDTODEVICE`, raw
`AF_PACKET`, and (for relay) `PACKET_IGNORE_OUTGOING`, worker-process startup, plus the second interface. Dot1X/all mode
also reports whether the installed `wpa_supplicant` build accepts TEAP; this capability is
informational because TEAP is not compiled into many distribution packages.

```bash
# Check one execution path
sudo .venv/bin/python nacleaver.py -i eth0 doctor --mode mab

# Check every path; a second interface is required because this includes relay
sudo .venv/bin/python nacleaver.py -i eth0 -i2 eth1 doctor --mode all
```

The JSON result contains every check and a top-level `ready` verdict. IPv4 and IPv6 are reported
independently; posture/post modes accept either family. Missing privileges, packet capability,
required tool, or relay interface is
a failure. The command exits with status `2` when required checks fail, making it suitable for a
pre-engagement setup script.

---

### `recover` — Crash Recovery

State-changing modes atomically record MAC, NetworkManager, bridge, ebtables, disposable
connection, and temporary-file state in a root-only journal under `/run/nacleaver`. Normal exit,
`Ctrl+C`, and `SIGTERM` clear it. After a crash or `SIGKILL`, replay stale journals with:

```bash
sudo python3 nacleaver.py recover
```

Live process journals are skipped. Use `--force` only after confirming the recorded process no
longer owns the interface. Recovery exits `2` if any record remains incomplete and saves an
auditable per-journal JSON result.

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

2. **Address-control probes** — If no EAPOL is observed, sends DHCPv4 Discover, IPv6 Router
   Solicitation, and DHCPv6 Solicit. Offers, Advertises, prefixes, RDNSS values, and router
   evidence are recorded; control traffic alone is never reported as an assigned lease.

3. **Bound connectivity check** — Only when the selected interface owns usable IPv4 or IPv6,
   sends a raw HTTP request bound with `SO_BINDTODEVICE`:
   - `2xx` → `OPEN` (connectivity verified on this interface)
   - `3xx` redirect → `CAPTIVE_PORTAL`
   - no response → `QUARANTINE_VLAN`
   - DHCP Offer without an assigned address → `DHCP_ONLY`

4. **CDP/LLDP parse** — Opportunistically captures switch discovery frames to extract switch
   hostname and port ID (useful for engagement documentation).

**NAC types returned:**

| Type | Meaning |
|---|---|
| `DOT1X` | EAPOL frames observed — port enforces 802.1X |
| `OPEN` | The selected interface has IPv4/IPv6 and bound connectivity is verified |
| `DHCP_ONLY` | DHCPv4/DHCPv6/RA evidence exists, but no usable address is assigned |
| `QUARANTINE_VLAN` | Interface has an address but bound connectivity fails |
| `CAPTIVE_PORTAL` | Interface-bound HTTP probe is redirected |
| `UNKNOWN` | No inbound EAPOL, address-control evidence, or assigned address; detection is inconclusive |

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
| IPv6 traffic seen | `+8` |
| STP frames seen (switch uplink) | `−60` and rejected |
| CDP/LLDP frames seen (network device) | `−60` and rejected |
| OUI category: workstation | `+25` |
| OUI category: mobile | `+5` |
| OUI category: printer | `−10` |
| OUI category: network device | `−100` and rejected |

Automatic selection also rejects candidates without ARP/IPv4/IPv6 endpoint evidence and candidates
below `--min-score` (default `15`). After selection, NetworkManager is temporarily detached,
the MAC change is verified, and an isolated one-shot `dhclient` must exit successfully *and*
assign IPv4 or IPv6 before the authorization stage succeeds. Address assignment is not proof of usable
access: the CLI records a separate interface-bound verification result. The original MAC and
NetworkManager profile are restored and verified on exit unless `--no-restore-mac` is set.

---

### `dot1x` — 802.1X Authentication Bypass

Attempts 802.1X authentication using the real kernel 802.1X stack (`wpa_supplicant` primary,
`nmcli` fallback). Supports 11 EAP profiles with automatic priority-ordered fallback and
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
  --private-key /path/to/key.pem \
  --server-ca-cert /path/to/client-radius-ca.pem \
  --server-domain radius.client.example

# EAP-FAST with a persistent PAC store and explicitly authorized provisioning
sudo python3 nacleaver.py -i eth0 dot1x -u pentest -p 'Password123' \
  --eap-method fast --pac-file /var/lib/nacleaver/client.pac \
  --fast-provisioning 1 --backend wpa_supplicant

# EAP-SIM/AKA/AKA' through a real PC/SC SIM/USIM reader
sudo python3 nacleaver.py -i eth0 dot1x --eap-method aka \
  --sim-pcsc --sim-pin '1234' --backend wpa_supplicant

# Only when explicitly required by the authorized test plan: disable server
# certificate validation to assess insecure supplicant policy
sudo python3 nacleaver.py -i eth0 dot1x -u pentest -p 'Password123' \
  --insecure-no-server-cert

# Use nmcli backend instead of wpa_supplicant
sudo python3 nacleaver.py -i eth0 dot1x -u pentest -p 'Password123' --backend nmcli
```

**Available EAP profiles:**

| Priority | Method | Common use case |
|---|---|---|
| 1 | `peap` (PEAP/MSCHAPv2) | Enterprise AD authentication — most common |
| 2 | `ttls_mschapv2` (TTLS/MSCHAPv2) | Alternative to PEAP |
| 3 | `ttls_pap` (TTLS/PAP) | Legacy deployments |
| 4 | `teap` (TEAP/MSCHAPv2) | TLS-based tunnel; compiled supplicant support required |
| 5 | `pwd` (EAP-PWD) | Password-based, RFC 5931 |
| 6 | `md5` (EAP-MD5) | Legacy challenge-response |
| 7 | `tls` (EAP-TLS) | Certificate-based — requires client certificate and key |
| 8 | `fast` (FAST/MSCHAPv2) | PAC-based tunnel — requires `--pac-file` |
| 9 | `sim` (EAP-SIM) | Real PC/SC GSM SIM/USIM |
| 10 | `aka` (EAP-AKA) | Real PC/SC USIM |
| 11 | `aka_prime` (EAP-AKA') | Real PC/SC USIM with AKA' |

The portable default automatic order is PEAP, TTLS/MSCHAPv2, TTLS/PAP, PWD, then MD5. TEAP is
implemented but selected explicitly or added to `method_order` only after `doctor --mode dot1x`
confirms that the local supplicant build accepts it. TLS, FAST, SIM, AKA, and AKA' are likewise
selected explicitly or added to `method_order` because they require engagement-specific material.
Before touching the interface, NACleaver asks the installed `wpa_supplicant` parser whether the
chosen method was compiled into that build and reports a clear unsupported-method result instead
of treating a missing plugin as bad credentials.

**Credential file format:**

```
# Lines starting with # are ignored
admin:Password123
jsmith:Summer2024!
serviceaccount:
```

Each `identity:password` pair is tried against every enabled EAP method (in priority order)
before moving to the next credential. Authorization-stage success requires both an authenticated
802.1X state and an assigned IPv4 or IPv6 address; final success additionally requires interface-bound
connectivity verification. The successful `wpa_supplicant`/temporary NetworkManager profile stays
alive through posture and post-auth work, then cleanup restores the previous connection. Passwords
are redacted from JSON and are not placed in `nmcli` process arguments. Encrypted EAP-TLS keys
use `--private-key-password`, also via a private secret file. PEAP, TTLS, TEAP, and TLS use
the operating system CA store by default. `--server-ca-cert`, `--server-domain`, and
`--anonymous-identity` support engagement-specific supplicant policy; disabling RADIUS server
certificate validation requires the explicit `--insecure-no-server-cert` flag. FAST, TEAP,
SIM, AKA, and AKA' require the `wpa_supplicant` backend.

---

### `relay` — Transparent 802.1X Relay

An inline assessment path that does not require test credentials. Physical insertion between the switch and
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
3. Interface-scoped `ebtables` rules remove EAPOL frames (0x888E) from kernel bridging
4. Two `multiprocessing.Process` instances start — one sniffing each interface, forwarding
   ingress-only EAPOL frames in the opposite direction
5. All other traffic (DHCP, ARP, TCP/UDP) passes through the kernel bridge transparently
6. When an EAP-Success frame is observed on the switch side, the port is marked authorized
7. `dhclient` requests a lease on the bridge interface
8. EAPOL forwarding stays active until access verification and post-auth work complete
9. On exit or timeout: workers stop, bridge is torn down, NACleaver's exact ebtables rules are removed, original state restored

The bridge and ebtables rules are registered with the `Cleanup` singleton, so `Ctrl+C` or
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
| FortiNAC | HTTPS marker fingerprint on configured/default management portal |
| PacketFence | HTTPS marker fingerprint on configured/default captive portal |

The built-in signatures are validated data, not hard-coded scanner branches. `posture.signatures`
can replace them with engagement-specific TCP ports, HTTP response markers, rDNS markers, posture
type, and workflow URL. IPv6 gateways are formatted and probed correctly. HTTPS fingerprints
validate TLS by default. An engagement-specific probe may set `verify_tls: false` only when a
self-signed appliance must be assessed; resulting evidence is labeled explicitly as unverified
TLS and is never treated as final access proof.

**HTTP posture workflow:**

NACleaver does not fabricate generic agent identities or compliance results. If a redirect portal
is detected, it selects only a workflow whose `match_hosts` entry matches that portal. Agent/API
workflows can instead use `match_posture_types` or `match_products` plus an explicit `base_url`. The
engagement config defines the authorized HTTP steps and their exact status, JSON, or body
expectations. Every step is restricted to the detected portal's origin. Even when all response
expectations match, success is reported only after the configured interface-bound access proof
succeeds.

When no matching workflow is configured, the gate is reported with `bypass_attempted: false`; no
synthetic request is sent. Proprietary agent protocols that require signed measurements, device
certificates, TPM state, or vendor secrets are never forged. Their real, authorized HTTP/API
transactions can be described as workflows; unsupported signed protocols remain explicit
evidence findings rather than false-positive successes.

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
| `OPEN` | Keep already verified access; do not spoof a MAC |
| `DOT1X` | `dot1x` if credentials are supplied, then optional `relay` fallback |
| `DHCP_ONLY` / `QUARANTINE_VLAN` | `mab` → optional `dot1x` → optional `relay` |
| `CAPTIVE_PORTAL` | Interface-bound posture handling |
| `UNKNOWN` | `mab` → optional `dot1x` → optional `relay` |

After an authorization-stage success, posture handling and a fresh interface-bound connectivity
probe run automatically. Active post-auth enumeration starts only when that final probe verifies
usable access (unless enumeration itself is run explicitly as a standalone command).

---

### `post` — Post-Auth Enumeration

Enumerates the internal network segment after a successful bypass. Runs automatically in
`auto` mode; can also be run standalone if you already have an IP.

```bash
sudo python3 nacleaver.py -i eth0 post
```

**What it does:**

1. **Layer-2 discovery** — ARP-scans IPv4 through the selected interface; broad prefixes are
   bounded by `post_auth.max_hosts`. IPv6 uses the NDP cache plus a link-local all-nodes multicast
   probe and never attempts to enumerate an entire `/64` numerically
2. **OUI lookup** — Resolves each discovered MAC to a vendor name via the OUI database
3. **TCP port scan** — Scans a targeted port list on each discovered host using a thread pool
   (20 concurrent workers, 0.5s timeout per port)
4. **Reverse DNS** — Attempts FQDN resolution for each host
5. **Gateway probe** — Scans the gateway for open ports and grabs the HTTP `Server` header
6. **NAC server fingerprint** — Applies the same configurable TCP, HTTP marker, and rDNS product
   signatures used by posture detection

**Ports scanned by default:**
`22, 80, 443, 445, 1040, 1443, 3389, 8080, 8081, 8443, 8905`

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
| `--timeout` | config | Per-attempt/auth timeout in seconds |
| `--dhcp-timeout` | config | IPv4/IPv6 address acquisition timeout in seconds |
| `--harvest-duration` | `60` | MAC harvest window in seconds (MAB) |
| `--min-score` | `15` | Minimum automatic MAB candidate score |
| `--eap-method` | `auto` | EAP profile: PEAP, TTLS, PWD, MD5, TLS, FAST, TEAP, SIM, AKA, AKA', or `auto` |
| `--spray-delay` | `2.0` | Seconds between credential spray attempts |
| `--backend` | `auto` | 802.1X backend: `wpa_supplicant`, `nmcli`, `auto` |
| `--conn-name` | `NACleaver-8021x` | nmcli connection name |
| `--client-cert` | — | Client certificate path (EAP-TLS) |
| `--private-key` | — | Private key path (EAP-TLS) |
| `--private-key-password` | — | Password for an encrypted EAP-TLS key |
| `--server-ca-cert` | system CA | CA certificate for RADIUS server validation |
| `--server-domain` | — | Required RADIUS certificate domain suffix |
| `--anonymous-identity` | — | Outer identity for PEAP/TTLS |
| `--insecure-no-server-cert` | `false` | Explicitly disable RADIUS server certificate validation |
| `--pac-file` | — | Persistent writable PAC store for EAP-FAST |
| `--fast-provisioning` | `0` | EAP-FAST provisioning mode `0`–`3` |
| `--sim-pin` | — | PIN for a real PC/SC SIM/USIM |
| `--sim-pcsc [reader]` | first reader | Select PC/SC reader for SIM/AKA/AKA' |
| `--sim-number` | — | Select a non-negative slot on multi-SIM implementations |
| `--no-restore-mac` | `false` | Do not restore original MAC on exit |
| `--no-posture` | `false` | Skip posture bypass after auth |
| `--no-post` | `false` | Skip post-auth enumeration |
| `-o`, `--output` | `output/` | Output directory for logs and JSON results |
| `--config` | `config.yaml` | Alternate YAML configuration file |
| `-v`, `--verbose` | `false` | Verbose logging |

---

## Output Format

Every command writes timestamped results to `output/nacleaver_YYYYMMDD_HHMMSS_microseconds.json`:

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
    "authorization_success": true,
    "outcome": "verified_access",
    "obtained_ip": "10.10.50.147",
    "bypass_method": "dot1x",
    "network_interface": "eth0"
  }
}
```

Log files are also written to `output/nacleaver_YYYYMMDD_HHMMSS_microseconds.log`. Both JSON and
log artifacts are created with mode `0600`; when invoked through `sudo`, ownership is returned to
the invoking user so the results do not become unreadable root-owned files.

`summary.success` means the fixed connectivity endpoint was reached through the selected
interface. `summary.authorization_success` records the lower-level authentication/DHCP result.
On an intentionally internet-isolated internal network, a valid authorization may therefore be
reported as `restricted_or_unverified` rather than being overstated as a verified bypass.

Process exit statuses are stable for automation:

| Status | Meaning |
|---|---|
| `0` | Command completed and its requested access/recovery goal was verified, or an evidence-only `recon`/`post` command completed |
| `1` | Fatal execution, dependency, configuration, or result-persistence failure |
| `2` | Assessment completed but access/readiness/restoration was not verified |
| `130` / `143` | Interrupted by `SIGINT` / `SIGTERM` after cleanup |

---

## Configuration

`config.yaml` sets default timeouts and behavior. CLI flags always take precedence:

```yaml
recon:
  eapol_timeout: 30       # Seconds to sniff for EAPOL frames
  dhcp_timeout: 10        # Seconds to wait for DHCP offer
  http_timeout: 5         # Interface-bound connectivity probe

mab:
  harvest_duration: 60    # MAC observation window
  min_score: 15.0         # Minimum score to consider a candidate
  dhcp_timeout: 30        # Require assigned IPv4 or IPv6

dot1x:
  default_timeout: 15     # Per-EAP-method timeout
  spray_delay: 2.0        # Delay between spray attempts
  preferred_backend: auto # wpa_supplicant | nmcli | auto
  server_ca_cert: null    # null uses the operating system CA store
  server_domain: null     # e.g. radius.client.example
  anonymous_identity: null
  private_key_password: null
  insecure_no_server_cert: false
  pac_file: null          # Required when FAST is selected
  fast_provisioning: 0    # 0 disabled; 1/2/3 are explicit provisioning modes
  sim_pin: null
  sim_pcsc: ""            # Empty selects the first PC/SC reader
  sim_number: null
  method_order:
    - peap_mschapv2
    - ttls_mschapv2
    - ttls_pap
    - pwd
    - md5

relay:
  auth_timeout: 90        # Max wait for EAP-Success
  dhcp_timeout: 15
  bridge_name: nacleaver_br

posture:
  probe_timeout: 5
  signatures: null        # null = maintained built-in product evidence signatures
  http_workflows: []      # No synthetic posture requests by default

verification:
  policy: any             # any | all
  targets: []             # Empty = built-in interface-bound public probe

post_auth:
  arp_sweep: true
  arp_timeout: 2
  port_scan: true
  port_scan_timeout: 0.5
  max_hosts: 1024         # Bound broad ARP sweeps
  nac_probe_timeout: 1.0
  ports: [22, 80, 443, 445, 1040, 1443, 3389, 8080, 8081, 8443, 8905]
```

For an internal-only engagement, define authoritative targets so Internet egress is not mistaken
for the access policy under test:

```yaml
verification:
  policy: all
  targets:
    - name: internal-health
      type: http
      url: https://health.client.example/nac-test
      verify_tls: true
      expected_status: [200]
      body_contains: [authorized]
    - name: approved-service
      type: tcp
      host: 10.20.30.40
      port: 443
```

An authorized captive-portal transaction can be represented without embedding generic fake
posture data:

```yaml
posture:
  probe_timeout: 5
  http_workflows:
    - name: authorized-guest-portal
      match_hosts: [portal.client.example]
      verify_tls: true
      steps:
        - name: accept-authorized-use-policy
          method: POST
          path: /api/accept
          json: {accepted: true}
          expected_status: [200]
          expected_json: {status: accepted}
```

For a product/API workflow without a detected redirect, use a context match and explicit origin:

```yaml
posture:
  http_workflows:
    - name: authorized-client-agent-api
      match_products: [Client NAC]
      match_posture_types: [unknown]
      base_url: https://nac.client.example/
      verify_tls: true
      steps:
        - name: query-authorized-assessment-state
          method: GET
          path: /api/assessment/state
          expected_status: [200]
          expected_json: {state: authorized}
```

Request bodies and headers are not copied into the JSON result; the report retains the step name,
method, URL, response status, and match outcome.

---

## Real-World Scenarios

### Scenario 1: Unknown corporate segment

You're plugged into a wall jack and don't know what NAC is deployed.

```bash
# Step 1: reconnaissance
sudo python3 nacleaver.py -i eth0 recon --timeout 30

# Output says: NAC Type = DHCP_ONLY or QUARANTINE_VLAN
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

The database auto-creates from `data/oui_seed.py` on first run. When available, NACleaver also
reads the distribution IEEE registry (for example `/usr/share/ieee-data/oui.txt`) and caches
lookups, avoiding the small built-in database's unknown/misclassified vendor problem.
Prefixes that conflicted in older built-in seeds are treated as unknown unless a system registry
or a supplied IEEE CSV resolves them; an old local cache cannot silently reintroduce the conflict.

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

### Interpretation limits

- A DHCP Offer or an assigned address is evidence of one stage, not proof that NAC controls were
  bypassed. Final success requires the configured interface-bound connectivity proof.
- The default proof uses Cloudflare's `1.1.1.1/cdn-cgi/trace`. An authorized network with no
  internet egress can legitimately produce `restricted_or_unverified`; configure engagement-
  approved `verification.targets` to prove the specific internal access that is in scope. Recon
  and auto mode use those targets for classification before changing an interface; auto mode
  additionally checks them when EAPOL evidence short-circuits recon classification.
- Passive MAB harvesting on a normal switched access port can see only traffic delivered to that
  port. It cannot guarantee visibility of every authorized endpoint, and cloning an endpoint that
  remains active can trigger duplicate-MAC or port-security controls.
- HTTP posture handling is configuration-driven and never claims compliance from a generic
  payload. Modern posture systems may require stateful agent protocols, certificates, TPM-backed
  identity, or signed measurements. Those cases are reported as unsupported signed-protocol
  evidence unless an authorized, real product workflow has been configured.
- Relay mode requires a real inline two-interface topology. Unit tests validate state handling and
  cleanup, but only an isolated wired lab can validate switch timing and driver behavior end to end.

### MAC restoration

NACleaver's `Cleanup` class registers the original MAC address before any spoof and restores
it on exit — including on `Ctrl+C` and `SIGTERM`. State is also written atomically to a private
recovery journal for crash/SIGKILL recovery. The sequence:

1. `Cleanup.register_mac(iface, original_mac)` is called **before** `ip link set address`
2. On exit: `wpa_supplicant` / `dhclient` are killed, then MAC is restored via `ip link`

Use `--no-restore-mac` to leave the spoofed MAC in place (e.g. for persistence testing).
If an older/crashed version already left the interface spoofed, recover the driver-reported
hardware address explicitly:

```bash
sudo python3 nacleaver.py -i eth0 restore-mac
```

The command temporarily detaches NetworkManager, restores and verifies the permanent MAC, then
reactivates the connection that was active before recovery.

### Bridge teardown

The relay module's bridge (`nacleaver_br`) and interface-scoped ebtables rules are registered with
`Cleanup` and torn down automatically. If a forcefully killed process leaves state behind, use the
journal before considering a manual operation:

```bash
sudo python3 nacleaver.py recover
```

The journal retains failed cleanup entries so recovery is retryable. Only if the journal itself is
unavailable should the exact engagement interfaces/rules be removed manually:

```bash
ebtables -t broute -D BROUTING -i eth0 -p 0x888e -j DROP
ebtables -t broute -D BROUTING -i eth1 -p 0x888e -j DROP
ip link set eth0 nomaster
ip link set eth1 nomaster
ip link delete nacleaver_br
```

### wpa_supplicant conflicts

NetworkManager and an external `dhclient` must not own the same interface concurrently.
For the `wpa_supplicant` and MAB paths, NACleaver records the active profile, disconnects the
device, marks it temporarily unmanaged, and restores the prior profile during cleanup. The
`nmcli` backend instead creates a uniquely named disposable profile and never modifies an
existing user profile.

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
├── requirements.txt      # Maintained direct runtime constraints
├── requirements.lock     # Exact validated runtime versions
├── requirements-dev.txt  # Maintained development constraints
├── requirements-dev.lock # Exact CI/security toolchain versions
├── pyproject.toml        # pytest, coverage, and ruff policy
├── .github/workflows/    # Test, coverage, lint, SAST, and CVE CI
├── config.yaml           # Default configuration
├── core/
│   ├── __init__.py
│   ├── utils.py          # Helpers: interface ops, subprocess, logging, Cleanup
│   ├── doctor.py         # Non-invasive runtime/interface preflight
│   ├── recon.py          # EAPOL/DHCPv4/DHCPv6/RA/CDP/portal detection
│   ├── fingerprints.py   # Validated, configurable NAC product signatures
│   ├── mab.py            # OUI DB, MAC scoring, spoof + DHCP
│   ├── dot1x.py          # wpa_supplicant/nmcli backends, EAP methods, spray
│   ├── relay.py          # Linux bridge, ebtables, multiprocessing EAPOL relay
│   └── posture.py        # Product detection and configured HTTP/API workflows
├── modules/
│   ├── __init__.py
│   └── post_auth.py      # ARP/NDP discovery, dual-stack scan, NAC fingerprint
└── data/
    ├── oui_seed.py       # Built-in OUI seed entries (Python dict)
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
- Run `python3 -m compileall -q nacleaver.py core modules tests`
- Run `ruff check nacleaver.py core modules tests`
- Run `python3 -m pytest --cov --cov-report=term-missing` using the interpreter where the
  locked dependencies were installed
- Run `bandit -q -r nacleaver.py core modules`
- Run `pip-audit -r requirements.lock`
- Do not add features that cannot be fully implemented — no stubs, no TODOs

---

## License

MIT License. See [LICENSE](LICENSE) for details.

This software is provided for authorized security testing only. The authors are not responsible
for illegal or unauthorized use.
