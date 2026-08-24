import concurrent.futures
import ipaddress
import logging
import os
import socket
import struct
import time
from dataclasses import dataclass, field

import netifaces

from core.utils import get_iface_ip, get_iface_netmask, ip_to_network, run_subprocess
from core.mab import lookup_oui

logger = logging.getLogger('nacleaver')

PORT_SCAN_TARGETS = [22, 80, 443, 445, 3389, 8080, 8443, 8905, 8081, 1040]


@dataclass
class HostEntry:
    ip: str
    mac: str
    vendor: str
    open_ports: list[int] = field(default_factory=list)
    hostname: str | None = None


@dataclass
class PostAuthResult:
    obtained_ip: str
    subnet: str
    gateway: str | None
    dns_servers: list[str] = field(default_factory=list)
    domain_name: str | None = None
    dhcp_options: dict = field(default_factory=dict)
    nac_server_ip: str | None = None
    nac_server_type: str | None = None
    discovered_hosts: list[HostEntry] = field(default_factory=list)
    gateway_ports: list[int] = field(default_factory=list)
    duration_sec: float = 0.0


def _arp_sweep(iface: str, subnet: str, timeout: int = 2) -> list[tuple[str, str]]:
    """ARP ping an entire subnet. Returns list of (ip, mac) tuples."""
    from scapy.all import Ether, ARP, srp

    results = []
    try:
        answered, _ = srp(
            Ether(dst="ff:ff:ff:ff:ff:ff") / ARP(pdst=subnet),
            iface=iface,
            timeout=timeout,
            verbose=False,
        )
        for _, rcv in answered:
            results.append((rcv.psrc, rcv.hwsrc))
    except Exception as e:
        logger.debug(f"[post_auth] ARP sweep error: {e}")

    return results


def _tcp_connect(ip: str, port: int, timeout: float) -> int | None:
    """Return port if open, None if closed/filtered."""
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.settimeout(timeout)
    try:
        result = sock.connect_ex((ip, port))
        if result == 0:
            return port
        return None
    except (socket.timeout, OSError):
        return None
    finally:
        sock.close()


def _tcp_port_scan(ip: str, ports: list[int], timeout: float = 0.5) -> list[int]:
    """Scan TCP ports on ip using thread pool. Returns list of open ports."""
    open_ports = []
    with concurrent.futures.ThreadPoolExecutor(max_workers=20) as executor:
        futures = {executor.submit(_tcp_connect, ip, port, timeout): port for port in ports}
        for future in concurrent.futures.as_completed(futures):
            try:
                result = future.result()
                if result is not None:
                    open_ports.append(result)
            except Exception as e:
                logger.debug(f"[post_auth] Port scan error: {e}")
    return sorted(open_ports)


def _probe_gateway(gateway: str, ports: list[int]) -> tuple[list[int], str | None]:
    """Scan gateway ports and grab HTTP banner if port 80 is open."""
    open_ports = _tcp_port_scan(gateway, ports, timeout=0.5)
    server_banner = None

    if 80 in open_ports:
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(3)
            sock.connect((gateway, 80))
            sock.sendall(b"GET / HTTP/1.0\r\nHost: " + gateway.encode() + b"\r\n\r\n")
            response = sock.recv(1024).decode('utf-8', errors='replace')
            sock.close()
            for line in response.splitlines():
                if line.lower().startswith('server:'):
                    server_banner = line.split(':', 1)[1].strip()
                    break
        except (socket.timeout, OSError, ValueError) as e:
            logger.debug(f"[post_auth] Gateway HTTP probe error: {e}")

    return open_ports, server_banner


def _detect_nac_server(
    gateway: str,
    dns_servers: list[str],
    timeout: int = 3,
) -> tuple[str | None, str | None]:
    """Probe for NAC server presence on gateway and DNS servers."""
    nac_port_map = {
        8905: ("Cisco ISE", gateway),
        8081: ("Aruba ClearPass", gateway),
        1040: ("Forescout", gateway),
    }

    for port, (nac_type, target) in nac_port_map.items():
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(timeout)
        try:
            result = sock.connect_ex((target, port))
            if result == 0:
                logger.info(f"[post_auth] NAC server detected: {nac_type} at {target}:{port}")
                sock.close()
                return target, nac_type
        except (socket.timeout, OSError):
            pass
        finally:
            sock.close()

    # rDNS sometimes leaks hostnames like ise.corp or clearpass.corp
    candidates = [gateway] + dns_servers
    nac_keywords = {
        'ise': 'Cisco ISE',
        'clearpass': 'Aruba ClearPass',
        'forescout': 'Forescout',
        'nac': 'Unknown NAC',
        'radius': 'Unknown NAC',
    }
    for host in candidates:
        try:
            hostname = socket.getfqdn(host)
            hostname_lower = hostname.lower()
            for keyword, nac_type in nac_keywords.items():
                if keyword in hostname_lower and hostname_lower != host:
                    logger.info(f"[post_auth] NAC server hint via rDNS: {host} → {hostname} ({nac_type})")
                    return host, nac_type
        except (socket.timeout, OSError):
            pass

    return None, None


def _parse_dhcp_leases(iface: str) -> dict:
    """Parse dhclient lease files for DHCP options."""
    lease_paths = [
        f"/var/lib/dhcp/dhclient.{iface}.leases",
        "/var/lib/dhcp/dhclient.leases",
        "/var/lib/dhclient.leases",
        f"/tmp/dhclient.{iface}.leases",
    ]

    for path in lease_paths:
        if os.path.exists(path):
            return _parse_lease_file(path)
    return {}


def _parse_lease_file(path: str) -> dict:
    """Parse the last lease block from a dhclient lease file."""
    options: dict = {}
    try:
        with open(path) as f:
            content = f.read()

        blocks = content.split('lease {')
        if len(blocks) < 2:
            return options

        last_block = blocks[-1]
        for line in last_block.splitlines():
            line = line.strip().rstrip(';')
            if line.startswith('option domain-name ') and 'domain-name-servers' not in line:
                options['domain-name'] = line.split(None, 2)[2].strip('"')
            elif line.startswith('option domain-name-servers '):
                options['domain-name-servers'] = line.split(None, 2)[2]
            elif line.startswith('option routers '):
                options['routers'] = line.split(None, 2)[2]
            elif line.startswith('option subnet-mask '):
                options['subnet-mask'] = line.split(None, 2)[2]
            elif line.startswith('option ntp-servers '):
                options['ntp-servers'] = line.split(None, 2)[2]
    except (OSError, IndexError) as e:
        logger.debug(f"[post_auth] Lease file parse error: {e}")

    return options


def _read_resolv_conf() -> list[str]:
    """Parse /etc/resolv.conf for nameserver lines."""
    dns_servers = []
    try:
        with open('/etc/resolv.conf') as f:
            for line in f:
                line = line.strip()
                if line.startswith('nameserver '):
                    ns = line.split(None, 1)[1].strip()
                    if ns and ns not in dns_servers:
                        dns_servers.append(ns)
    except OSError:
        pass
    return dns_servers


def _get_gateway_from_routes(iface: str) -> str | None:
    """Extract default gateway from ip route for the given interface."""
    rc, out, _ = run_subprocess(["ip", "route", "show", "dev", iface])
    if rc != 0:
        return None
    for line in out.splitlines():
        parts = line.split()
        if 'default' in line:
            try:
                via_idx = parts.index('via')
                return parts[via_idx + 1]
            except (ValueError, IndexError):
                pass
        elif len(parts) >= 3 and parts[1] == 'via':
            return parts[2]
    # fallback: global default route
    rc, out, _ = run_subprocess(["ip", "route", "show", "default"])
    if rc == 0:
        for line in out.splitlines():
            parts = line.split()
            try:
                via_idx = parts.index('via')
                return parts[via_idx + 1]
            except (ValueError, IndexError):
                pass
    return None


def run_post_auth(
    iface: str,
    obtained_ip: str,
    arp_sweep: bool = True,
    port_scan: bool = True,
    verbose: bool = False,
) -> PostAuthResult:
    """Full post-bypass network enumeration."""
    start_time = time.time()

    netmask = get_iface_netmask(iface)
    subnet = ip_to_network(obtained_ip, netmask) if netmask else f"{obtained_ip}/24"
    gateway = _get_gateway_from_routes(iface)
    dns_servers = _read_resolv_conf()
    dhcp_opts = _parse_dhcp_leases(iface)
    domain_name = dhcp_opts.get('domain-name')

    if verbose:
        logger.info(f"[post_auth] IP={obtained_ip}, subnet={subnet}, GW={gateway}, DNS={dns_servers}")

    result = PostAuthResult(
        obtained_ip=obtained_ip,
        subnet=subnet,
        gateway=gateway,
        dns_servers=dns_servers,
        domain_name=domain_name,
        dhcp_options=dhcp_opts,
    )

    discovered_hosts: list[HostEntry] = []

    if arp_sweep:
        if verbose:
            logger.info(f"[post_auth] ARP sweeping {subnet} ...")
        arp_results = _arp_sweep(iface, subnet, timeout=2)
        if verbose:
            logger.info(f"[post_auth] ARP sweep found {len(arp_results)} hosts")

        for ip, mac in arp_results:
            if ip == obtained_ip:
                continue
            vendor, _ = lookup_oui(mac)

            hostname = None
            try:
                hostname = socket.getfqdn(ip)
                if hostname == ip:
                    hostname = None
            except (socket.timeout, OSError):
                pass

            open_ports: list[int] = []
            if port_scan:
                open_ports = _tcp_port_scan(ip, PORT_SCAN_TARGETS, timeout=0.5)

            discovered_hosts.append(HostEntry(
                ip=ip,
                mac=mac,
                vendor=vendor,
                open_ports=open_ports,
                hostname=hostname,
            ))

    result.discovered_hosts = discovered_hosts

    if gateway:
        gw_ports, _ = _probe_gateway(gateway, PORT_SCAN_TARGETS)
        result.gateway_ports = gw_ports

        nac_ip, nac_type = _detect_nac_server(gateway, dns_servers)
        result.nac_server_ip = nac_ip
        result.nac_server_type = nac_type

        if verbose and nac_type:
            logger.info(f"[post_auth] NAC server: {nac_type} at {nac_ip}")

    result.duration_sec = time.time() - start_time

    if verbose:
        logger.info(f"[post_auth] Enumeration complete in {result.duration_sec:.1f}s")
        logger.info(f"[post_auth] Discovered {len(discovered_hosts)} hosts")

    return result


if __name__ == "__main__":
    import sys
    from rich import print as rprint
    from core.utils import require_root, setup_logging, get_iface_ip as _get_ip
    require_root()
    setup_logging(verbose=True)
    if len(sys.argv) < 2:
        print("Usage: sudo python3 modules/post_auth.py <iface>")
        sys.exit(1)
    iface = sys.argv[1]
    ip = _get_ip(iface)
    if not ip:
        print(f"No IP on {iface}")
        sys.exit(1)
    result = run_post_auth(iface, ip, verbose=True)
    rprint(result)
