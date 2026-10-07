import concurrent.futures
import ipaddress
import logging
import os
import socket
import time
from dataclasses import dataclass, field


from core.utils import (
    get_cached_lease_paths,
    get_iface_ipv6s,
    get_iface_netmask,
    ip_to_network,
    run_subprocess,
)
from core.mab import lookup_oui
from core.fingerprints import validated_signatures

logger = logging.getLogger('nacleaver')

PORT_SCAN_TARGETS = [22, 80, 443, 445, 1040, 1443, 3389, 8080, 8081, 8443, 8905]


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
    scanned_subnet: str
    gateway: str | None
    dns_servers: list[str] = field(default_factory=list)
    domain_name: str | None = None
    dhcp_options: dict = field(default_factory=dict)
    nac_server_ip: str | None = None
    nac_server_type: str | None = None
    discovered_hosts: list[HostEntry] = field(default_factory=list)
    gateway_ports: list[int] = field(default_factory=list)
    duration_sec: float = 0.0
    address_family: str = "ipv4"
    interface_ipv6: list[str] = field(default_factory=list)
    ipv6_neighbors: list[HostEntry] = field(default_factory=list)


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


def _ndp_discover(iface: str, timeout: int = 2) -> list[tuple[str, str]]:
    """Discover IPv6 neighbors from NDP cache and an interface-bound all-nodes probe."""
    discovered: dict[str, str] = {}
    rc, output, _ = run_subprocess(["ip", "-6", "neigh", "show", "dev", iface])
    if rc == 0:
        for line in output.splitlines():
            fields = line.split()
            if not fields:
                continue
            try:
                address = str(ipaddress.IPv6Address(fields[0].split("%", 1)[0]))
                lladdr = fields.index("lladdr")
                mac = fields[lladdr + 1].lower()
            except (ValueError, IndexError):
                continue
            if "FAILED" not in fields and "INCOMPLETE" not in fields:
                discovered[address] = mac

    try:
        from scapy.all import Ether, IPv6, ICMPv6EchoRequest, srp
        answered, _ = srp(
            Ether(dst="33:33:00:00:00:01")
            / IPv6(dst="ff02::1")
            / ICMPv6EchoRequest(),
            iface=iface,
            timeout=timeout,
            multi=True,
            verbose=False,
        )
        for _, received in answered:
            if received.haslayer(IPv6):
                address = str(ipaddress.IPv6Address(received[IPv6].src))
                mac = str(getattr(received, "src", "")).lower()
                if mac:
                    discovered[address] = mac
    except Exception as exc:
        logger.debug(f"[post_auth] IPv6 neighbor discovery error: {exc}")
    return sorted(discovered.items())


def _bind_socket(sock: socket.socket, iface: str | None) -> None:
    if iface:
        sock.setsockopt(
            socket.SOL_SOCKET,
            getattr(socket, "SO_BINDTODEVICE", 25),
            iface.encode() + b"\0",
        )


def _tcp_connect(
    ip: str,
    port: int,
    timeout: float,
    iface: str | None = None,
) -> int | None:
    """Return port if open, keeping the probe on the authorized interface."""
    try:
        candidates = socket.getaddrinfo(ip, port, socket.AF_UNSPEC, socket.SOCK_STREAM)
    except socket.gaierror:
        return None
    for family, socktype, proto, _, sockaddr in candidates:
        sock = socket.socket(family, socktype, proto)
        sock.settimeout(timeout)
        try:
            _bind_socket(sock, iface)
            if family == socket.AF_INET6 and ipaddress.ip_address(ip.split("%", 1)[0]).is_link_local:
                if not iface:
                    continue
                sockaddr = (sockaddr[0], sockaddr[1], sockaddr[2], socket.if_nametoindex(iface))
            if sock.connect_ex(sockaddr) == 0:
                return port
        except (socket.timeout, OSError, ValueError):
            pass
        finally:
            sock.close()
    return None


def _tcp_port_scan(
    ip: str,
    ports: list[int],
    timeout: float = 0.5,
    iface: str | None = None,
) -> list[int]:
    """Scan TCP ports concurrently through one interface."""
    open_ports = []
    workers = max(1, min(20, len(ports)))
    with concurrent.futures.ThreadPoolExecutor(max_workers=workers) as executor:
        futures = {
            executor.submit(_tcp_connect, ip, port, timeout, iface): port
            for port in ports
        }
        for future in concurrent.futures.as_completed(futures):
            try:
                result = future.result()
                if result is not None:
                    open_ports.append(result)
            except Exception as exc:
                logger.debug(f"[post_auth] Port scan error: {exc}")
    return sorted(open_ports)


def _probe_gateway(
    gateway: str,
    ports: list[int],
    timeout: float,
    iface: str,
) -> tuple[list[int], str | None]:
    """Scan gateway ports and grab an HTTP server header."""
    open_ports = _tcp_port_scan(gateway, ports, timeout=timeout, iface=iface)
    server_banner = None

    if 80 in open_ports:
        host_header = f"[{gateway}]" if ":" in gateway else gateway
        try:
            for family, socktype, proto, _, sockaddr in socket.getaddrinfo(
                gateway, 80, socket.AF_UNSPEC, socket.SOCK_STREAM
            ):
                sock = socket.socket(family, socktype, proto)
                sock.settimeout(max(1.0, timeout))
                try:
                    _bind_socket(sock, iface)
                    if family == socket.AF_INET6 and ipaddress.ip_address(gateway).is_link_local:
                        sockaddr = (sockaddr[0], sockaddr[1], sockaddr[2], socket.if_nametoindex(iface))
                    sock.connect(sockaddr)
                    sock.sendall(
                        b"GET / HTTP/1.0\r\nHost: " + host_header.encode() + b"\r\n\r\n"
                    )
                    response = sock.recv(1024).decode("utf-8", errors="replace")
                    for line in response.splitlines():
                        if line.lower().startswith("server:"):
                            server_banner = line.split(":", 1)[1].strip()
                            break
                    break
                finally:
                    sock.close()
        except (socket.timeout, socket.gaierror, OSError, ValueError) as exc:
            logger.debug(f"[post_auth] Gateway HTTP probe error: {exc}")

    return open_ports, server_banner


def _detect_nac_server(
    gateway: str,
    dns_servers: list[str],
    timeout: float = 1.0,
    iface: str | None = None,
    signatures: list[dict] | None = None,
) -> tuple[str | None, str | None]:
    """Probe NAC-specific gateway ports through the authorized interface."""
    normalized = validated_signatures(signatures)
    http_cache: dict[tuple[str, bool], tuple[int, str, dict]] = {}
    port_cache: dict[int, bool] = {}
    for signature in normalized:
        for port in signature["tcp_ports"]:
            if port not in port_cache:
                port_cache[port] = _tcp_connect(gateway, port, timeout, iface) is not None
            if port_cache[port]:
                logger.info(
                    f"[post_auth] NAC server detected: {signature['name']} "
                    f"at {gateway}:{port}"
                )
                return gateway, signature["name"]
        for probe in signature["http_probes"]:
            if probe["port"] not in port_cache:
                port_cache[probe["port"]] = (
                    _tcp_connect(gateway, probe["port"], timeout, iface) is not None
                )
            if not port_cache[probe["port"]]:
                continue
            from core.posture import _http_get_text, _url_address
            url = (
                f"{probe['scheme']}://{_url_address(gateway)}:"
                f"{probe['port']}/"
            )
            cache_key = (url, probe["verify_tls"])
            if cache_key not in http_cache:
                http_cache[cache_key] = _http_get_text(
                    url,
                    max(1, int(timeout)),
                    iface=iface,
                    verify_tls=probe["verify_tls"],
                )
            status, body, headers = http_cache[cache_key]
            content = (body + " " + str(headers)).lower()
            if status and any(marker in content for marker in probe["markers"]):
                logger.info(
                    f"[post_auth] NAC HTTP fingerprint: {signature['name']} at {url}"
                )
                return gateway, signature["name"]

    # rDNS sometimes exposes names such as ise.corp or clearpass.corp.
    candidates = [gateway] + dns_servers
    nac_keywords = {
        marker: signature["name"]
        for signature in normalized
        for marker in signature["rdns_markers"]
    }
    nac_keywords.update({"nac": "Unknown NAC", "radius": "Unknown NAC"})
    for host in candidates:
        try:
            hostname = socket.getfqdn(host)
            hostname_lower = hostname.lower()
            for keyword, nac_type in nac_keywords.items():
                if keyword in hostname_lower and hostname_lower != host:
                    logger.info(
                        f"[post_auth] NAC server hint via rDNS: {host} → {hostname} ({nac_type})"
                    )
                    return host, nac_type
        except (socket.timeout, OSError):
            pass

    return None, None

def _parse_dhcp_leases(iface: str) -> dict:
    """Parse dhclient lease files for DHCP options."""
    lease_paths = get_cached_lease_paths(iface) + [
        f"/var/lib/dhcp/dhclient.{iface}.leases",
        "/var/lib/dhcp/dhclient.leases",
        "/var/lib/dhclient.leases",
    ]

    options: dict = {}
    for path in lease_paths:
        if os.path.exists(path):
            options.update(_parse_lease_file(path))
    return options


def _parse_lease_file(path: str) -> dict:
    """Parse the last lease block from a dhclient lease file."""
    options: dict = {}
    try:
        with open(path) as f:
            content = f.read()

        ipv4_blocks = content.split('lease {')
        ipv6_blocks = content.split('lease6 {')
        blocks = ipv6_blocks if len(ipv6_blocks) > 1 else ipv4_blocks
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
            elif line.startswith('option dhcp6.name-servers '):
                options['dhcp6.name-servers'] = line.split(None, 2)[2]
            elif line.startswith('option dhcp6.domain-search '):
                options['dhcp6.domain-search'] = line.split(None, 2)[2].strip('"')
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


def _get_gateway_from_routes(iface: str, family: int = 4) -> str | None:
    """Extract default gateway from ip route for the given interface."""
    command = ["ip", "-6", "route", "show", "dev", iface] if family == 6 else [
        "ip", "route", "show", "dev", iface
    ]
    rc, out, _ = run_subprocess(command)
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
    return None



def _bounded_scan_subnet(subnet: str, obtained_ip: str, max_hosts: int) -> str:
    """Limit broad enterprise prefixes to a deterministic subnet around our IP."""
    network = ipaddress.ip_network(subnet, strict=False)
    if network.version == 6:
        # IPv6 discovery uses NDP multicast and the neighbor cache; never try to
        # enumerate a /64 as a numeric address range.
        return str(network)
    max_hosts = max(4, int(max_hosts))
    if network.num_addresses <= max_hosts:
        return str(network)

    host_bits = max_hosts.bit_length() - 1
    bounded_prefix = max(network.prefixlen, 32 - host_bits)
    bounded = ipaddress.ip_network(f"{obtained_ip}/{bounded_prefix}", strict=False)
    logger.warning(
        f"[post_auth] Limiting ARP sweep from {network} to {bounded} "
        f"(max_hosts={max_hosts})"
    )
    return str(bounded)

def run_post_auth(
    iface: str,
    obtained_ip: str,
    arp_sweep: bool = True,
    port_scan: bool = True,
    arp_timeout: int = 2,
    port_scan_timeout: float = 0.5,
    ports: list[int] | None = None,
    max_hosts: int = 1024,
    nac_probe_timeout: float = 1.0,
    nac_signatures: list[dict] | None = None,
    verbose: bool = False,
) -> PostAuthResult:
    """Full post-bypass network enumeration."""
    start_time = time.time()
    scan_ports = list(ports) if ports is not None else PORT_SCAN_TARGETS

    address = ipaddress.ip_address(obtained_ip.split("%", 1)[0])
    address_family = "ipv6" if address.version == 6 else "ipv4"
    netmask = get_iface_netmask(iface, obtained_ip)
    subnet = ip_to_network(obtained_ip, netmask) if netmask else str(
        ipaddress.ip_network(f"{obtained_ip}/{'64' if address.version == 6 else '24'}", strict=False)
    )
    scanned_subnet = _bounded_scan_subnet(subnet, obtained_ip, max_hosts)
    gateway = _get_gateway_from_routes(iface, family=address.version)
    dhcp_opts = _parse_dhcp_leases(iface)
    dhcp_dns = dhcp_opts.get("domain-name-servers", "")
    if dhcp_opts.get("dhcp6.name-servers"):
        dhcp_dns = f"{dhcp_dns} {dhcp_opts['dhcp6.name-servers']}".strip()
    dns_servers = [part.strip() for part in dhcp_dns.replace(",", " ").split() if part.strip()]
    if not dns_servers:
        dns_servers = _read_resolv_conf()
    domain_name = dhcp_opts.get('domain-name') or dhcp_opts.get('dhcp6.domain-search')

    if verbose:
        logger.info(f"[post_auth] IP={obtained_ip}, subnet={subnet}, GW={gateway}, DNS={dns_servers}")

    result = PostAuthResult(
        obtained_ip=obtained_ip,
        subnet=subnet,
        scanned_subnet=scanned_subnet,
        gateway=gateway,
        dns_servers=dns_servers,
        domain_name=domain_name,
        dhcp_options=dhcp_opts,
        address_family=address_family,
        interface_ipv6=get_iface_ipv6s(iface),
    )

    discovered_hosts: list[HostEntry] = []

    if arp_sweep and address.version == 4:
        if verbose:
            logger.info(f"[post_auth] ARP sweeping {scanned_subnet} ...")
        arp_results = _arp_sweep(iface, scanned_subnet, timeout=arp_timeout)
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
                open_ports = _tcp_port_scan(ip, scan_ports, timeout=port_scan_timeout, iface=iface)

            discovered_hosts.append(HostEntry(
                ip=ip,
                mac=mac,
                vendor=vendor,
                open_ports=open_ports,
                hostname=hostname,
            ))

    ipv6_neighbors: list[HostEntry] = []
    if arp_sweep and get_iface_ipv6s(iface, include_link_local=True):
        if verbose:
            logger.info(f"[post_auth] Discovering IPv6 neighbors on {iface} ...")
        for ip, mac in _ndp_discover(iface, timeout=arp_timeout):
            if ip == obtained_ip:
                continue
            vendor, _ = lookup_oui(mac)
            hostname = None
            try:
                resolved = socket.getfqdn(ip)
                hostname = resolved if resolved != ip else None
            except (socket.timeout, OSError):
                pass
            open_ports = (
                _tcp_port_scan(ip, scan_ports, timeout=port_scan_timeout, iface=iface)
                if port_scan else []
            )
            entry = HostEntry(ip=ip, mac=mac, vendor=vendor, open_ports=open_ports, hostname=hostname)
            ipv6_neighbors.append(entry)
            if all(existing.ip != ip for existing in discovered_hosts):
                discovered_hosts.append(entry)

    result.discovered_hosts = discovered_hosts
    result.ipv6_neighbors = ipv6_neighbors

    if gateway:
        if port_scan:
            gw_ports, _ = _probe_gateway(
                gateway, scan_ports, timeout=port_scan_timeout, iface=iface
            )
            result.gateway_ports = gw_ports
        nac_ip, nac_type = _detect_nac_server(
            gateway, dns_servers, timeout=nac_probe_timeout, iface=iface,
            signatures=nac_signatures,
        )
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
    from core.utils import (
        require_root, setup_logging, get_iface_ip as _get_ip, get_iface_ipv6 as _get_ipv6,
    )
    require_root()
    setup_logging(verbose=True)
    if len(sys.argv) < 2:
        print("Usage: sudo python3 modules/post_auth.py <iface>")
        sys.exit(1)
    iface = sys.argv[1]
    ip = _get_ip(iface) or _get_ipv6(iface)
    if not ip:
        print(f"No IP on {iface}")
        sys.exit(1)
    result = run_post_auth(iface, ip, verbose=True)
    rprint(result)
