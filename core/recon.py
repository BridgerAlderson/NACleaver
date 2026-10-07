import logging
import secrets
import socket
import ssl
import struct
import threading
import time
from dataclasses import dataclass, field
from enum import Enum, auto
from typing import Any
from urllib.parse import urlsplit

from core.utils import (
    get_iface_gateway6,
    get_iface_ip,
    get_iface_ipv6s,
    get_iface_mac,
)

logger = logging.getLogger("nacleaver")

EAP_TYPE_NAMES = {
    1: "Identity",
    4: "MD5-Challenge",
    13: "EAP-TLS",
    18: "EAP-SIM",
    21: "EAP-TTLS",
    23: "EAP-AKA",
    25: "PEAP",
    43: "EAP-FAST",
    50: "EAP-AKA'",
    52: "EAP-PWD",
    55: "EAP-TEAP",
}


class NacType(Enum):
    DOT1X = auto()
    DOT1X_STRICT = auto()  # retained for result compatibility
    OPEN = auto()
    DHCP_ONLY = auto()
    MAB_OR_OPEN = auto()  # legacy/ambiguous result from older releases
    QUARANTINE_VLAN = auto()
    CAPTIVE_PORTAL = auto()
    UNKNOWN = auto()


@dataclass
class ReconResult:
    nac_type: NacType
    eap_methods_observed: list[int] = field(default_factory=list)
    dhcp_lease: str | None = None
    dhcp_offer: str | None = None
    interface_ip: str | None = None
    dhcp_subnet: str | None = None
    dhcp_gateway: str | None = None
    dhcp_options: dict = field(default_factory=dict)
    switch_vendor: str | None = None
    switch_port: str | None = None
    captive_portal_url: str | None = None
    connectivity_verified: bool = False
    http_status: int | None = None
    probe_error: str | None = None
    duration_sec: float = 0.0
    raw_eapol_count: int = 0
    interface_ipv6: list[str] = field(default_factory=list)
    ipv6_gateway: str | None = None
    ipv6_ra_observed: bool = False
    dhcpv6_advertise: bool = False
    ipv6_prefixes: list[str] = field(default_factory=list)
    ipv6_dns_servers: list[str] = field(default_factory=list)


@dataclass
class AccessVerification:
    """Interface-bound evidence collected after an authorization attempt."""
    state: NacType
    interface_ip: str | None
    connectivity_verified: bool
    captive_portal_url: str | None = None
    http_status: int | None = None
    error: str | None = None
    policy: str = "default"
    probes: list[dict] = field(default_factory=list)
    interface_ipv6: list[str] = field(default_factory=list)


def _bind_socket_to_interface(sock: socket.socket, iface: str) -> None:
    bind_opt = getattr(socket, "SO_BINDTODEVICE", 25)
    sock.setsockopt(socket.SOL_SOCKET, bind_opt, iface.encode() + b"\0")


def _connect_bound_socket(
    iface: str,
    host: str,
    port: int,
    timeout: float,
) -> socket.socket:
    errors: list[str] = []
    for family, socktype, proto, _, sockaddr in socket.getaddrinfo(
        host, port, socket.AF_UNSPEC, socket.SOCK_STREAM
    ):
        if family not in {socket.AF_INET, socket.AF_INET6}:
            continue
        sock = socket.socket(family, socktype, proto)
        sock.settimeout(timeout)
        try:
            _bind_socket_to_interface(sock, iface)
            if family == socket.AF_INET6 and sockaddr[0].lower().startswith("fe80:"):
                sockaddr = (sockaddr[0], sockaddr[1], sockaddr[2], socket.if_nametoindex(iface))
            sock.connect(sockaddr)
            return sock
        except OSError as exc:
            errors.append(str(exc))
            sock.close()
    raise OSError("; ".join(errors) or f"unable to resolve/connect to {host}:{port}")


def _verification_tcp_probe(
    iface: str,
    host: str,
    port: int,
    timeout: float,
) -> tuple[bool, str | None]:
    sock = None
    try:
        sock = _connect_bound_socket(iface, host, port, timeout)
        return True, None
    except OSError as exc:
        return False, str(exc)
    finally:
        if sock is not None:
            sock.close()


def _http_target_probe(
    iface: str,
    target: dict[str, Any],
    timeout: float,
) -> dict:
    url = target.get("url")
    if not isinstance(url, str):
        raise ValueError("HTTP verification target requires a url")
    parsed = urlsplit(url)
    if parsed.scheme not in {"http", "https"} or not parsed.hostname:
        raise ValueError("verification url must use http or https")
    port = parsed.port or (443 if parsed.scheme == "https" else 80)
    path = parsed.path or "/"
    if parsed.query:
        path += "?" + parsed.query

    raw_sock = _connect_bound_socket(iface, parsed.hostname, port, timeout)
    stream: socket.socket = raw_sock
    try:
        if parsed.scheme == "https":
            verify_tls = target.get("verify_tls", True)
            if not isinstance(verify_tls, bool):
                raise ValueError("verify_tls must be boolean")
            context = ssl.create_default_context()
            if not verify_tls:
                context.check_hostname = False
                context.verify_mode = ssl.CERT_NONE
            stream = context.wrap_socket(raw_sock, server_hostname=parsed.hostname)

        host_header = (
            f"[{parsed.hostname}]" if ":" in parsed.hostname else parsed.hostname
        )
        if parsed.port is not None:
            host_header += f":{parsed.port}"
        stream.sendall(
            (
                f"GET {path} HTTP/1.1\r\n"
                f"Host: {host_header}\r\n"
                "User-Agent: NACleaver-Verification/1\r\n"
                "Connection: close\r\n\r\n"
            ).encode("ascii", errors="strict")
        )
        chunks: list[bytes] = []
        total = 0
        while total < 65536:
            chunk = stream.recv(min(8192, 65536 - total))
            if not chunk:
                break
            chunks.append(chunk)
            total += len(chunk)
        response = b"".join(chunks).decode("iso-8859-1", errors="replace")
        head, separator, body = response.partition("\r\n\r\n")
        first_line = head.splitlines()[0] if head else ""
        parts = first_line.split()
        if len(parts) < 2 or not parts[1].isdigit():
            raise OSError("malformed HTTP response")
        status = int(parts[1])
        expected = target.get("expected_status", list(range(200, 300)))
        expected_values = expected if isinstance(expected, list) else [expected]
        if any(isinstance(value, bool) for value in expected_values):
            raise ValueError("expected_status cannot contain booleans")
        expected_statuses = {int(value) for value in expected_values}
        if not expected_statuses or any(value < 100 or value > 599 for value in expected_statuses):
            raise ValueError("expected_status must contain HTTP status codes")
        body_contains = target.get("body_contains")
        needles = (
            body_contains if isinstance(body_contains, list) else [body_contains]
        ) if body_contains is not None else []
        if body_contains is not None and (
            not needles or any(not isinstance(needle, str) for needle in needles)
        ):
            raise ValueError("body_contains must be a string or non-empty string list")
        matched = status in expected_statuses and all(needle in body for needle in needles)
        location = None
        for line in head.splitlines()[1:]:
            if line.lower().startswith("location:"):
                location = line.split(":", 1)[1].strip()
                break
        return {
            "success": matched,
            "status": status,
            "redirect_url": location,
            "details": "response matched" if matched else "response did not match expectations",
        }
    finally:
        try:
            stream.close()
        except OSError:
            raw_sock.close()


def _run_verification_target(
    iface: str,
    target: Any,
    timeout: float,
    index: int,
) -> dict:
    if not isinstance(target, dict):
        return {
            "name": f"target-{index}",
            "type": "invalid",
            "success": False,
            "error": "verification targets must be mappings",
        }
    name = str(target.get("name") or f"target-{index}")
    target_type = str(target.get("type", "http")).lower()
    result: dict[str, Any] = {
        "name": name,
        "type": target_type,
        "success": False,
    }
    try:
        if target_type == "http":
            url = target.get("url")
            parsed = urlsplit(url) if isinstance(url, str) else None
            result["target"] = (
                f"{parsed.scheme}://{parsed.netloc}{parsed.path or '/'}"
                if parsed and parsed.scheme and parsed.netloc else str(url)
            )
            result.update(_http_target_probe(iface, target, timeout))
        elif target_type == "tcp":
            host = target.get("host")
            port = target.get("port")
            if not isinstance(host, str) or not host:
                raise ValueError("TCP verification target requires host")
            if isinstance(port, bool):
                raise ValueError("TCP verification port is invalid")
            port = int(port)
            if port < 1 or port > 65535:
                raise ValueError("TCP verification port must be 1-65535")
            result["target"] = f"{host}:{port}"
            success, error = _verification_tcp_probe(iface, host, port, timeout)
            result["success"] = success
            result["error"] = error
        else:
            raise ValueError("verification target type must be http or tcp")
    except (OSError, ValueError, UnicodeError, ssl.SSLError) as exc:
        result["error"] = str(exc)
    return result


def _is_dhcp_offer_value(value) -> bool:
    if isinstance(value, bytes):
        value = int.from_bytes(value, "big")
    if isinstance(value, str):
        return value.strip().lower() in {"2", "offer"}
    return value == 2


def _parse_cdp_tlvs(raw_bytes: bytes) -> tuple[str | None, str | None]:
    """Extract device-ID and port-ID from raw CDP payload."""
    vendor = None
    port = None
    try:
        i = 4  # skip CDP version (1) + ttl (1) + checksum (2)
        while i + 4 <= len(raw_bytes):
            tlv_type = struct.unpack('!H', raw_bytes[i:i+2])[0]
            tlv_len = struct.unpack('!H', raw_bytes[i+2:i+4])[0]
            if tlv_len < 4:
                break
            value = raw_bytes[i+4:i+tlv_len]
            if tlv_type == 1:  # Device-ID
                vendor = value.decode('utf-8', errors='replace').strip('\x00')
            elif tlv_type == 3:  # Port-ID
                port = value.decode('utf-8', errors='replace').strip('\x00')
            i += tlv_len
    except (struct.error, ValueError):
        pass
    return vendor, port


def _parse_lldp_tlvs(raw_bytes: bytes) -> tuple[str | None, str | None]:
    """Extract system name and port ID from raw LLDP PDU."""
    sys_name = None
    port_id = None
    try:
        i = 0
        while i + 2 <= len(raw_bytes):
            header = struct.unpack('!H', raw_bytes[i:i+2])[0]
            tlv_type = (header >> 9) & 0x7F
            tlv_len = header & 0x1FF
            if tlv_type == 0:  # End of LLDPDU
                break
            value = raw_bytes[i+2:i+2+tlv_len]
            if tlv_type == 2:  # Port ID
                if len(value) > 1:
                    port_id = value[1:].decode('utf-8', errors='replace').strip('\x00')
            elif tlv_type == 5:  # System Name
                sys_name = value.decode('utf-8', errors='replace').strip('\x00')
            i += 2 + tlv_len
    except (struct.error, ValueError):
        pass
    return sys_name, port_id


def _dhcp_probe(iface: str, dhcp_timeout: int) -> tuple[bool, dict]:
    """Send DHCP Discover, wait for Offer. Returns (success, options_dict)."""
    from scapy.all import AsyncSniffer, Ether, IP, UDP, BOOTP, DHCP, sendp, conf

    mac = get_iface_mac(iface)
    mac_bytes = bytes.fromhex(mac.replace(':', ''))
    xid = secrets.randbelow(0xFFFFFFFF) + 1

    original_checkIPaddr = conf.checkIPaddr
    conf.checkIPaddr = False

    offer_list: list = []

    def _capture_offer(pkt):
        try:
            if not pkt.haslayer(BOOTP) or pkt[BOOTP].xid != xid:
                return
            if bytes(pkt[BOOTP].chaddr)[:len(mac_bytes)] != mac_bytes:
                return
            if not pkt.haslayer(DHCP):
                return
            message_type = None
            for option in pkt[DHCP].options:
                if isinstance(option, tuple) and option[0] == "message-type":
                    message_type = option[1]
                    break
            if _is_dhcp_offer_value(message_type):
                offer_list.append(pkt)
        except Exception as exc:
            logger.debug(f"DHCP offer parse error: {exc}")

    sniffer = AsyncSniffer(
        iface=iface,
        filter="udp and src port 67",
        prn=_capture_offer,
        store=False,
    )
    sniffer_started = False
    # These are DHCP wire-protocol addresses, not local server bind targets.
    dhcp_unspecified_source = socket.inet_ntoa(bytes(4))
    dhcp_limited_broadcast = socket.inet_ntoa(bytes([0xFF]) * 4)

    discover = (
        Ether(dst="ff:ff:ff:ff:ff:ff", src=mac) /
        IP(src=dhcp_unspecified_source, dst=dhcp_limited_broadcast) /
        UDP(sport=68, dport=67) /
        BOOTP(chaddr=mac_bytes, xid=xid, flags=0x8000) /
        DHCP(options=[
            ("message-type", "discover"),
            ("hostname", "nacleaver"),
            ("param_req_list", [1, 3, 6, 15, 28]),
            "end"
        ])
    )

    try:
        sniffer.start()
        sniffer_started = True
        time.sleep(0.2)
        sendp(discover, iface=iface, verbose=False)
        deadline = time.monotonic() + dhcp_timeout
        while time.monotonic() < deadline and not offer_list:
            time.sleep(0.2)
    except Exception as e:
        logger.debug(f"DHCP probe error: {e}")
    finally:
        if sniffer_started:
            try:
                sniffer.stop()
            except Exception as exc:
                logger.debug(f"DHCP sniffer stop error: {exc}")
        conf.checkIPaddr = original_checkIPaddr

    if not offer_list:
        return False, {}

    offer = offer_list[0]
    options: dict = {}

    if offer.haslayer(BOOTP):
        options['_yiaddr'] = offer[BOOTP].yiaddr

    if offer.haslayer(DHCP):
        for opt in offer[DHCP].options:
            if isinstance(opt, tuple) and len(opt) >= 2:
                key, val = opt[0], opt[1]
                if key == 'subnet_mask':
                    options['subnet_mask'] = str(val)
                elif key == 'router':
                    options['router'] = str(val) if not isinstance(val, list) else str(val[0])
                elif key == 'name_server':
                    options['name_server'] = str(val) if not isinstance(val, list) else str(val[0])
                elif key == 'domain':
                    options['domain'] = str(val)
                else:
                    try:
                        options[str(key)] = str(val)
                    except Exception as exc:
                        logger.debug(f"DHCP option parse error: {exc}")

    return True, options


def _ipv6_control_probe(iface: str, timeout: int) -> dict[str, Any]:
    """Actively solicit IPv6 RA/DHCPv6 evidence without assigning an address."""
    from scapy.all import (
        AsyncSniffer,
        DHCP6_Advertise,
        DHCP6_Solicit,
        DHCP6OptClientId,
        DHCP6OptDNSServers,
        DHCP6OptIA_NA,
        DHCP6OptOptReq,
        DUID_LL,
        Ether,
        ICMPv6NDOptPrefixInfo,
        ICMPv6NDOptRDNSS,
        ICMPv6ND_RA,
        ICMPv6ND_RS,
        IPv6,
        UDP,
        sendp,
    )

    observation: dict[str, Any] = {
        "ra_observed": False,
        "dhcpv6_advertise": False,
        "gateway": None,
        "prefixes": [],
        "dns_servers": [],
    }
    transaction_id = secrets.randbelow(0xFFFFFF) + 1

    def capture(packet) -> None:
        try:
            if packet.haslayer(ICMPv6ND_RA):
                observation["ra_observed"] = True
                observation["gateway"] = packet[IPv6].src
                index = 1
                while True:
                    prefix = packet.getlayer(ICMPv6NDOptPrefixInfo, nb=index)
                    if prefix is None:
                        break
                    value = f"{prefix.prefix}/{int(prefix.prefixlen)}"
                    if value not in observation["prefixes"]:
                        observation["prefixes"].append(value)
                    index += 1
                index = 1
                while True:
                    rdnss = packet.getlayer(ICMPv6NDOptRDNSS, nb=index)
                    if rdnss is None:
                        break
                    for address in getattr(rdnss, "dns", []) or []:
                        value = str(address)
                        if value not in observation["dns_servers"]:
                            observation["dns_servers"].append(value)
                    index += 1
            if packet.haslayer(DHCP6_Advertise):
                advertise = packet[DHCP6_Advertise]
                if int(getattr(advertise, "trid", -1)) != transaction_id:
                    return
                observation["dhcpv6_advertise"] = True
                dns_option = packet.getlayer(DHCP6OptDNSServers)
                if dns_option is not None:
                    for address in getattr(dns_option, "dnsservers", []) or []:
                        value = str(address)
                        if value not in observation["dns_servers"]:
                            observation["dns_servers"].append(value)
        except (AttributeError, TypeError, ValueError):
            return

    sniffer = AsyncSniffer(
        iface=iface,
        filter="icmp6 or (udp and (port 546 or port 547))",
        prn=capture,
        store=False,
    )
    started = False
    try:
        sniffer.start()
        started = True
        time.sleep(0.2)
        mac = get_iface_mac(iface)
        iaid = int(mac.replace(":", "")[-8:], 16)
        sendp(
            Ether(src=mac, dst="33:33:00:00:00:02") /
            IPv6(src="::", dst="ff02::2") /
            ICMPv6ND_RS(),
            iface=iface,
            verbose=False,
        )
        link_locals = [
            value for value in get_iface_ipv6s(iface, include_link_local=True)
            if value.lower().startswith("fe80:")
        ]
        source = link_locals[0] if link_locals else "::"
        sendp(
            Ether(src=mac, dst="33:33:00:01:00:02") /
            IPv6(src=source, dst="ff02::1:2") /
            UDP(sport=546, dport=547) /
            DHCP6_Solicit(trid=transaction_id) /
            DHCP6OptClientId(duid=DUID_LL(lladdr=mac)) /
            DHCP6OptIA_NA(iaid=iaid) /
            DHCP6OptOptReq(reqopts=[23, 24]),
            iface=iface,
            verbose=False,
        )
        deadline = time.monotonic() + max(1, timeout)
        while time.monotonic() < deadline:
            if observation["ra_observed"] and observation["dhcpv6_advertise"]:
                break
            time.sleep(0.2)
    except Exception as exc:
        observation["error"] = str(exc)
    finally:
        if started:
            try:
                sniffer.stop()
            except Exception as exc:
                logger.debug(f"IPv6 control sniffer stop error: {exc}")
    return observation


def _http_probe_bound(iface: str, timeout: int = 5) -> tuple[int | None, str | None, str | None]:
    """Issue an HTTP probe on a socket bound to exactly one Linux interface."""
    endpoints: list[str] = []
    if get_iface_ip(iface):
        endpoints.append("1.1.1.1")
    if get_iface_ipv6s(iface):
        endpoints.append("2606:4700:4700::1111")
    if not endpoints:
        return None, None, "Interface has no usable IPv4 or IPv6 address"
    sock = None
    try:
        last_error = None
        selected_endpoint = None
        for endpoint in endpoints:
            try:
                sock = _connect_bound_socket(iface, endpoint, 80, timeout)
                selected_endpoint = endpoint
                break
            except OSError as exc:
                last_error = str(exc)
        if sock is None:
            return None, None, last_error or "connectivity endpoint unavailable"
        host_header = (
            f"[{selected_endpoint}]" if selected_endpoint and ":" in selected_endpoint
            else selected_endpoint or "1.1.1.1"
        )
        sock.sendall(
            (
                "GET /cdn-cgi/trace HTTP/1.1\r\n"
                f"Host: {host_header}\r\n"
                "Connection: close\r\n\r\n"
            ).encode("ascii")
        )
        chunks = []
        total = 0
        while total < 65536:
            chunk = sock.recv(min(8192, 65536 - total))
            if not chunk:
                break
            chunks.append(chunk)
            total += len(chunk)
        response = b"".join(chunks).decode("iso-8859-1", errors="replace")
        first_line = response.splitlines()[0] if response else ""
        parts = first_line.split()
        if len(parts) < 2 or not parts[1].isdigit():
            return None, None, "Malformed HTTP response"
        status = int(parts[1])
        location = None
        for line in response.splitlines()[1:]:
            if line.lower().startswith("location:"):
                location = line.split(":", 1)[1].strip()
                break
        if status == 200:
            _, _, body = response.partition("\r\n\r\n")
            trace_fields = {
                line.split("=", 1)[0].strip().lower()
                for line in body.splitlines()
                if "=" in line
            }
            if not {"ip", "colo"}.issubset(trace_fields):
                return status, location, "Unexpected content from connectivity endpoint"
        return status, location, None
    except OSError as exc:
        return None, None, str(exc)
    finally:
        if sock is not None:
            sock.close()


def _check_captive_portal(
    iface: str,
    timeout: int = 5,
) -> tuple[NacType, str | None, int | None, str | None]:
    """Classify connectivity using traffic forced through *iface*."""
    if not get_iface_ip(iface) and not get_iface_ipv6s(iface):
        return NacType.DHCP_ONLY, None, None, "Interface has no assigned IPv4 or IPv6 address"

    status, redirect_url, error = _http_probe_bound(iface, timeout)
    if status in (301, 302, 303, 307, 308, 511):
        return NacType.CAPTIVE_PORTAL, redirect_url, status, None
    if status is not None and 200 <= status < 300 and error is None:
        return NacType.OPEN, None, status, None
    if status is not None and 200 <= status < 300:
        return NacType.UNKNOWN, redirect_url, status, error
    if status is None:
        return NacType.QUARANTINE_VLAN, None, None, error
    return NacType.UNKNOWN, None, status, f"Unexpected HTTP status {status}"


def verify_interface_access(
    iface: str,
    timeout: int = 5,
    targets: list[dict] | None = None,
    policy: str = "any",
) -> AccessVerification:
    """Verify access through exactly *iface* without treating DHCP as proof.

    When engagement-specific targets are provided, the result is based on those
    HTTP/TCP checks instead of assuming that public Internet access is expected.
    """
    interface_ipv6 = get_iface_ipv6s(iface)
    interface_ip = get_iface_ip(iface) or (interface_ipv6[0] if interface_ipv6 else None)
    if targets:
        if policy not in {"any", "all"}:
            raise ValueError("verification policy must be 'any' or 'all'")
        if not interface_ip:
            return AccessVerification(
                state=NacType.DHCP_ONLY,
                interface_ip=None,
                connectivity_verified=False,
                error="Interface has no assigned IPv4 or IPv6 address",
                policy=policy,
                interface_ipv6=interface_ipv6,
            )
        probes = [
            _run_verification_target(iface, target, timeout, index)
            for index, target in enumerate(targets, start=1)
        ]
        successes = [bool(probe.get("success")) for probe in probes]
        verified = all(successes) if policy == "all" else any(successes)
        redirect = next(
            (probe.get("redirect_url") for probe in probes if probe.get("redirect_url")),
            None,
        )
        http_status = next(
            (probe.get("status") for probe in probes if probe.get("status") is not None),
            None,
        )
        errors = [str(probe["error"]) for probe in probes if probe.get("error")]
        if verified:
            state = NacType.OPEN
            error = None
        elif redirect:
            state = NacType.CAPTIVE_PORTAL
            error = "; ".join(errors) or "verification targets did not satisfy policy"
        else:
            state = NacType.QUARANTINE_VLAN
            error = "; ".join(errors) or "verification targets did not satisfy policy"
        return AccessVerification(
            state=state,
            interface_ip=interface_ip,
            connectivity_verified=verified,
            captive_portal_url=redirect,
            http_status=http_status,
            error=error,
            policy=policy,
            probes=probes,
            interface_ipv6=interface_ipv6,
        )

    state, portal_url, http_status, error = _check_captive_portal(
        iface, timeout=timeout
    )
    return AccessVerification(
        state=state,
        interface_ip=interface_ip,
        connectivity_verified=state == NacType.OPEN,
        captive_portal_url=portal_url,
        http_status=http_status,
        error=error,
        policy="default",
        interface_ipv6=interface_ipv6,
    )


def run_recon(
    iface: str,
    timeout: int = 30,
    dhcp_timeout: int = 10,
    http_timeout: int = 5,
    verbose: bool = False,
    verification_targets: list[dict] | None = None,
    verification_policy: str = "any",
) -> ReconResult:
    """Full NAC detection: EAPOL sniff + DHCP probe + captive portal check + CDP/LLDP."""
    from scapy.all import AsyncSniffer, Ether, EAPOL, conf, sendp

    start_time = time.time()
    result = ReconResult(nac_type=NacType.UNKNOWN)
    own_mac = get_iface_mac(iface)
    result.interface_ip = get_iface_ip(iface)
    result.interface_ipv6 = get_iface_ipv6s(iface)
    result.ipv6_gateway = get_iface_gateway6(iface)
    result.dhcp_lease = result.interface_ip
    eap_types_seen: set[int] = set()
    eapol_count = 0
    switch_vendor = None
    switch_port = None

    original_promisc = conf.sniff_promisc
    conf.sniff_promisc = True

    eapol_pkts: list = []
    inbound_eapol = threading.Event()

    def note_inbound_eapol(pkt) -> None:
        if getattr(pkt, "src", "").lower() != own_mac.lower():
            inbound_eapol.set()

    # Run both sniffers together. An authenticator response lets recon stop
    # early instead of always paying the full configured timeout.
    eapol_sniffer = AsyncSniffer(
        iface=iface,
        filter="ether proto 0x888e",
        store=True,
        timeout=timeout,
        prn=note_inbound_eapol,
    )
    cdp_sniffer = AsyncSniffer(
        iface=iface,
        filter="ether host 01:00:0c:cc:cc:cc or ether proto 0x88cc",
        store=True,
        timeout=timeout,
    )

    try:
        eapol_sniffer.start()
        cdp_sniffer.start()
        time.sleep(0.2)
        # An active EAPOL-Start avoids missing quiet authenticators. Our own frame
        # is excluded from the receive count below.
        try:
            sendp(
                Ether(src=own_mac, dst="01:80:c2:00:00:03") /
                EAPOL(version=1, type=1, len=0),
                iface=iface,
                verbose=False,
            )
        except Exception as exc:
            logger.debug(f"EAPOL-Start probe failed: {exc}")

        if verbose:
            logger.info(f"[recon] Sniffing EAPOL/CDP/LLDP on {iface} for {timeout}s ...")

        deadline = time.monotonic() + timeout
        while time.monotonic() < deadline:
            if inbound_eapol.wait(timeout=0.2):
                # Brief grace period captures the following EAP Request type.
                time.sleep(min(1.0, max(0.0, deadline - time.monotonic())))
                break
    finally:
        for sniffer in (eapol_sniffer, cdp_sniffer):
            try:
                if getattr(sniffer, "running", False):
                    sniffer.stop()
            except Exception as exc:
                logger.debug(f"Recon sniffer stop error: {exc}")
        conf.sniff_promisc = original_promisc

    eapol_pkts = eapol_sniffer.results or []
    disc_pkts = cdp_sniffer.results or []

    # pull EAP type codes out of request frames
    for pkt in eapol_pkts:
        try:
            if getattr(pkt, "src", "").lower() == own_mac.lower():
                continue
            eapol_count += 1
            from scapy.all import EAP
            if pkt.haslayer(EAP):
                eap_code = pkt[EAP].code
                if eap_code == 1:  # Request — has type field
                    eap_type = getattr(pkt[EAP], 'type', None)
                    if eap_type is not None:
                        eap_types_seen.add(int(eap_type))
        except Exception as e:
            logger.debug(f"EAP parse error: {e}")

    # extract switch hostname and port from discovery frames
    for pkt in disc_pkts:
        try:
            raw = bytes(pkt)
            if pkt.dst == '01:00:0c:cc:cc:cc':  # CDP
                vendor, port = _parse_cdp_tlvs(raw[22:])
                if vendor:
                    switch_vendor = vendor
                if port:
                    switch_port = port
            elif pkt.type == 0x88CC:  # LLDP
                vendor, port = _parse_lldp_tlvs(raw[14:])
                if vendor:
                    switch_vendor = vendor
                if port:
                    switch_port = port
        except Exception as e:
            logger.debug(f"CDP/LLDP parse error: {e}")

    result.eap_methods_observed = sorted(eap_types_seen)
    result.raw_eapol_count = eapol_count
    result.switch_vendor = switch_vendor
    result.switch_port = switch_port

    if eapol_count > 0:
        result.nac_type = NacType.DOT1X
        result.duration_sec = time.time() - start_time
        if verbose:
            logger.info(f"[recon] DOT1X detected: {eapol_count} EAPOL frames, EAP types: {result.eap_methods_observed}")
        return result

    # No EAPOL response: a DHCP OFFER is useful evidence, but it is not a lease.
    if verbose:
        logger.info(f"[recon] No inbound EAPOL observed. Trying DHCP probe on {iface} ...")

    dhcp_ok, dhcp_opts = _dhcp_probe(iface, dhcp_timeout=dhcp_timeout)
    if dhcp_ok:
        result.dhcp_offer = dhcp_opts.get("_yiaddr")
        result.dhcp_subnet = dhcp_opts.get("subnet_mask")
        result.dhcp_gateway = dhcp_opts.get("router")
        result.dhcp_options = {k: v for k, v in dhcp_opts.items() if not k.startswith("_")}
        if verbose:
            logger.info(f"[recon] DHCP offer received: IP={result.dhcp_offer}, GW={result.dhcp_gateway}")

    ipv6_evidence = _ipv6_control_probe(iface, timeout=dhcp_timeout)
    result.ipv6_ra_observed = bool(ipv6_evidence.get("ra_observed"))
    result.dhcpv6_advertise = bool(ipv6_evidence.get("dhcpv6_advertise"))
    result.ipv6_gateway = ipv6_evidence.get("gateway") or get_iface_gateway6(iface)
    result.ipv6_prefixes = list(ipv6_evidence.get("prefixes", []))
    result.ipv6_dns_servers = list(ipv6_evidence.get("dns_servers", []))

    result.interface_ip = get_iface_ip(iface)
    result.interface_ipv6 = get_iface_ipv6s(iface)
    result.dhcp_lease = result.interface_ip
    if result.interface_ip or result.interface_ipv6:
        if verification_targets:
            verification = verify_interface_access(
                iface,
                timeout=http_timeout,
                targets=verification_targets,
                policy=verification_policy,
            )
            result.nac_type = verification.state
            result.captive_portal_url = verification.captive_portal_url
            result.http_status = verification.http_status
            result.probe_error = verification.error
            result.connectivity_verified = verification.connectivity_verified
        else:
            nac_type, portal_url, http_status, probe_error = _check_captive_portal(
                iface, timeout=http_timeout
            )
            result.nac_type = nac_type
            result.captive_portal_url = portal_url
            result.http_status = http_status
            result.probe_error = probe_error
            result.connectivity_verified = nac_type == NacType.OPEN
    elif dhcp_ok or result.ipv6_ra_observed or result.dhcpv6_advertise:
        result.nac_type = NacType.DHCP_ONLY
        result.probe_error = "Addressing control traffic observed, but no usable address is assigned"
    else:
        result.nac_type = NacType.UNKNOWN
        result.probe_error = "No EAPOL, IPv4/IPv6 addressing evidence, or assigned usable address"

    result.duration_sec = time.time() - start_time
    if verbose:
        logger.info(
            f"[recon] NAC type: {result.nac_type.name}, "
            f"HTTP={result.http_status}, error={result.probe_error}"
        )
    return result


if __name__ == "__main__":
    import sys
    from rich import print as rprint
    from core.utils import require_root, setup_logging
    require_root()
    setup_logging(verbose=True)
    iface = sys.argv[1] if len(sys.argv) > 1 else "eth0"
    result = run_recon(iface, timeout=15, verbose=True)
    rprint(result)
