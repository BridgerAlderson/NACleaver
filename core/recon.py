import logging
import random
import socket
import struct
import time
from dataclasses import dataclass, field
from enum import Enum, auto

import requests
import urllib3

from core.utils import get_iface_mac, get_iface_ip

logger = logging.getLogger('nacleaver')
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

EAP_TYPE_NAMES = {
    1: "Identity",
    4: "MD5-Challenge",
    13: "EAP-TLS",
    21: "EAP-TTLS",
    25: "PEAP",
    43: "EAP-FAST",
    52: "EAP-PWD",
}


class NacType(Enum):
    DOT1X = auto()
    DOT1X_STRICT = auto()
    MAB_OR_OPEN = auto()
    QUARANTINE_VLAN = auto()
    CAPTIVE_PORTAL = auto()
    UNKNOWN = auto()


@dataclass
class ReconResult:
    nac_type: NacType
    eap_methods_observed: list[int] = field(default_factory=list)
    dhcp_lease: str | None = None
    dhcp_subnet: str | None = None
    dhcp_gateway: str | None = None
    dhcp_options: dict = field(default_factory=dict)
    switch_vendor: str | None = None
    switch_port: str | None = None
    captive_portal_url: str | None = None
    duration_sec: float = 0.0
    raw_eapol_count: int = 0


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
    xid = random.randint(1, 0xFFFFFFFF)

    original_checkIPaddr = conf.checkIPaddr
    conf.checkIPaddr = False

    offer_list: list = []

    def _capture_offer(pkt):
        try:
            if pkt.haslayer(BOOTP) and pkt[BOOTP].xid == xid:
                offer_list.append(pkt)
        except Exception:
            pass

    sniffer = AsyncSniffer(
        iface=iface,
        filter="udp and src port 67",
        prn=_capture_offer,
        store=False,
    )
    sniffer.start()
    time.sleep(0.2)

    discover = (
        Ether(dst="ff:ff:ff:ff:ff:ff", src=mac) /
        IP(src="0.0.0.0", dst="255.255.255.255") /
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
        sendp(discover, iface=iface, verbose=False)
        deadline = time.time() + dhcp_timeout
        while time.time() < deadline and not offer_list:
            time.sleep(0.2)
    except Exception as e:
        logger.debug(f"DHCP probe send error: {e}")
    finally:
        sniffer.stop()
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
                    except Exception:
                        pass

    return True, options


def _check_captive_portal(iface: str, timeout: int = 5) -> tuple[NacType, str | None]:
    """Return (nac_type, redirect_url) based on HTTP probe."""
    probe_url = "http://1.1.1.1"
    src_ip = get_iface_ip(iface)

    session = requests.Session()
    if src_ip:
        adapter = _BindAdapter(src_ip)
        session.mount("http://", adapter)
        session.mount("https://", adapter)

    try:
        resp = session.get(probe_url, timeout=timeout, allow_redirects=False)
        if resp.status_code in (301, 302, 303, 307, 308):
            redirect_url = resp.headers.get('Location')
            return NacType.CAPTIVE_PORTAL, redirect_url
        if resp.status_code == 200:
            return NacType.MAB_OR_OPEN, None
        return NacType.MAB_OR_OPEN, None
    except requests.exceptions.ConnectionError:
        return NacType.QUARANTINE_VLAN, None
    except requests.exceptions.Timeout:
        return NacType.QUARANTINE_VLAN, None
    except Exception as e:
        logger.debug(f"Captive portal probe error: {e}")
        return NacType.MAB_OR_OPEN, None


class _BindAdapter(requests.adapters.HTTPAdapter):
    def __init__(self, source_ip: str, **kwargs):
        self._source_ip = source_ip
        super().__init__(**kwargs)

    def send(self, request, **kwargs):
        kwargs['source_address'] = (self._source_ip, 0)
        return super().send(request, **kwargs)


def run_recon(iface: str, timeout: int = 30, verbose: bool = False) -> ReconResult:
    """Full NAC detection: EAPOL sniff + DHCP probe + captive portal check + CDP/LLDP."""
    from scapy.all import AsyncSniffer, conf

    start_time = time.time()
    result = ReconResult(nac_type=NacType.UNKNOWN)
    eap_types_seen: set[int] = set()
    eapol_count = 0
    switch_vendor = None
    switch_port = None

    original_promisc = conf.sniff_promisc
    conf.sniff_promisc = True

    eapol_pkts: list = []
    cdp_pkts: list = []
    lldp_pkts: list = []

    # run both sniffers together so they share the same timeout window
    eapol_sniffer = AsyncSniffer(
        iface=iface,
        filter="ether proto 0x888e",
        store=True,
        timeout=timeout,
    )
    cdp_sniffer = AsyncSniffer(
        iface=iface,
        filter="ether host 01:00:0c:cc:cc:cc or ether proto 0x88cc",
        store=True,
        timeout=timeout,
    )

    eapol_sniffer.start()
    cdp_sniffer.start()

    if verbose:
        logger.info(f"[recon] Sniffing EAPOL/CDP/LLDP on {iface} for {timeout}s ...")

    eapol_sniffer.join()
    cdp_sniffer.join()

    conf.sniff_promisc = original_promisc

    eapol_pkts = eapol_sniffer.results or []
    disc_pkts = cdp_sniffer.results or []

    # pull EAP type codes out of request frames
    for pkt in eapol_pkts:
        eapol_count += 1
        try:
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

    # no EAPOL — check if the port is open at all
    if verbose:
        logger.info(f"[recon] No EAPOL observed. Trying DHCP probe on {iface} ...")

    dhcp_ok, dhcp_opts = _dhcp_probe(iface, dhcp_timeout=10)

    if not dhcp_ok:
        result.nac_type = NacType.DOT1X_STRICT
        result.duration_sec = time.time() - start_time
        if verbose:
            logger.info("[recon] No DHCP offer received — port fully blocked (DOT1X_STRICT)")
        return result

    offered_ip = dhcp_opts.get('_yiaddr')
    result.dhcp_lease = offered_ip
    result.dhcp_subnet = dhcp_opts.get('subnet_mask')
    result.dhcp_gateway = dhcp_opts.get('router')
    result.dhcp_options = {k: v for k, v in dhcp_opts.items() if not k.startswith('_')}

    if verbose:
        logger.info(f"[recon] DHCP offer received: IP={offered_ip}, GW={result.dhcp_gateway}")

    # got a lease; check whether routing actually works
    nac_type, portal_url = _check_captive_portal(iface, timeout=5)
    result.nac_type = nac_type
    result.captive_portal_url = portal_url

    result.duration_sec = time.time() - start_time

    if verbose:
        logger.info(f"[recon] NAC type: {result.nac_type.name}, captive portal: {portal_url}")

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
