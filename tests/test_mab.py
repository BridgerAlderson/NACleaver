from core import mab
from data.oui_seed import AMBIGUOUS_OUI_PREFIXES, OUI_SEED
import sqlite3
from contextlib import closing
import re


def test_endpoint_candidate_wins_and_network_oui_is_rejected():
    endpoint = mab.MACEntry(
        mac="e8:6a:64:00:00:01", vendor="LCFC", category="workstation",
        frame_count=3, arp_seen=True, ipv4_seen=True, score=51,
    )
    network = mab.MACEntry(
        mac="00:1b:17:00:00:01", vendor="Palo Alto Networks", category="network",
        frame_count=100, arp_seen=True, ipv4_seen=True, score=23,
    )
    selected = mab.select_mab_candidate([network, endpoint], min_score=15)
    assert selected is endpoint
    assert not network.eligible
    assert "network-device OUI" in network.rejection_reason


def test_control_plane_and_no_endpoint_evidence_are_rejected():
    control = mab.MACEntry(mac="00:11:22:33:44:55", score=80, stp_seen=True, arp_seen=True)
    silent = mab.MACEntry(mac="00:11:22:33:44:66", score=80)
    assert mab.select_mab_candidate([control, silent], min_score=15) is None
    assert "control-plane traffic" in control.rejection_reason
    assert "no ARP/IPv4/IPv6 endpoint evidence" in silent.rejection_reason


def test_ipv6_endpoint_evidence_is_eligible():
    endpoint = mab.MACEntry(
        mac="00:11:22:33:44:77", frame_count=20, ipv6_seen=True, score=28
    )
    assert mab.select_mab_candidate([endpoint], min_score=15) is endpoint


def test_system_oui_fallback_is_cached(tmp_path, monkeypatch):
    monkeypatch.setattr(mab, "_DB_PATH", tmp_path / "oui.db")
    monkeypatch.setattr(mab, "_IEEE_CSV", tmp_path / "missing.csv")
    monkeypatch.setattr(mab, "_load_system_oui", lambda: {"E86A64": "LCFC(HeFei) Electronics"})
    vendor, category = mab.lookup_oui("e8:6a:64:aa:bb:cc")
    assert vendor.startswith("LCFC")
    assert category == "workstation"


def test_known_network_vendor_classification():
    assert mab._classify_vendor("Palo Alto Networks") == "network"
    assert mab._classify_vendor("Cisco Systems") == "network"


def test_conflicting_seed_prefixes_are_not_assigned_to_a_vendor():
    assert "001185" in AMBIGUOUS_OUI_PREFIXES
    assert "D4BED9" in AMBIGUOUS_OUI_PREFIXES
    assert not AMBIGUOUS_OUI_PREFIXES.intersection(OUI_SEED)
    assert all(re.fullmatch(r"[0-9A-F]{6}", prefix) for prefix in OUI_SEED)


def test_legacy_conflicting_oui_row_uses_system_registry(tmp_path, monkeypatch):
    monkeypatch.setattr(mab, "_DB_PATH", tmp_path / "oui.db")
    monkeypatch.setattr(mab, "_IEEE_CSV", tmp_path / "missing.csv")
    monkeypatch.setattr(mab, "_load_system_oui", lambda: {"001185": "Cisco Systems"})
    mab.init_oui_db()
    with closing(sqlite3.connect(mab._DB_PATH)) as conn:
        conn.execute(
            "INSERT OR REPLACE INTO oui VALUES (?, ?, ?)",
            ("001185", "Wrong Workstation", "workstation"),
        )
        conn.commit()
    assert mab.lookup_oui("00:11:85:00:00:01") == ("Cisco Systems", "network")


def test_conflicting_oui_prefers_supplied_ieee_csv_over_legacy_cache(tmp_path, monkeypatch):
    monkeypatch.setattr(mab, "_DB_PATH", tmp_path / "oui.db")
    registry = tmp_path / "oui_full.csv"
    registry.write_text(
        "Registry,Assignment,Organization Name,Organization Address\n"
        "MA-L,001185,Cisco Systems,Example\n",
        encoding="utf-8",
    )
    monkeypatch.setattr(mab, "_IEEE_CSV", registry)
    monkeypatch.setattr(mab, "_load_system_oui", lambda: {})
    mab.init_oui_db()
    with closing(sqlite3.connect(mab._DB_PATH)) as conn:
        conn.execute(
            "INSERT OR REPLACE INTO oui VALUES (?, ?, ?)",
            ("001185", "Wrong Workstation", "workstation"),
        )
        conn.commit()
    assert mab.lookup_oui("00:11:85:00:00:01") == ("Cisco Systems", "network")
