import logging
import sys

import pytest

import nacleaver
from core import doctor, dot1x, mab, posture, recon, relay
from modules import post_auth


def _patch_main_environment(monkeypatch, tmp_path):
    saved = []
    monkeypatch.setattr(nacleaver, "validate_interface", lambda iface: True)
    monkeypatch.setattr(nacleaver, "require_root", lambda: None)
    monkeypatch.setattr(nacleaver, "load_config", lambda path=None, strict=False: {})
    monkeypatch.setattr(
        nacleaver,
        "check_all_dependencies",
        lambda: {
            "ip": True,
            "dhclient": True,
            "pkill": True,
            "ebtables": True,
            "ethtool": True,
            "wpa_supplicant": True,
            "wpa_cli": True,
            "nmcli": True,
        },
    )
    monkeypatch.setattr(
        nacleaver,
        "check_python_dependencies",
        lambda modules: {name: True for name in modules},
    )
    monkeypatch.setattr(
        nacleaver,
        "setup_logging",
        lambda verbose, output: logging.getLogger("nacleaver-test"),
    )
    monkeypatch.setattr(nacleaver.Cleanup, "enable_journal", lambda: tmp_path / "state.json")
    monkeypatch.setattr(nacleaver.Cleanup, "disable_mac_restore", lambda: None)
    monkeypatch.setattr(nacleaver.atexit, "register", lambda callback: None)
    monkeypatch.setattr(nacleaver.signal, "signal", lambda *args: None)
    monkeypatch.setattr(
        nacleaver,
        "save_json_result",
        lambda result, output: (saved.append(result) or str(tmp_path / "result.json")),
    )
    return saved


def _verified_access(iface, *args, **kwargs):
    return recon.AccessVerification(
        state=recon.NacType.OPEN,
        interface_ip="10.0.0.8",
        connectivity_verified=True,
    )


@pytest.mark.parametrize(
    ("command", "extra_args"),
    [
        ("recon", []),
        ("mab", []),
        ("dot1x", ["-u", "alice"]),
        ("relay", ["-i2", "eth1"]),
        ("posture", []),
        ("post", []),
        ("restore-mac", []),
        ("auto", ["-u", "alice"]),
        ("doctor", ["--mode", "recon"]),
    ],
)
def test_main_dispatches_every_command(monkeypatch, tmp_path, command, extra_args):
    saved = _patch_main_environment(monkeypatch, tmp_path)
    monkeypatch.setattr(recon, "verify_interface_access", _verified_access)
    monkeypatch.setattr(nacleaver, "get_iface_ip", lambda iface: "10.0.0.8")
    monkeypatch.setattr(nacleaver, "get_iface_ipv6", lambda iface: None)
    monkeypatch.setattr(nacleaver, "get_iface_gateway", lambda iface: "10.0.0.1")
    monkeypatch.setattr(nacleaver, "get_iface_gateway6", lambda iface: None)

    monkeypatch.setattr(
        recon,
        "run_recon",
        lambda *args, **kwargs: recon.ReconResult(
            nac_type=recon.NacType.OPEN,
            interface_ip="10.0.0.8",
            connectivity_verified=True,
        ),
    )
    monkeypatch.setattr(
        mab,
        "run_mab_bypass",
        lambda *args, **kwargs: mab.MABResult(
            success=True,
            spoofed_mac="00:11:22:33:44:55",
            obtained_ip="10.0.0.8",
            original_mac="00:aa:bb:cc:dd:ee",
            candidates=[],
        ),
    )
    monkeypatch.setattr(
        dot1x,
        "run_dot1x",
        lambda *args, **kwargs: dot1x.Dot1XResult(
            success=True,
            method_used=dot1x.EAPMethod.PEAP_MSCHAPV2,
            identity="alice",
            password=dot1x.REDACTED_PASSWORD,
            obtained_ip="10.0.0.8",
            backend_used="wpa_supplicant",
        ),
    )
    monkeypatch.setattr(
        relay,
        "run_relay",
        lambda *args, **kwargs: relay.RelayResult(
            success=True,
            auth_completed=True,
            obtained_ip="10.0.0.8",
            endpoint_mac="00:11:22:33:44:55",
            duration_sec=1.0,
            eapol_frames_relayed=4,
            network_interface="nacleaver_br",
        ),
    )
    monkeypatch.setattr(
        posture,
        "detect_and_bypass_posture",
        lambda *args, **kwargs: posture.PostureResult(
            posture_type=posture.PostureType.NONE,
            posture_url=None,
            bypass_attempted=False,
            bypass_success=False,
            details="No posture check detected",
        ),
    )
    monkeypatch.setattr(
        post_auth,
        "run_post_auth",
        lambda *args, **kwargs: post_auth.PostAuthResult(
            obtained_ip="10.0.0.8",
            subnet="10.0.0.0/24",
            scanned_subnet="10.0.0.0/24",
            gateway="10.0.0.1",
        ),
    )
    monkeypatch.setattr(
        doctor,
        "run_doctor",
        lambda *args, **kwargs: doctor.DoctorResult(
            interface="eth0", mode="recon", ready=True
        ),
    )
    monkeypatch.setattr(
        nacleaver,
        "restore_permanent_mac",
        lambda iface: (True, "00:aa:bb:cc:dd:ee", None),
    )
    monkeypatch.setattr(
        nacleaver,
        "cmd_auto",
        lambda args, logger: {
            "timestamp": "test",
            "interface": args.interface,
            "command": "auto",
            "summary": {"success": True},
        },
    )

    argv = ["nacleaver", "-i", "eth0", "-o", str(tmp_path), command, *extra_args]
    monkeypatch.setattr(sys, "argv", argv)
    assert nacleaver.main() == nacleaver.EXIT_OK
    assert saved and saved[-1]["command"] == command


def test_main_dependency_failure_happens_before_cleanup_journal(monkeypatch, tmp_path):
    _patch_main_environment(monkeypatch, tmp_path)
    journal_calls = []
    monkeypatch.setattr(
        nacleaver,
        "check_all_dependencies",
        lambda: {
            "ip": True,
            "dhclient": True,
            "pkill": True,
            "ebtables": False,
            "ethtool": True,
            "wpa_supplicant": True,
            "wpa_cli": True,
            "nmcli": True,
        },
    )
    monkeypatch.setattr(
        nacleaver.Cleanup,
        "enable_journal",
        lambda: journal_calls.append(True),
    )
    monkeypatch.setattr(
        sys,
        "argv",
        ["nacleaver", "-i", "eth0", "relay", "-i2", "eth1"],
    )
    assert nacleaver.main() == nacleaver.EXIT_FATAL
    assert not journal_calls


def test_main_reports_cleanup_failure_in_saved_result_and_exit_code(monkeypatch, tmp_path):
    saved = _patch_main_environment(monkeypatch, tmp_path)
    monkeypatch.setattr(nacleaver.Cleanup, "run_all", lambda: False)
    monkeypatch.setattr(
        sys, "argv", ["nacleaver", "-i", "eth0", "-o", str(tmp_path), "doctor"]
    )
    monkeypatch.setattr(
        doctor,
        "run_doctor",
        lambda *args, **kwargs: doctor.DoctorResult(
            interface="eth0", mode="all", ready=True
        ),
    )
    assert nacleaver.main() == nacleaver.EXIT_FATAL
    assert saved[-1]["cleanup"]["recovery_required"]
