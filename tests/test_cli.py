import nacleaver
from types import SimpleNamespace

from core import posture, recon
from core.recon import NacType


def test_duplicate_flags_work_before_and_after_mab_command():
    parser = nacleaver.build_parser()
    before = parser.parse_args(["-i", "eth0", "--timeout", "22", "--harvest-duration", "9", "mab"])
    after = parser.parse_args(["-i", "eth0", "mab", "--timeout", "22", "--harvest-duration", "9"])
    assert before.timeout == after.timeout == 22
    assert before.harvest_duration == after.harvest_duration == 9


def test_auto_specific_flags_do_not_overwrite_global_values():
    parser = nacleaver.build_parser()
    before = parser.parse_args([
        "-i", "eth0", "--harvest-duration", "11", "--min-score", "20",
        "--config", "custom.yaml", "auto",
    ])
    after = parser.parse_args([
        "-i", "eth0", "auto", "--harvest-duration", "11", "--min-score", "20",
        "--config", "custom.yaml",
    ])
    assert before.harvest_duration == after.harvest_duration == 11
    assert before.min_score == after.min_score == 20
    assert before.config == after.config == "custom.yaml"


def test_enum_summary_method_never_calls_lower_on_enum():
    assert nacleaver._result_method({}, NacType.MAB_OR_OPEN) == "mab_or_open"
    assert nacleaver._result_method({"method": "mab"}, NacType.UNKNOWN) == "mab"


def test_configured_eap_order_is_honored():
    methods = nacleaver._resolve_eap_methods("auto", ["pwd", "peap_mschapv2"])
    assert [method.value for method in methods] == ["pwd", "peap_mschapv2"]


def test_unknown_configured_eap_method_is_rejected():
    import pytest
    with pytest.raises(ValueError, match="unsupported EAP"):
        nacleaver._resolve_eap_methods("auto", ["peap_mschapv2", "made_up"])


def test_default_eap_order_contains_only_portable_methods():
    methods = nacleaver._resolve_eap_methods("auto")
    assert "teap_mschapv2" not in [method.value for method in methods]


def test_dependency_preflight_fails_closed_for_relay_and_selected_backend():
    dependencies = {
        "ip": True,
        "dhclient": True,
        "pkill": True,
        "ebtables": False,
        "wpa_supplicant": False,
        "wpa_cli": False,
        "nmcli": False,
    }
    relay_errors = nacleaver._dependency_errors(
        "auto", dependencies, interface2="eth1"
    )
    assert any("ebtables" in error for error in relay_errors)

    dot1x_errors = nacleaver._dependency_errors(
        "dot1x", dependencies, backend="auto", dot1x_requested=True
    )
    assert any("either the complete" in error for error in dot1x_errors)


def test_process_exit_codes_distinguish_execution_from_verified_access():
    assert nacleaver._result_exit_code(
        "mab", {"summary": {"success": True}}
    ) == nacleaver.EXIT_OK
    assert nacleaver._result_exit_code(
        "mab", {"summary": {"success": False}}
    ) == nacleaver.EXIT_NOT_VERIFIED
    assert nacleaver._result_exit_code(
        "recon", {"recon": {"nac_type": "DOT1X"}}
    ) == nacleaver.EXIT_OK
    assert nacleaver._result_exit_code(
        "post", {"post_auth": {}}, save_failed=True
    ) == nacleaver.EXIT_FATAL
    assert nacleaver._result_exit_code(
        "posture", {
            "posture": {"posture_type": "http_redirect", "bypass_success": False},
            "summary": {"success": True},
        },
    ) == nacleaver.EXIT_NOT_VERIFIED
    assert nacleaver._result_exit_code(
        "relay", {"summary": {"success": True}, "cleanup": {"success": False}}
    ) == nacleaver.EXIT_FATAL


def test_interface_works_before_and_after_command():
    parser = nacleaver.build_parser()
    before = parser.parse_args(["-i", "eth0", "recon"])
    after = parser.parse_args(["recon", "-i", "eth0"])
    assert before.interface == after.interface == "eth0"


def test_dot1x_server_validation_flags_work_after_command():
    parser = nacleaver.build_parser()
    args = parser.parse_args([
        "dot1x", "-i", "eth0", "--server-domain", "radius.client.example",
        "--anonymous-identity", "anonymous", "--insecure-no-server-cert",
    ])
    assert args.server_domain == "radius.client.example"
    assert args.anonymous_identity == "anonymous"
    assert args.insecure_no_server_cert is True


def test_auto_does_not_report_captive_ip_as_success(monkeypatch):
    monkeypatch.setattr(
        recon,
        "run_recon",
        lambda *args, **kwargs: recon.ReconResult(
            nac_type=NacType.CAPTIVE_PORTAL,
            interface_ip="10.0.0.8",
            dhcp_lease="10.0.0.8",
            captive_portal_url="http://portal.test/",
        ),
    )
    monkeypatch.setattr(
        posture,
        "detect_and_bypass_posture",
        lambda *args, **kwargs: posture.PostureResult(
            posture_type=posture.PostureType.HTTP_REDIRECT,
            posture_url="http://portal.test/",
            bypass_attempted=True,
            bypass_success=False,
            details="rejected",
        ),
    )
    monkeypatch.setattr(
        recon,
        "verify_interface_access",
        lambda *args, **kwargs: recon.AccessVerification(
            state=NacType.CAPTIVE_PORTAL,
            interface_ip="10.0.0.8",
            connectivity_verified=False,
            captive_portal_url="http://portal.test/",
            http_status=302,
        ),
    )

    from modules import post_auth
    monkeypatch.setattr(
        post_auth,
        "run_post_auth",
        lambda *args, **kwargs: (_ for _ in ()).throw(
            AssertionError("restricted access must not be enumerated")
        ),
    )

    args = SimpleNamespace(
        interface="eth0",
        eap_method="auto",
        eap_method_order=None,
        recon_timeout=1,
        dhcp_timeout=1,
        recon_http_timeout=1,
        verbose=False,
        posture_timeout=1,
        no_posture=False,
        no_post=False,
    )
    result = nacleaver.cmd_auto(args, logger=None)
    assert not result["summary"]["success"]
    assert not result["summary"]["authorization_success"]
    assert result["summary"]["outcome"] == "restricted_or_unverified"
    assert "post_auth" not in result
    assert "post_auth_skipped" in result


def test_auto_uses_internal_verification_before_attempting_mab(monkeypatch):
    from core import mab

    monkeypatch.setattr(
        recon, "run_recon",
        lambda *args, **kwargs: recon.ReconResult(
            nac_type=NacType.QUARANTINE_VLAN,
            interface_ip="10.0.0.8",
        ),
    )
    monkeypatch.setattr(
        recon, "verify_interface_access",
        lambda *args, **kwargs: recon.AccessVerification(
            state=NacType.OPEN,
            interface_ip="10.0.0.8",
            connectivity_verified=True,
        ),
    )
    monkeypatch.setattr(
        mab,
        "run_mab_bypass",
        lambda *args, **kwargs: (_ for _ in ()).throw(
            AssertionError("already authorized interface must not be spoofed")
        ),
    )
    args = SimpleNamespace(
        interface="eth0", eap_method="auto", eap_method_order=None,
        recon_timeout=1, dhcp_timeout=1, recon_http_timeout=1,
        verbose=False, no_posture=True, no_post=True,
        verification_targets=[{"type": "tcp", "host": "10.0.0.10", "port": 443}],
        verification_policy="any",
    )
    result = nacleaver.cmd_auto(args, logger=None)
    assert result["summary"]["success"]
    assert result["summary"]["bypass_method"] == "already_authorized"
    assert result["pre_verification"]["connectivity_verified"]
