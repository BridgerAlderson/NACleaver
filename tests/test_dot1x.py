import dataclasses
import os
from pathlib import Path

import pytest

from core import dot1x


def test_wpa_quote_escapes_and_rejects_newlines():
    assert dot1x._wpa_quote('a"b\\c') == '"a\\"b\\\\c"'
    with pytest.raises(ValueError):
        dot1x._wpa_quote("line1\nline2")


def test_generated_wpa_config_is_private():
    path = dot1x.generate_wpa_config(
        dot1x.EAPMethod.PEAP_MSCHAPV2, "alice", "secret"
    )
    try:
        assert os.stat(path).st_mode & 0o777 == 0o600
        contents = Path(path).read_text(encoding="utf-8")
        assert "secret" in contents
        assert 'ca_cert=""' not in contents
        assert "ca_cert=" in contents or "ca_path=" in contents
    finally:
        os.remove(path)


def test_insecure_server_validation_must_be_explicit():
    path = dot1x.generate_wpa_config(
        dot1x.EAPMethod.PEAP_MSCHAPV2,
        "alice",
        "secret",
        server_domain="radius.client.example",
        anonymous_identity="anonymous",
        insecure_no_server_cert=True,
    )
    try:
        contents = Path(path).read_text(encoding="utf-8")
        assert 'ca_cert=""' in contents
        assert 'domain_suffix_match="radius.client.example"' in contents
        assert 'anonymous_identity="anonymous"' in contents
    finally:
        os.remove(path)

    with pytest.raises(ValueError, match="mutually exclusive"):
        dot1x.generate_wpa_config(
            dot1x.EAPMethod.PEAP_MSCHAPV2,
            "alice",
            "secret",
            server_ca_cert="/tmp/ca.pem",
            insecure_no_server_cert=True,
        )


def test_eap_tls_requires_certificate_and_key():
    with pytest.raises(ValueError, match="client certificate"):
        dot1x.generate_wpa_config(dot1x.EAPMethod.TLS, "alice", "")


def test_fast_teap_and_sim_generate_real_wpa_parameters(tmp_path):
    pac = tmp_path / "client.pac"
    fast_path = dot1x.generate_wpa_config(
        dot1x.EAPMethod.FAST_MSCHAPV2,
        "alice",
        "secret",
        pac_file=str(pac),
        fast_provisioning=1,
    )
    teap_path = dot1x.generate_wpa_config(
        dot1x.EAPMethod.TEAP_MSCHAPV2,
        "alice",
        "secret",
        insecure_no_server_cert=True,
    )
    sim_path = dot1x.generate_wpa_config(
        dot1x.EAPMethod.AKA_PRIME,
        "",
        "",
        sim_pin="1234",
        sim_pcsc="Reader 0",
        sim_number=1,
    )
    try:
        fast = Path(fast_path).read_text(encoding="utf-8")
        assert "eap=FAST" in fast
        assert 'phase1="fast_provisioning=1"' in fast
        assert f'pac_file="{pac}"' in fast
        teap = Path(teap_path).read_text(encoding="utf-8")
        assert "eap=TEAP" in teap and 'phase2="auth=MSCHAPV2"' in teap
        sim = Path(sim_path).read_text(encoding="utf-8")
        assert "eap=AKA'" in sim
        assert 'pcsc="Reader 0"' in sim
        assert 'phase1="sim_num=1"' in sim
    finally:
        for path in (fast_path, teap_path, sim_path):
            os.remove(path)


def test_sim_method_does_not_require_username(monkeypatch):
    monkeypatch.setattr(dot1x, "_select_backend", lambda preferred: "wpa_supplicant")
    monkeypatch.setattr(
        dot1x, "_attempt_auth", lambda *args, **kwargs: (True, "2001:db8::9", None)
    )
    result = dot1x.run_dot1x("eth0", methods=[dot1x.EAPMethod.SIM])
    assert result.success
    assert result.address_family == "ipv6"


def test_results_redact_password(monkeypatch):
    monkeypatch.setattr(dot1x, "_select_backend", lambda preferred: "wpa_supplicant")
    monkeypatch.setattr(
        dot1x, "_attempt_auth",
        lambda *args, **kwargs: (True, "10.0.0.9", None),
    )
    result = dot1x.run_dot1x(
        "eth0", identity="alice", password="top-secret",
        methods=[dot1x.EAPMethod.PEAP_MSCHAPV2],
    )
    serialized = repr(dataclasses.asdict(result))
    assert result.success
    assert result.password == dot1x.REDACTED_PASSWORD
    assert all(a.password == dot1x.REDACTED_PASSWORD for a in result.attempts)
    assert "top-secret" not in serialized


def test_nmcli_password_is_not_put_in_argv(monkeypatch):
    commands = []
    registered = []
    monkeypatch.setattr(dot1x.Cleanup, "capture_interface", lambda iface: (True, None))
    monkeypatch.setattr(dot1x.Cleanup, "register_nm_connection", registered.append)
    monkeypatch.setattr(dot1x.Cleanup, "unregister_nm_connection", lambda name: None)

    def fake_run(cmd, **kwargs):
        commands.append(cmd)
        return 0, "", ""

    monkeypatch.setattr(dot1x, "run_subprocess", fake_run)
    monkeypatch.setattr(dot1x, "get_iface_ip", lambda iface: "10.0.0.8")
    success, ip = dot1x._try_nmcli(
        "eth0", "NACleaver", dot1x.EAPMethod.PEAP_MSCHAPV2,
        "alice", "top-secret", timeout=1,
    )
    assert success and ip == "10.0.0.8"
    assert registered
    assert not any("top-secret" in arg for cmd in commands for arg in cmd)
    assert any("passwd-file" in cmd for cmd in commands)
    modify = next(cmd for cmd in commands if "modify" in cmd)
    ca_index = modify.index("802-1x.system-ca-certs")
    assert modify[ca_index + 1] == "yes"


def test_auto_backend_requires_complete_wpa_stack(monkeypatch):
    available = {
        "wpa_supplicant": True,
        "wpa_cli": True,
        "dhclient": False,
        "nmcli": True,
    }
    monkeypatch.setattr(dot1x, "check_dependency", lambda name: available.get(name, False))
    assert dot1x._select_backend("auto") == "nmcli"


def test_wpa_capability_preflight_reports_uncompiled_method(monkeypatch, tmp_path):
    monkeypatch.setattr(dot1x, "_WPA_METHOD_CAPABILITY", {})
    config = tmp_path / "wpa.conf"
    config.write_text("network={}\n", encoding="utf-8")
    monkeypatch.setattr(
        dot1x,
        "run_subprocess",
        lambda *a, **k: (
            1,
            "Line 7: unknown EAP method 'TEAP'\nLine 12: failed to parse network block.",
            "",
        ),
    )
    with pytest.raises(ValueError, match="does not support teap_mschapv2"):
        dot1x._validate_wpa_method_support(
            str(config), dot1x.EAPMethod.TEAP_MSCHAPV2
        )


def test_nmcli_private_key_password_is_not_put_in_argv(monkeypatch, tmp_path):
    cert = tmp_path / "client.pem"
    key = tmp_path / "client.key"
    cert.write_text("cert", encoding="utf-8")
    key.write_text("key", encoding="utf-8")
    commands = []
    monkeypatch.setattr(dot1x.Cleanup, "capture_interface", lambda iface: (True, None))
    monkeypatch.setattr(dot1x.Cleanup, "register_nm_connection", lambda name: None)
    monkeypatch.setattr(dot1x.Cleanup, "unregister_nm_connection", lambda name: None)
    monkeypatch.setattr(
        dot1x, "run_subprocess", lambda cmd, **kwargs: (commands.append(cmd) or (0, "", ""))
    )
    monkeypatch.setattr(dot1x, "get_iface_ip", lambda iface: "10.0.0.8")
    success, _ = dot1x._try_nmcli(
        "eth0", "NACleaver", dot1x.EAPMethod.TLS, "alice", "", timeout=1,
        client_cert=str(cert), private_key=str(key), private_key_passwd="key-secret",
    )
    assert success
    assert not any("key-secret" in arg for cmd in commands for arg in cmd)
    assert any("passwd-file" in cmd for cmd in commands)
