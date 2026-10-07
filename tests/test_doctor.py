from core import doctor


def _ready_environment(monkeypatch):
    monkeypatch.setattr(doctor.platform, "system", lambda: "Linux")
    monkeypatch.setattr(doctor.os, "geteuid", lambda: 0)
    monkeypatch.setattr(doctor, "validate_interface", lambda iface: iface == "eth0")
    monkeypatch.setattr(doctor, "get_iface_state", lambda iface: "up")
    monkeypatch.setattr(doctor, "_carrier_state", lambda iface: "1")
    monkeypatch.setattr(doctor, "get_iface_mac", lambda iface: "00:11:22:33:44:55")
    monkeypatch.setattr(doctor, "get_iface_ip", lambda iface: "10.0.0.2")
    monkeypatch.setattr(doctor, "get_iface_ipv6s", lambda iface: [])
    monkeypatch.setattr(
        doctor,
        "check_all_dependencies",
        lambda: {
            "ip": True,
            "dhclient": True,
            "pkill": True,
            "ebtables": True,
            "wpa_supplicant": True,
            "wpa_cli": True,
            "nmcli": False,
        },
    )
    monkeypatch.setattr(doctor, "check_python_dependencies", lambda modules: {m: True for m in modules})
    monkeypatch.setattr(doctor, "_check_bind_to_device", lambda iface: (True, "ok"))
    monkeypatch.setattr(doctor, "_check_packet_socket", lambda iface, require_ignore_outgoing: (True, "ok"))
    monkeypatch.setattr(doctor, "_check_relay_worker_start", lambda: (True, "ok"))


def _supported_teap(monkeypatch):
    from core import dot1x

    monkeypatch.setattr(
        dot1x,
        "probe_wpa_method_support",
        lambda method: (True, "supported"),
    )


def test_doctor_reports_ready_recon_environment(monkeypatch):
    _ready_environment(monkeypatch)
    result = doctor.run_doctor("eth0", mode="recon")
    assert result.ready
    assert all(check.success for check in result.checks if check.required)


def test_doctor_reports_teap_as_optional_capability(monkeypatch):
    _ready_environment(monkeypatch)
    _supported_teap(monkeypatch)
    result = doctor.run_doctor("eth0", mode="dot1x")
    check = next(
        item for item in result.checks if item.name == "wpa_method:teap_mschapv2"
    )
    assert check.success
    assert not check.required


def test_missing_teap_capability_does_not_fail_portable_dot1x_readiness(monkeypatch):
    _ready_environment(monkeypatch)
    from core import dot1x

    monkeypatch.setattr(
        dot1x,
        "probe_wpa_method_support",
        lambda method: (False, "TEAP not compiled"),
    )
    result = doctor.run_doctor("eth0", mode="dot1x")
    check = next(
        item for item in result.checks if item.name == "wpa_method:teap_mschapv2"
    )
    assert result.ready
    assert not check.success
    assert not check.required


def test_doctor_relay_requires_second_interface(monkeypatch):
    _ready_environment(monkeypatch)
    result = doctor.run_doctor("eth0", mode="relay")
    assert not result.ready
    check = next(item for item in result.checks if item.name == "secondary_interface")
    assert check.required and not check.success


def test_doctor_relay_rejects_unstartable_worker_backend(monkeypatch):
    _ready_environment(monkeypatch)
    monkeypatch.setattr(doctor, "validate_interface", lambda iface: iface in {"eth0", "eth1"})
    monkeypatch.setattr(doctor, "_check_relay_worker_start", lambda: (False, "forkserver denied"))
    result = doctor.run_doctor("eth0", mode="relay", interface2="eth1")
    check = next(item for item in result.checks if item.name == "relay_worker_start")
    assert not result.ready
    assert check.required and check.details == "forkserver denied"


def test_doctor_posture_requires_assigned_ip(monkeypatch):
    _ready_environment(monkeypatch)
    monkeypatch.setattr(doctor, "get_iface_ip", lambda iface: None)
    result = doctor.run_doctor("eth0", mode="posture")
    assert not result.ready
    check = next(item for item in result.checks if item.name == "primary_network_address")
    assert check.required and not check.success


def test_doctor_accepts_ipv6_only_posture_interface(monkeypatch):
    _ready_environment(monkeypatch)
    monkeypatch.setattr(doctor, "get_iface_ip", lambda iface: None)
    monkeypatch.setattr(doctor, "get_iface_ipv6s", lambda iface: ["2001:db8::2"])
    result = doctor.run_doctor("eth0", mode="posture")
    assert result.ready
