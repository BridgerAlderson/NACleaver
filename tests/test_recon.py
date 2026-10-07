from core import recon
from types import SimpleNamespace
import sys
import types


def _fake_scapy(monkeypatch, sniffer_type):
    fake_all = types.ModuleType("scapy.all")
    fake_all.AsyncSniffer = sniffer_type
    fake_all.EAP = object()
    fake_all.EAPOL = lambda **kwargs: object()
    fake_all.conf = SimpleNamespace(sniff_promisc=False)
    fake_all.sendp = lambda *args, **kwargs: None

    class Ether:
        def __init__(self, **kwargs):
            pass

        def __truediv__(self, other):
            return self

    fake_all.Ether = Ether
    fake_scapy = types.ModuleType("scapy")
    fake_scapy.all = fake_all
    monkeypatch.setitem(sys.modules, "scapy", fake_scapy)
    monkeypatch.setitem(sys.modules, "scapy.all", fake_all)
    return fake_all


def test_http_verification_uses_bound_socket_and_expected_content(monkeypatch):
    calls = []

    class FakeSocket:
        def __init__(self):
            self.chunks = [
                b"HTTP/1.1 200 OK\r\nContent-Type: text/plain\r\n\r\nauthorized=true",
                b"",
            ]

        def sendall(self, payload):
            calls.append(payload)

        def recv(self, size):
            return self.chunks.pop(0)

        def close(self):
            calls.append("closed")

    monkeypatch.setattr(
        recon,
        "_connect_bound_socket",
        lambda iface, host, port, timeout: (
            calls.append((iface, host, port, timeout)) or FakeSocket()
        ),
    )
    result = recon._http_target_probe(
        "eth0",
        {
            "url": "http://intranet.example/nac-health",
            "expected_status": [200],
            "body_contains": "authorized=true",
        },
        2,
    )
    assert result["success"]
    assert calls[0] == ("eth0", "intranet.example", 80, 2)
    assert b"GET /nac-health HTTP/1.1" in calls[1]
    assert calls[-1] == "closed"


def test_recon_classifies_eap_request_evidence_without_dhcp(monkeypatch):
    eap = SimpleNamespace(code=1, type=25)
    eap_layer = object()

    class Packet:
        src = "00:11:22:33:44:55"

        def haslayer(self, layer):
            return layer is eap_layer

        def __getitem__(self, layer):
            return eap

    class FakeSniffer:
        def __init__(self, **kwargs):
            self.callback = kwargs.get("prn")
            self.results = [Packet()] if self.callback else []
            self.running = False

        def start(self):
            self.running = True
            if self.callback:
                self.callback(self.results[0])

        def stop(self):
            self.running = False

    fake_all = _fake_scapy(monkeypatch, FakeSniffer)
    fake_all.EAP = eap_layer
    monkeypatch.setattr(recon.time, "sleep", lambda duration: None)
    monkeypatch.setattr(recon, "get_iface_mac", lambda iface: "aa:bb:cc:dd:ee:ff")
    monkeypatch.setattr(recon, "get_iface_ip", lambda iface: None)
    monkeypatch.setattr(recon, "get_iface_ipv6s", lambda iface: [])
    monkeypatch.setattr(recon, "get_iface_gateway6", lambda iface: None)
    monkeypatch.setattr(
        recon, "_dhcp_probe",
        lambda *args, **kwargs: (_ for _ in ()).throw(
            AssertionError("EAP evidence must decide before DHCP probing")
        ),
    )
    result = recon.run_recon("eth0", timeout=1)
    assert result.nac_type is recon.NacType.DOT1X
    assert result.raw_eapol_count == 1
    assert result.eap_methods_observed == [25]


def test_recon_offer_without_lease_remains_dhcp_only(monkeypatch):
    class FakeSniffer:
        def __init__(self, **kwargs):
            self.results = []
            self.running = False

        def start(self):
            self.running = True

        def stop(self):
            self.running = False

    _fake_scapy(monkeypatch, FakeSniffer)
    monkeypatch.setattr(recon.time, "sleep", lambda duration: None)
    monkeypatch.setattr(recon, "get_iface_mac", lambda iface: "aa:bb:cc:dd:ee:ff")
    monkeypatch.setattr(recon, "get_iface_ip", lambda iface: None)
    monkeypatch.setattr(recon, "get_iface_ipv6s", lambda iface: [])
    monkeypatch.setattr(recon, "get_iface_gateway6", lambda iface: None)
    monkeypatch.setattr(
        recon, "_dhcp_probe",
        lambda *args, **kwargs: (True, {"_yiaddr": "10.0.0.8", "router": "10.0.0.1"}),
    )
    monkeypatch.setattr(recon, "_ipv6_control_probe", lambda *args, **kwargs: {})
    result = recon.run_recon("eth0", timeout=0)
    assert result.nac_type is recon.NacType.DHCP_ONLY
    assert result.dhcp_offer == "10.0.0.8"
    assert result.dhcp_lease is None


def test_recon_uses_internal_targets_instead_of_public_probe(monkeypatch):
    class FakeSniffer:
        def __init__(self, **kwargs):
            self.results = []
            self.running = False

        def start(self):
            self.running = True

        def stop(self):
            self.running = False

    _fake_scapy(monkeypatch, FakeSniffer)
    monkeypatch.setattr(recon.time, "sleep", lambda duration: None)
    monkeypatch.setattr(recon, "get_iface_mac", lambda iface: "aa:bb:cc:dd:ee:ff")
    monkeypatch.setattr(recon, "get_iface_ip", lambda iface: "10.0.0.8")
    monkeypatch.setattr(recon, "get_iface_ipv6s", lambda iface: [])
    monkeypatch.setattr(recon, "get_iface_gateway6", lambda iface: None)
    monkeypatch.setattr(recon, "_dhcp_probe", lambda *args, **kwargs: (False, {}))
    monkeypatch.setattr(recon, "_ipv6_control_probe", lambda *args, **kwargs: {})
    monkeypatch.setattr(
        recon,
        "_check_captive_portal",
        lambda *args, **kwargs: (_ for _ in ()).throw(
            AssertionError("configured internal targets must replace the public probe")
        ),
    )
    monkeypatch.setattr(
        recon,
        "verify_interface_access",
        lambda *args, **kwargs: recon.AccessVerification(
            state=recon.NacType.OPEN,
            interface_ip="10.0.0.8",
            connectivity_verified=True,
            policy="any",
        ),
    )
    result = recon.run_recon(
        "eth0", timeout=0,
        verification_targets=[{"type": "tcp", "host": "10.0.0.10", "port": 443}],
    )
    assert result.nac_type is recon.NacType.OPEN
    assert result.connectivity_verified


def test_dhcp_probe_accepts_only_offer_message_type():
    assert recon._is_dhcp_offer_value(2)
    assert recon._is_dhcp_offer_value("offer")
    assert recon._is_dhcp_offer_value(b"\x02")
    assert not recon._is_dhcp_offer_value(5)
    assert not recon._is_dhcp_offer_value("ack")


def test_captive_classification_is_interface_bound(monkeypatch):
    monkeypatch.setattr(recon, "get_iface_ip", lambda iface: "10.0.0.5")

    monkeypatch.setattr(recon, "_http_probe_bound", lambda iface, timeout: (200, None, None))
    nac_type, url, status, error = recon._check_captive_portal("eth0")
    assert nac_type is recon.NacType.OPEN
    assert status == 200
    assert url is None and error is None

    monkeypatch.setattr(
        recon, "_http_probe_bound",
        lambda iface, timeout: (302, "http://portal.test/login", None),
    )
    nac_type, url, status, error = recon._check_captive_portal("eth0")
    assert nac_type is recon.NacType.CAPTIVE_PORTAL
    assert url == "http://portal.test/login"
    assert status == 302 and error is None

    monkeypatch.setattr(recon, "_http_probe_bound", lambda iface, timeout: (None, None, "timeout"))
    nac_type, _, status, error = recon._check_captive_portal("eth0")
    assert nac_type is recon.NacType.QUARANTINE_VLAN
    assert status is None and error == "timeout"

    monkeypatch.setattr(
        recon,
        "_http_probe_bound",
        lambda iface, timeout: (200, None, "unexpected portal content"),
    )
    nac_type, _, status, error = recon._check_captive_portal("eth0")
    assert nac_type is recon.NacType.UNKNOWN
    assert status == 200 and error == "unexpected portal content"


def test_offer_without_assigned_ip_is_not_open(monkeypatch):
    monkeypatch.setattr(recon, "get_iface_ip", lambda iface: None)
    monkeypatch.setattr(recon, "get_iface_ipv6s", lambda iface: [])
    nac_type, _, status, error = recon._check_captive_portal("eth0")
    assert nac_type is recon.NacType.DHCP_ONLY
    assert status is None
    assert "no assigned IPv4" in error


def test_ipv6_only_interface_can_be_verified(monkeypatch):
    monkeypatch.setattr(recon, "get_iface_ip", lambda iface: None)
    monkeypatch.setattr(recon, "get_iface_ipv6s", lambda iface: ["2001:db8::9"])
    monkeypatch.setattr(recon, "_http_probe_bound", lambda iface, timeout: (200, None, None))
    result = recon.verify_interface_access("eth0", timeout=2)
    assert result.interface_ip == "2001:db8::9"
    assert result.interface_ipv6 == ["2001:db8::9"]
    assert result.state is recon.NacType.OPEN
    assert result.connectivity_verified


def test_access_verification_keeps_dhcp_separate_from_usable_access(monkeypatch):
    monkeypatch.setattr(recon, "get_iface_ip", lambda iface: "10.0.0.9")
    monkeypatch.setattr(
        recon,
        "_http_probe_bound",
        lambda iface, timeout: (None, None, "blocked"),
    )
    result = recon.verify_interface_access("eth0", timeout=2)
    assert result.interface_ip == "10.0.0.9"
    assert result.state is recon.NacType.QUARANTINE_VLAN
    assert not result.connectivity_verified
    assert result.error == "blocked"


def test_engagement_verification_targets_replace_public_probe(monkeypatch):
    monkeypatch.setattr(recon, "get_iface_ip", lambda iface: "10.0.0.9")
    monkeypatch.setattr(
        recon,
        "_check_captive_portal",
        lambda *a, **k: (_ for _ in ()).throw(AssertionError("public probe used")),
    )
    monkeypatch.setattr(
        recon,
        "_run_verification_target",
        lambda iface, target, timeout, index: {
            "name": target["name"],
            "type": "tcp",
            "success": target["name"] == "allowed-service",
        },
    )
    targets = [
        {"name": "allowed-service", "type": "tcp", "host": "10.0.0.10", "port": 443},
        {"name": "blocked-service", "type": "tcp", "host": "10.0.0.11", "port": 443},
    ]
    any_result = recon.verify_interface_access("eth0", targets=targets, policy="any")
    all_result = recon.verify_interface_access("eth0", targets=targets, policy="all")
    assert any_result.connectivity_verified
    assert any_result.state is recon.NacType.OPEN
    assert not all_result.connectivity_verified
    assert all_result.state is recon.NacType.QUARANTINE_VLAN
    assert len(any_result.probes) == 2
