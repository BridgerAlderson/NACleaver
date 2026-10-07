import sys
import types

import pytest

from core import relay
from core.utils import DHCPLeaseResult


def test_bridge_name_is_validated_before_system_changes(monkeypatch):
    monkeypatch.setattr(relay, "run_subprocess", lambda *args, **kwargs: pytest.fail("must not run"))
    with pytest.raises(RuntimeError, match="Invalid bridge name"):
        relay.setup_bridge("eth0", "eth1", bridge_name="name-is-far-too-long")


def test_bridge_setup_stops_on_failed_step(monkeypatch):
    calls = []
    monkeypatch.setattr(relay.Cleanup, "register_bridge", lambda name: calls.append(("registered", name)))

    def fake_run(cmd, **kwargs):
        calls.append(cmd)
        if "stp_state" in cmd:
            return 1, "", "operation failed"
        return 0, "", ""

    monkeypatch.setattr(relay, "run_subprocess", fake_run)
    with pytest.raises(RuntimeError, match="Disabling STP"):
        relay.setup_bridge("eth0", "eth1")
    assert ("registered", "nacleaver_br") in calls


def test_teardown_deletes_only_nacleaver_rule(monkeypatch):
    commands = []
    monkeypatch.setattr(
        relay, "run_subprocess",
        lambda cmd, **kwargs: (commands.append(cmd) or 0, "", ""),
    )
    monkeypatch.setattr(relay.Cleanup, "unregister_ebtables_rule", lambda *args: None)
    monkeypatch.setattr(relay.Cleanup, "unregister_bridge", lambda *args: None)
    assert relay.teardown_bridge("nacleaver_br", "eth0", "eth1")
    assert ["ebtables", "-t", "broute", "-F", "BROUTING"] not in commands
    for iface in ("eth0", "eth1"):
        assert [
            "ebtables", "-t", "broute", "-D", "BROUTING",
            "-i", iface, "-p", "0x888e", "-j", "DROP",
        ] in commands


def test_relay_listener_suppresses_outgoing_frames(monkeypatch):
    sockopts = []

    class FakeRawSocket:
        def setsockopt(self, level, option, value):
            sockopts.append((level, option, value))

    class FakeListener:
        ins = FakeRawSocket()

        def close(self):
            pass

    fake_conf = types.SimpleNamespace(
        L2listen=lambda **kwargs: FakeListener(),
    )
    fake_all = types.ModuleType("scapy.all")
    fake_all.conf = fake_conf
    fake_scapy = types.ModuleType("scapy")
    fake_scapy.all = fake_all
    monkeypatch.setitem(sys.modules, "scapy", fake_scapy)
    monkeypatch.setitem(sys.modules, "scapy.all", fake_all)

    listener = relay._open_ingress_eapol_socket("eth0")
    assert isinstance(listener, FakeListener)
    assert sockopts == [(relay._SOL_PACKET, relay._PACKET_IGNORE_OUTGOING, 1)]


def test_relay_keeps_forwarders_alive_after_eap_success(monkeypatch):
    processes = []
    registered = []

    class FakeEvent:
        def __init__(self):
            self.value = False

        def set(self):
            self.value = True

        def is_set(self):
            return self.value

    class FakeQueue:
        def __init__(self):
            self.messages = [
                {"event": "WORKER_READY", "worker": "switch"},
                {"event": "WORKER_READY", "worker": "endpoint"},
                {"event": "EAP_SUCCESS"},
            ]

        def get(self, timeout):
            return self.messages.pop(0)

    class FakeProcess:
        def __init__(self, **kwargs):
            self.pid = 56000 + len(processes)
            self.alive = False
            processes.append(self)

        def start(self):
            self.alive = True

        def is_alive(self):
            return self.alive

    monkeypatch.setattr(relay, "Event", FakeEvent)
    monkeypatch.setattr(relay, "Queue", FakeQueue)
    monkeypatch.setattr(relay, "Process", FakeProcess)
    monkeypatch.setattr(relay, "get_iface_state", lambda iface: "up")
    monkeypatch.setattr(relay, "get_iface_mac", lambda iface: "00:11:22:33:44:55")
    monkeypatch.setattr(relay.Cleanup, "prepare_interface", lambda iface: (True, None))
    monkeypatch.setattr(
        relay.Cleanup,
        "register_worker_process",
        lambda process, event: registered.append(process.pid),
    )
    monkeypatch.setattr(relay, "setup_bridge", lambda *args, **kwargs: "nacleaver_br")
    monkeypatch.setattr(
        relay,
        "request_network_lease",
        lambda iface, timeout: DHCPLeaseResult(
            True, "10.0.0.8", "10.0.0.1", 0, 0.1, address_family="ipv4"
        ),
    )
    result = relay.run_relay("eth0", "eth1")
    assert result.success
    assert registered == [56000, 56001]
    assert all(process.is_alive() for process in processes)
