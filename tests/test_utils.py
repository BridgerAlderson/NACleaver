import os
import json
from multiprocessing import get_context
from pathlib import Path

import pytest

from core import utils


def _wait_for_stop(event):
    event.wait(10)


def _prepare_dhcp(monkeypatch, returncode, ip):
    monkeypatch.setattr(utils, "validate_interface", lambda iface: True)
    monkeypatch.setattr(utils, "check_dependency", lambda name: True)
    monkeypatch.setattr(utils, "kill_process_on_iface", lambda *args: None)
    monkeypatch.setattr(utils, "run_subprocess", lambda *args, **kwargs: (returncode, "", "failed"))
    monkeypatch.setattr(utils, "get_iface_ip", lambda iface: ip)
    monkeypatch.setattr(utils, "get_iface_gateway", lambda iface: "10.0.0.1")


def test_dhcp_failure_never_accepts_stale_ip(monkeypatch):
    _prepare_dhcp(monkeypatch, returncode=1, ip="10.0.0.77")
    lease = utils.request_dhcp_lease("eth0", timeout=1)
    assert not lease.success
    assert lease.ip is None
    assert lease.gateway is None
    assert lease.returncode == 1


def test_interface_ip_ignores_link_local_address(monkeypatch):
    monkeypatch.setattr(
        utils.netifaces,
        "ifaddresses",
        lambda iface: {
            utils.netifaces.AF_INET: [
                {"addr": "169.254.20.4"},
                {"addr": "10.20.30.40"},
            ]
        },
    )
    assert utils.get_iface_ips("eth0") == ["10.20.30.40"]
    assert utils.get_iface_ip("eth0") == "10.20.30.40"


def test_interface_ipv6_separates_global_and_link_local(monkeypatch):
    monkeypatch.setattr(
        utils.netifaces,
        "ifaddresses",
        lambda iface: {
            utils.netifaces.AF_INET6: [
                {"addr": "fe80::1234%eth0"},
                {"addr": "2001:db8::42"},
            ]
        },
    )
    assert utils.get_iface_ipv6s("eth0") == ["2001:db8::42"]
    assert utils.get_iface_ipv6s("eth0", include_link_local=True) == [
        "fe80::1234", "2001:db8::42"
    ]


def test_ipv6_netmask_is_normalized_to_prefix_length(monkeypatch):
    monkeypatch.setattr(
        utils.netifaces,
        "ifaddresses",
        lambda iface: {
            utils.netifaces.AF_INET6: [{
                "addr": "2001:db8::9%eth0",
                "netmask": "ffff:ffff:ffff:ffff::",
            }]
        },
    )
    assert utils.get_iface_netmask("eth0", "2001:db8::9") == "64"


def test_dual_stack_addressing_falls_back_to_ipv6(monkeypatch):
    monkeypatch.setattr(
        utils,
        "request_dhcp_lease",
        lambda iface, timeout: utils.DHCPLeaseResult(
            False, None, None, 1, 0.1, "no IPv4"
        ),
    )
    monkeypatch.setattr(
        utils,
        "request_dhcp6_lease",
        lambda iface, timeout: utils.DHCPLeaseResult(
            True, "2001:db8::9", "fe80::1", 0, 0.1, address_family="ipv6"
        ),
    )
    result = utils.request_network_lease("eth0", timeout=1)
    assert result.success
    assert result.ip == "2001:db8::9"
    assert result.address_family == "ipv6"


def test_ip_to_network_rejects_non_contiguous_netmask():
    with pytest.raises(ValueError):
        utils.ip_to_network("10.0.0.5", "255.0.255.0")


def test_dhcp_success_requires_assigned_ipv4(monkeypatch):
    _prepare_dhcp(monkeypatch, returncode=0, ip=None)
    lease = utils.request_dhcp_lease("eth0", timeout=1)
    assert not lease.success
    assert "without assigning IPv4" in lease.error


def test_dhcp_success_reports_ip_and_gateway(monkeypatch):
    _prepare_dhcp(monkeypatch, returncode=0, ip="10.0.0.77")
    lease = utils.request_dhcp_lease("eth0", timeout=1)
    assert lease.success
    assert lease.ip == "10.0.0.77"
    assert lease.gateway == "10.0.0.1"


def test_set_mac_checks_and_verifies_every_step(monkeypatch):
    commands = []
    monkeypatch.setattr(utils, "validate_interface", lambda iface: True)
    monkeypatch.setattr(utils, "run_subprocess", lambda cmd, **kwargs: (commands.append(cmd) or 0, "", ""))
    monkeypatch.setattr(utils, "get_iface_mac", lambda iface: "02:11:22:33:44:55")
    ok, error = utils.set_iface_mac("eth0", "02:11:22:33:44:55")
    assert ok and error is None
    assert commands == [
        ["ip", "link", "set", "dev", "eth0", "down"],
        ["ip", "link", "set", "dev", "eth0", "address", "02:11:22:33:44:55"],
        ["ip", "link", "set", "dev", "eth0", "up"],
    ]


def test_restore_permanent_mac_restores_network_manager(monkeypatch):
    state = utils.NetworkManagerState(
        available=True, managed=True, active_connection_uuid="uuid-1"
    )
    calls = []
    monkeypatch.setattr(utils, "validate_interface", lambda iface: True)
    monkeypatch.setattr(utils, "get_permanent_mac", lambda iface: "e8:80:88:37:94:89")
    monkeypatch.setattr(utils, "detach_network_manager", lambda iface: (state, None))
    monkeypatch.setattr(utils, "kill_process_on_iface", lambda *args: calls.append(args))
    monkeypatch.setattr(utils, "set_iface_mac", lambda iface, mac: (calls.append((iface, mac)) or True, None))
    monkeypatch.setattr(utils, "restore_network_manager", lambda iface, saved: (calls.append((iface, saved)) or True, None))
    success, mac, error = utils.restore_permanent_mac("eth0")
    assert success and error is None
    assert mac == "e8:80:88:37:94:89"
    assert ("eth0", mac) in calls
    assert ("eth0", state) in calls


def test_json_result_is_private_and_serializes_enums(tmp_path):
    from core.recon import NacType
    output = utils.save_json_result({"nac_type": NacType.OPEN}, str(tmp_path))
    assert os.stat(output).st_mode & 0o777 == 0o600
    assert '"OPEN"' in Path(output).read_text(encoding="utf-8")


def test_output_directory_rejects_symlink(tmp_path):
    real = tmp_path / "real"
    real.mkdir()
    link = tmp_path / "linked-output"
    link.symlink_to(real, target_is_directory=True)
    with pytest.raises(RuntimeError, match="Unsafe output directory"):
        utils.save_json_result({"status": "test"}, str(link))


def test_successful_dhcp_lease_cache_is_private_and_unpredictable(monkeypatch):
    _prepare_dhcp(monkeypatch, returncode=0, ip="10.0.0.77")
    lease = utils.request_dhcp_lease("eth0", timeout=1)
    paths = utils.get_cached_lease_paths("eth0")
    assert lease.success
    assert len(paths) == 1
    assert os.stat(paths[0]).st_mode & 0o777 == 0o600
    assert Path(paths[0]).name.startswith("nacleaver-dhclient4-")
    assert Path(paths[0]).name != "nacleaver-dhclient-eth0.leases"


def test_python_dependency_check_does_not_import_module(monkeypatch):
    calls = []
    monkeypatch.setattr(
        utils.importlib.util,
        "find_spec",
        lambda name: (calls.append(name) or (object() if name == "present" else None)),
    )
    assert utils.check_python_dependencies(["present", "missing"]) == {
        "present": True,
        "missing": False,
    }
    assert calls == ["present", "missing"]


def test_strict_config_loading_fails_closed(tmp_path):
    missing = tmp_path / "missing.yaml"
    with pytest.raises(ValueError, match="does not exist"):
        utils.load_config(missing, strict=True)

    invalid = tmp_path / "invalid.yaml"
    invalid.write_text("- not\n- a\n- mapping\n", encoding="utf-8")
    with pytest.raises(ValueError, match="top-level YAML"):
        utils.load_config(invalid, strict=True)


def test_root_output_is_returned_to_sudo_user(monkeypatch, tmp_path):
    calls = []
    monkeypatch.setattr(utils.os, "geteuid", lambda: 0)
    monkeypatch.setenv("SUDO_UID", "1001")
    monkeypatch.setenv("SUDO_GID", "1002")
    monkeypatch.setattr(utils.os, "chown", lambda path, uid, gid: calls.append((path, uid, gid)))
    target = tmp_path / "result.json"
    utils._restore_output_ownership(target)
    assert calls == [(target, 1001, 1002)]


def test_cleanup_removes_packet_rules_before_bridge(monkeypatch):
    commands = []
    utils.Cleanup.register_ebtables_rule(
        "broute", "BROUTING", ["-i", "eth0", "-p", "0x888e", "-j", "DROP"]
    )
    utils.Cleanup.register_bridge("nacleaver_br")
    monkeypatch.setattr(
        utils,
        "run_subprocess",
        lambda cmd, **kwargs: (commands.append(cmd) or 0, "", ""),
    )
    utils.Cleanup.run_all()
    assert commands[0][:5] == ["ebtables", "-t", "broute", "-D", "BROUTING"]
    assert commands[1] == ["ip", "link", "delete", "nacleaver_br"]


def test_relay_worker_is_journaled_and_stopped_before_bridge_cleanup(monkeypatch, tmp_path):
    utils.Cleanup._reset_memory()
    journal = utils.Cleanup.enable_journal(tmp_path)

    class Event:
        stopped = False

        def set(self):
            self.stopped = True

    class Process:
        pid = 55551
        alive = True

        def join(self, timeout):
            if event.stopped:
                self.alive = False

        def is_alive(self):
            return self.alive

    event = Event()
    process = Process()
    monkeypatch.setattr(
        utils.Cleanup, "_process_start_ticks",
        lambda pid: 12345 if process.alive else None,
    )
    utils.Cleanup.register_worker_process(process, event)
    assert json.loads(journal.read_text())["worker_processes"] == [
        {"pid": process.pid, "start_ticks": 12345}
    ]
    assert utils.Cleanup.run_all()
    assert event.stopped
    assert not journal.exists()
    utils.Cleanup._reset_memory()


def test_relay_health_rejects_a_stopped_forwarder():
    utils.Cleanup._reset_memory()

    class StoppedProcess:
        def is_alive(self):
            return False

    utils.Cleanup._worker_pids = {55553: 12345}
    utils.Cleanup._live_workers = [StoppedProcess()]
    assert not utils.Cleanup.relay_workers_healthy()
    utils.Cleanup._reset_memory()


def test_real_relay_worker_lifecycle_is_recoverable(tmp_path):
    utils.Cleanup._reset_memory()
    journal = utils.Cleanup.enable_journal(tmp_path)
    context = get_context("fork")
    stop_event = context.Event()
    worker = context.Process(target=_wait_for_stop, args=(stop_event,), daemon=True)
    worker.start()
    try:
        utils.Cleanup.register_worker_process(worker, stop_event)
        assert utils.Cleanup.relay_workers_healthy()
        assert journal.exists()
        assert utils.Cleanup.run_all()
        assert not worker.is_alive()
        assert not journal.exists()
    finally:
        stop_event.set()
        if worker.is_alive():
            worker.terminate()
            worker.join(timeout=2)
        utils.Cleanup._reset_memory()


def test_recovery_never_signals_reused_worker_pid(monkeypatch, tmp_path):
    utils.Cleanup._reset_memory()
    journal = utils.Cleanup.enable_journal(tmp_path)
    utils.Cleanup._worker_pids[55552] = 12345
    utils.Cleanup._sync_journal()
    utils.Cleanup._reset_memory()
    original_start_ticks = utils.Cleanup._process_start_ticks
    monkeypatch.setattr(
        utils.Cleanup,
        "_process_start_ticks",
        lambda pid: 99999 if pid == 55552 else original_start_ticks(pid),
    )
    original_kill = utils.os.kill

    def guarded_kill(pid, sig):
        assert pid != 55552
        return original_kill(pid, sig)

    monkeypatch.setattr(utils.os, "kill", guarded_kill)
    result = utils.Cleanup.recover_journals(tmp_path, force=True)
    assert result[0]["recovered"]
    assert not journal.exists()
    utils.Cleanup._reset_memory()


def test_cleanup_journal_is_private_atomic_and_removed_after_cleanup(monkeypatch, tmp_path):
    utils.Cleanup._reset_memory()
    commands = []
    journal = utils.Cleanup.enable_journal(tmp_path)
    utils.Cleanup.register_ebtables_rule(
        "broute", "BROUTING", ["-i", "eth0", "-p", "0x888e", "-j", "DROP"]
    )
    utils.Cleanup.register_bridge("nacleaver_br")
    assert journal.exists()
    assert os.stat(journal).st_mode & 0o777 == 0o600
    payload = json.loads(journal.read_text())
    assert payload["created_by"] == "NACleaver"
    assert payload["bridges"] == ["nacleaver_br"]

    monkeypatch.setattr(
        utils,
        "run_subprocess",
        lambda cmd, **kwargs: (commands.append(cmd) or 0, "", ""),
    )
    utils.Cleanup.run_all()
    assert not journal.exists()
    utils.Cleanup._reset_memory()


def test_recover_journal_replays_only_recorded_state(monkeypatch, tmp_path):
    utils.Cleanup._reset_memory()
    journal = utils.Cleanup.enable_journal(tmp_path)
    utils.Cleanup.register_bridge("nacleaver_br")
    utils.Cleanup._reset_memory()  # simulate a new process after an unclean exit
    commands = []
    monkeypatch.setattr(
        utils,
        "run_subprocess",
        lambda cmd, **kwargs: (commands.append(cmd) or 0, "", ""),
    )
    results = utils.Cleanup.recover_journals(tmp_path, force=True)
    assert results == [{
        "journal": str(journal),
        "recovered": True,
        "pid": os.getpid(),
    }]
    assert ["ip", "link", "delete", "nacleaver_br"] in commands
    assert not journal.exists()
    utils.Cleanup._reset_memory()


def test_recover_skips_live_process_without_force(tmp_path):
    utils.Cleanup._reset_memory()
    journal = utils.Cleanup.enable_journal(tmp_path)
    utils.Cleanup.register_bridge("nacleaver_br")
    utils.Cleanup._reset_memory()
    results = utils.Cleanup.recover_journals(tmp_path, force=False)
    assert results[0]["journal"] == str(journal)
    assert results[0]["skipped"] == "process is still running"
    assert journal.exists()
    journal.unlink()
    utils.Cleanup._reset_memory()


def test_recover_distinguishes_reused_pid_by_start_time(monkeypatch, tmp_path):
    utils.Cleanup._reset_memory()
    journal = utils.Cleanup.enable_journal(tmp_path)
    utils.Cleanup.register_bridge("nacleaver_br")
    payload = json.loads(journal.read_text())
    utils.Cleanup._reset_memory()
    monkeypatch.setattr(utils.Cleanup, "_process_is_alive", lambda pid: True)
    monkeypatch.setattr(
        utils.Cleanup,
        "_process_start_ticks",
        lambda pid: int(payload["process_start_ticks"]) + 1,
    )
    monkeypatch.setattr(utils, "run_subprocess", lambda *a, **k: (0, "", ""))
    result = utils.Cleanup.recover_journals(tmp_path)
    assert result[0]["recovered"]
    assert not journal.exists()
    utils.Cleanup._reset_memory()


def test_recovery_refuses_symlinked_journal(tmp_path):
    target = tmp_path / "outside.json"
    target.write_text("{}", encoding="utf-8")
    link = tmp_path / "state-999.json"
    link.symlink_to(target)
    result = utils.Cleanup.recover_journals(tmp_path, force=True)
    assert not result[0]["recovered"]
    assert "symlinked" in result[0]["error"]
