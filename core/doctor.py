import os
import platform
import socket
import sys
from dataclasses import dataclass, field
from pathlib import Path

from core.utils import (
    check_all_dependencies,
    check_python_dependencies,
    get_iface_ip,
    get_iface_ipv6s,
    get_iface_mac,
    get_iface_state,
    validate_interface,
)


_SOL_PACKET = 263
_PACKET_IGNORE_OUTGOING = 23
_ETH_P_ALL = 0x0003


@dataclass
class DoctorCheck:
    name: str
    success: bool
    required: bool
    details: str


@dataclass
class DoctorResult:
    interface: str
    mode: str
    ready: bool
    checks: list[DoctorCheck] = field(default_factory=list)
    python_executable: str = sys.executable
    python_version: str = platform.python_version()
    kernel: str = platform.release()


_MODE_TOOLS = {
    "recon": {"ip"},
    "mab": {"ip", "dhclient", "pkill"},
    "dot1x": {"ip", "pkill"},
    "relay": {"ip", "ebtables", "dhclient", "pkill"},
    "posture": {"ip"},
    "post": {"ip"},
    "all": {"ip", "dhclient", "pkill", "ebtables"},
}

_SCAPY_MODES = {"recon", "mab", "relay", "post", "all"}


def _carrier_state(iface: str) -> str:
    try:
        return Path(f"/sys/class/net/{iface}/carrier").read_text().strip()
    except OSError:
        return "unknown"


def _check_bind_to_device(iface: str) -> tuple[bool, str]:
    sock = None
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        bind_opt = getattr(socket, "SO_BINDTODEVICE", 25)
        sock.setsockopt(socket.SOL_SOCKET, bind_opt, iface.encode() + b"\0")
        return True, "SO_BINDTODEVICE accepted"
    except OSError as exc:
        return False, str(exc)
    finally:
        if sock is not None:
            sock.close()


def _check_packet_socket(iface: str, require_ignore_outgoing: bool) -> tuple[bool, str]:
    if not hasattr(socket, "AF_PACKET"):
        return False, "AF_PACKET is unavailable on this platform"
    sock = None
    try:
        sock = socket.socket(
            socket.AF_PACKET,
            socket.SOCK_RAW,
            socket.htons(_ETH_P_ALL),
        )
        sock.bind((iface, 0))
        if require_ignore_outgoing:
            sock.setsockopt(_SOL_PACKET, _PACKET_IGNORE_OUTGOING, 1)
        detail = "raw AF_PACKET socket accepted"
        if require_ignore_outgoing:
            detail += "; PACKET_IGNORE_OUTGOING accepted"
        return True, detail
    except OSError as exc:
        return False, str(exc)
    finally:
        if sock is not None:
            sock.close()


def _relay_worker_probe() -> None:
    """Importable target for Python versions using spawn or forkserver."""


def _check_relay_worker_start() -> tuple[bool, str]:
    from multiprocessing import Process

    worker = Process(target=_relay_worker_probe)
    started = False
    try:
        worker.start()
        started = True
        worker.join(timeout=3)
        if worker.is_alive():
            return False, "relay worker did not exit in time"
        return worker.exitcode == 0, f"relay worker exitcode={worker.exitcode}"
    except (OSError, RuntimeError, ValueError) as exc:
        return False, str(exc)
    finally:
        if started and worker.is_alive():
            worker.terminate()
            worker.join(timeout=1)


def run_doctor(
    iface: str,
    mode: str = "all",
    interface2: str | None = None,
) -> DoctorResult:
    if mode not in _MODE_TOOLS:
        raise ValueError(f"Unknown doctor mode: {mode}")

    checks: list[DoctorCheck] = []

    def add(name: str, success: bool, required: bool, details: str) -> None:
        checks.append(DoctorCheck(name, success, required, details))

    linux = platform.system() == "Linux"
    add("platform", linux, True, platform.platform())
    version_ok = sys.version_info >= (3, 10)
    add("python_version", version_ok, True, platform.python_version())
    add(
        "root_privileges",
        os.geteuid() == 0,
        True,
        f"effective_uid={os.geteuid()}",
    )

    iface_ok = validate_interface(iface)
    add("primary_interface", iface_ok, True, iface)
    if iface_ok:
        state = get_iface_state(iface)
        add("primary_link_state", state in {"up", "unknown"}, True, state)
        carrier = _carrier_state(iface)
        add("primary_carrier", carrier in {"1", "unknown"}, True, carrier)
        try:
            add("primary_mac", True, True, get_iface_mac(iface))
        except OSError as exc:
            add("primary_mac", False, True, str(exc))
        ip = get_iface_ip(iface)
        ipv6 = get_iface_ipv6s(iface)
        add(
            "primary_ipv4",
            ip is not None,
            False,
            ip or "not assigned",
        )
        add(
            "primary_ipv6",
            bool(ipv6),
            False,
            ", ".join(ipv6) or "not assigned",
        )
        add(
            "primary_network_address",
            bool(ip or ipv6),
            mode in {"posture", "post"},
            ip or (ipv6[0] if ipv6 else "not assigned"),
        )

    if mode in {"relay", "all"}:
        worker_ok, worker_detail = _check_relay_worker_start()
        add("relay_worker_start", worker_ok, True, worker_detail)
        second_ok = bool(interface2 and validate_interface(interface2))
        add("secondary_interface", second_ok, True, interface2 or "not supplied")
        if second_ok and interface2:
            state = get_iface_state(interface2)
            add("secondary_link_state", state in {"up", "unknown"}, True, state)
            add(
                "interfaces_distinct",
                interface2 != iface,
                True,
                f"{iface} != {interface2}",
            )

    tools = check_all_dependencies()
    for tool in sorted(_MODE_TOOLS[mode]):
        add("tool:" + tool, tools.get(tool, False), True, "available" if tools.get(tool) else "missing")

    if mode in {"dot1x", "all"}:
        wpa_ready = all(tools.get(name, False) for name in ("wpa_supplicant", "wpa_cli", "dhclient"))
        nm_ready = tools.get("nmcli", False)
        add(
            "dot1x_backend",
            wpa_ready or nm_ready,
            True,
            f"wpa_stack={wpa_ready}, nmcli={nm_ready}",
        )
        if wpa_ready:
            from core.dot1x import EAPMethod, probe_wpa_method_support

            teap_ok, teap_detail = probe_wpa_method_support(
                EAPMethod.TEAP_MSCHAPV2
            )
            add(
                "wpa_method:teap_mschapv2",
                teap_ok,
                False,
                teap_detail,
            )

    python_modules = ["scapy"] if mode in _SCAPY_MODES else []
    for module, available in check_python_dependencies(python_modules).items():
        add("python_module:" + module, available, True, "available" if available else "missing")

    if iface_ok:
        bind_ok, bind_detail = _check_bind_to_device(iface)
        add("interface_binding", bind_ok, True, bind_detail)
        packet_required = mode in _SCAPY_MODES
        packet_ok, packet_detail = _check_packet_socket(
            iface,
            require_ignore_outgoing=mode in {"relay", "all"},
        )
        add("packet_socket", packet_ok, packet_required, packet_detail)

    ready = all(check.success for check in checks if check.required)
    return DoctorResult(interface=iface, mode=mode, ready=ready, checks=checks)
