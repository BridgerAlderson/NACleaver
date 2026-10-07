import json
import importlib.util
import ipaddress
import logging
import os
import re
import shutil
import signal
# Centralized list-argv runner; shell execution is never enabled.
import subprocess  # nosec B404
import sys
import tempfile
import time
from dataclasses import asdict, dataclass, is_dataclass
from datetime import datetime
from enum import Enum
from pathlib import Path
from typing import Any

import netifaces
import yaml
from rich.console import Console
from rich.logging import RichHandler

console = Console()

_PROJECT_ROOT = Path(__file__).resolve().parent.parent
_IFACE_RE = re.compile(r"^[a-zA-Z0-9_.:-]{1,64}$")
_DEFAULT_STATE_DIR = Path("/run/nacleaver")
_LEASE_CACHE_PATHS: dict[str, list[str]] = {}


@dataclass
class NetworkManagerState:
    available: bool = False
    managed: bool = False
    active_connection_uuid: str | None = None
    active_connection_name: str | None = None


@dataclass
class DHCPLeaseResult:
    success: bool
    ip: str | None
    gateway: str | None
    returncode: int
    duration_sec: float
    error: str | None = None
    address_family: str = "ipv4"


def require_root() -> None:
    if os.geteuid() != 0:
        console.print("[bold red][!] NACleaver requires root privileges. Run with sudo.[/bold red]")
        sys.exit(1)


def validate_interface(iface: str) -> bool:
    return bool(_IFACE_RE.fullmatch(iface)) and Path(f"/sys/class/net/{iface}").exists()


def get_interfaces() -> list[str]:
    try:
        return sorted(
            iface for iface in os.listdir("/sys/class/net")
            if iface != "lo" and validate_interface(iface)
        )
    except OSError as exc:
        logging.getLogger("nacleaver").warning(f"Failed to list interfaces: {exc}")
        return []


def get_iface_mac(iface: str) -> str:
    path = Path(f"/sys/class/net/{iface}/address")
    if not path.exists():
        raise FileNotFoundError(f"Interface {iface} not found at {path}")
    return path.read_text().strip().lower()


def get_iface_ip(iface: str) -> str | None:
    ips = get_iface_ips(iface)
    return ips[0] if ips else None


def get_iface_ipv6s(iface: str, include_link_local: bool = False) -> list[str]:
    """Return usable IPv6 addresses, optionally including link-local addresses."""
    try:
        addrs = netifaces.ifaddresses(iface).get(netifaces.AF_INET6, [])
        usable: list[str] = []
        for entry in addrs:
            value = entry.get("addr")
            if not value:
                continue
            normalized = value.split("%", 1)[0]
            address = ipaddress.ip_address(normalized)
            if address.is_unspecified or address.is_loopback or address.is_multicast:
                continue
            if address.is_link_local and not include_link_local:
                continue
            usable.append(normalized)
        return usable
    except (ValueError, KeyError, OSError):
        return []


def get_iface_ipv6(iface: str) -> str | None:
    addresses = get_iface_ipv6s(iface)
    return addresses[0] if addresses else None


def get_iface_ips(iface: str) -> list[str]:
    """Return usable unicast IPv4 addresses currently assigned to *iface*."""
    try:
        addrs = netifaces.ifaddresses(iface).get(netifaces.AF_INET, [])
        usable = []
        for entry in addrs:
            value = entry.get("addr")
            if not value:
                continue
            address = ipaddress.ip_address(value)
            if (
                address.is_unspecified
                or address.is_loopback
                or address.is_link_local
                or address.is_multicast
            ):
                continue
            usable.append(value)
        return usable
    except (ValueError, KeyError, OSError):
        return []


def get_iface_netmask(iface: str, address: str | None = None) -> str | None:
    family = netifaces.AF_INET6 if address and ":" in address else netifaces.AF_INET
    try:
        inet = netifaces.ifaddresses(iface).get(family) or []
        if address:
            for entry in inet:
                candidate = str(entry.get("addr", "")).split("%", 1)[0]
                if candidate == address.split("%", 1)[0]:
                    netmask = entry.get("netmask")
                    if family == netifaces.AF_INET6 and netmask:
                        # netifaces commonly returns an IPv6 mask as "ffff:.../64".
                        if "/" in netmask:
                            return netmask.rsplit("/", 1)[1]
                        try:
                            mask_value = int(ipaddress.IPv6Address(netmask))
                            bits = f"{mask_value:0128b}"
                            if "01" in bits:
                                raise ValueError("non-contiguous IPv6 netmask")
                            return str(bits.count("1"))
                        except (ValueError, TypeError):
                            pass
                    return netmask
            return None
        for entry in inet:
            value = entry.get("addr")
            if value and value in get_iface_ips(iface):
                return entry.get("netmask")
    except (ValueError, KeyError, OSError):
        pass
    return None


def get_iface_state(iface: str) -> str:
    path = Path(f"/sys/class/net/{iface}/operstate")
    try:
        return path.read_text().strip()
    except OSError:
        return "unknown"


def validate_mac(mac: str) -> bool:
    return bool(re.fullmatch(r"([0-9a-fA-F]{2}:){5}[0-9a-fA-F]{2}", mac))


def normalize_mac(mac: str) -> str:
    clean = mac.replace(":", "").replace("-", "").lower()
    if len(clean) != 12 or not re.fullmatch(r"[0-9a-f]{12}", clean):
        raise ValueError(f"Invalid MAC address: {mac}")
    return ":".join(clean[i:i + 2] for i in range(0, 12, 2))


def is_multicast_mac(mac: str) -> bool:
    try:
        return bool(int(normalize_mac(mac)[:2], 16) & 0x01)
    except ValueError:
        return True


def is_locally_administered_mac(mac: str) -> bool:
    try:
        return bool(int(normalize_mac(mac)[:2], 16) & 0x02)
    except ValueError:
        return True


def check_dependency(cmd: str) -> bool:
    return shutil.which(cmd) is not None


def check_all_dependencies() -> dict[str, bool]:
    tools = [
        "wpa_supplicant", "wpa_cli", "nmcli", "dhclient",
        "ip", "ebtables", "pkill", "ethtool",
    ]
    return {tool: check_dependency(tool) for tool in tools}


def check_python_dependencies(modules: list[str]) -> dict[str, bool]:
    """Check import availability without importing privileged network modules."""
    results: dict[str, bool] = {}
    for module in modules:
        try:
            results[module] = importlib.util.find_spec(module) is not None
        except (ImportError, AttributeError, ValueError):
            results[module] = False
    return results


def load_config(
    path: str | Path | None = None,
    *,
    strict: bool = False,
) -> dict[str, Any]:
    """Load runtime configuration, optionally failing closed on invalid input."""
    config_path = Path(path) if path else _PROJECT_ROOT / "config.yaml"
    if not config_path.exists():
        if strict:
            raise ValueError(f"configuration file does not exist: {config_path}")
        return {}
    try:
        with config_path.open(encoding="utf-8") as handle:
            data = yaml.safe_load(handle) or {}
        if not isinstance(data, dict):
            raise ValueError("top-level YAML value must be a mapping")
        return data
    except (OSError, ValueError, yaml.YAMLError) as exc:
        if strict:
            raise ValueError(f"unable to load configuration {config_path}: {exc}") from exc
        logging.getLogger("nacleaver").warning(f"Unable to load {config_path}: {exc}")
        return {}


def config_value(config: dict[str, Any], section: str, key: str, default: Any) -> Any:
    section_value = config.get(section, {})
    if not isinstance(section_value, dict):
        return default
    value = section_value.get(key, default)
    return default if value is None else value


def _restore_output_ownership(path: str | Path) -> None:
    """Return root-created artifacts to the user who invoked sudo, when known."""
    if os.geteuid() != 0:
        return
    uid_value = os.environ.get("SUDO_UID")
    gid_value = os.environ.get("SUDO_GID")
    if not uid_value or not gid_value:
        return
    try:
        uid = int(uid_value)
        gid = int(gid_value)
    except ValueError:
        return
    if uid <= 0 or gid < 0:
        return
    try:
        os.chown(path, uid, gid)
    except OSError as exc:
        logging.getLogger("nacleaver").debug(
            f"Unable to return artifact ownership for {path}: {exc}"
        )


def _prepare_output_dir(output_dir: str) -> Path:
    directory = Path(output_dir)
    existed = directory.exists()
    directory.mkdir(parents=True, exist_ok=True, mode=0o700)
    if directory.is_symlink() or not directory.is_dir():
        raise RuntimeError(f"Unsafe output directory: {directory}")
    if not existed:
        os.chmod(directory, 0o700)
        _restore_output_ownership(directory)
    return directory


def _create_private_file(path: Path) -> None:
    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL
    if hasattr(os, "O_NOFOLLOW"):
        flags |= os.O_NOFOLLOW
    fd = os.open(path, flags, 0o600)
    os.close(fd)
    _restore_output_ownership(path)


def setup_logging(verbose: bool, output_dir: str = "output") -> logging.Logger:
    directory = _prepare_output_dir(output_dir)
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S_%f")
    log_file = directory / f"nacleaver_{timestamp}.log"

    logger = logging.getLogger("nacleaver")
    logger.setLevel(logging.DEBUG if verbose else logging.INFO)
    for handler in logger.handlers:
        handler.close()
    logger.handlers.clear()

    rich_handler = RichHandler(rich_tracebacks=True, markup=True, show_path=False)
    rich_handler.setLevel(logging.DEBUG if verbose else logging.INFO)
    logger.addHandler(rich_handler)

    _create_private_file(log_file)
    file_handler = logging.FileHandler(log_file)
    file_handler.setLevel(logging.DEBUG)
    file_handler.setFormatter(logging.Formatter(
        "%(asctime)s - %(name)s - %(levelname)s - %(message)s"
    ))
    logger.addHandler(file_handler)
    return logger


def save_json_result(result: dict, output_dir: str = "output") -> str:
    directory = _prepare_output_dir(output_dir)
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S_%f")
    output_path = directory / f"nacleaver_{timestamp}.json"

    def default_serializer(obj):
        if is_dataclass(obj):
            return asdict(obj)
        if isinstance(obj, Enum):
            return obj.name
        if hasattr(obj, "__dict__"):
            return obj.__dict__
        return str(obj)

    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL
    if hasattr(os, "O_NOFOLLOW"):
        flags |= os.O_NOFOLLOW
    output_fd = os.open(output_path, flags, 0o600)
    with os.fdopen(output_fd, "w", encoding="utf-8") as handle:
        json.dump(result, handle, indent=2, default=default_serializer)
    _restore_output_ownership(output_path)
    return str(output_path)


def kill_process_on_iface(process_name: str, iface: str) -> None:
    if not validate_interface(iface):
        return
    run_subprocess(
        ["pkill", "-f", f"{re.escape(process_name)}.*{re.escape(iface)}"],
    )


def run_subprocess(cmd: list[str], timeout: int = 10) -> tuple[int, str, str]:
    try:
        # Every call site passes a list; user-controlled shell strings are never used.
        result = subprocess.run(  # nosec B603
            cmd, capture_output=True, text=True, timeout=timeout, check=False
        )
        return result.returncode, result.stdout, result.stderr
    except subprocess.TimeoutExpired as exc:
        stdout = exc.stdout.decode(errors="replace") if isinstance(exc.stdout, bytes) else (exc.stdout or "")
        stderr = exc.stderr.decode(errors="replace") if isinstance(exc.stderr, bytes) else (exc.stderr or "")
        return 124, stdout, stderr or "timeout"
    except PermissionError:
        return 126, "", "permission denied"
    except OSError as exc:
        return 1, "", str(exc)


def get_default_interface() -> str | None:
    rc, out, _ = run_subprocess(["ip", "route", "show", "default"])
    if rc != 0:
        return None
    for line in out.splitlines():
        parts = line.split()
        if parts and parts[0] == "default":
            try:
                return parts[parts.index("dev") + 1]
            except (ValueError, IndexError):
                continue
    return None


def get_iface_gateway(iface: str) -> str | None:
    rc, out, _ = run_subprocess(["ip", "-4", "route", "show", "dev", iface])
    if rc != 0:
        return None
    for line in out.splitlines():
        parts = line.split()
        if not parts or parts[0] != "default":
            continue
        try:
            return parts[parts.index("via") + 1]
        except (ValueError, IndexError):
            return None
    return None


def get_iface_gateway6(iface: str) -> str | None:
    rc, out, _ = run_subprocess(["ip", "-6", "route", "show", "default", "dev", iface])
    if rc != 0:
        return None
    for line in out.splitlines():
        parts = line.split()
        if not parts or parts[0] != "default":
            continue
        try:
            return parts[parts.index("via") + 1]
        except (ValueError, IndexError):
            return None
    return None


def get_permanent_mac(iface: str) -> str:
    """Return the hardware MAC when the driver exposes it, otherwise current MAC."""
    if not validate_interface(iface):
        raise ValueError(f"Invalid or missing interface: {iface}")

    rc, out, _ = run_subprocess(["ip", "-details", "link", "show", "dev", iface])
    if rc == 0:
        match = re.search(r"\bpermaddr\s+([0-9a-fA-F:]{17})\b", out)
        if match:
            return match.group(1).lower()

    if check_dependency("ethtool"):
        rc, out, _ = run_subprocess(["ethtool", "-P", iface])
        if rc == 0:
            match = re.search(r"([0-9a-fA-F:]{17})", out)
            if match:
                return match.group(1).lower()
    return get_iface_mac(iface)


def get_network_manager_state(iface: str) -> NetworkManagerState:
    if not check_dependency("nmcli") or not validate_interface(iface):
        return NetworkManagerState()

    rc, managed, _ = run_subprocess(["nmcli", "-g", "GENERAL.MANAGED", "device", "show", iface])
    if rc != 0:
        return NetworkManagerState()

    def field(name: str) -> str | None:
        field_rc, value, _ = run_subprocess(["nmcli", "-g", name, "device", "show", iface])
        if field_rc != 0:
            return None
        cleaned = value.strip()
        return None if not cleaned or cleaned == "--" else cleaned

    return NetworkManagerState(
        available=True,
        managed=managed.strip().lower() in {"yes", "true", "1"},
        active_connection_uuid=field("GENERAL.CON-UUID"),
        active_connection_name=field("GENERAL.CONNECTION"),
    )


def detach_network_manager(iface: str) -> tuple[NetworkManagerState, str | None]:
    """Temporarily hand an interface from NetworkManager to NACleaver."""
    state = get_network_manager_state(iface)
    if not state.available or not state.managed:
        return state, None

    if state.active_connection_uuid:
        rc, _, err = run_subprocess(["nmcli", "device", "disconnect", iface], timeout=15)
        if rc != 0:
            return state, f"NetworkManager disconnect failed: {err.strip()}"

    rc, _, err = run_subprocess(["nmcli", "device", "set", iface, "managed", "no"])
    if rc != 0:
        return state, f"Unable to mark {iface} unmanaged: {err.strip()}"
    return state, None


def restore_network_manager(iface: str, state: NetworkManagerState) -> tuple[bool, str | None]:
    if not state.available or not state.managed:
        return True, None

    rc, _, err = run_subprocess(["nmcli", "device", "set", iface, "managed", "yes"])
    if rc != 0:
        return False, f"Unable to return {iface} to NetworkManager: {err.strip()}"

    if state.active_connection_uuid:
        rc, _, err = run_subprocess([
            "nmcli", "connection", "up", "uuid", state.active_connection_uuid, "ifname", iface,
        ], timeout=30)
        if rc != 0:
            connection = state.active_connection_name or state.active_connection_uuid
            return False, f"Unable to reactivate {connection}: {err.strip()}"
    return True, None


def set_iface_mac(iface: str, mac: str) -> tuple[bool, str | None]:
    """Set and verify an interface MAC, checking every link operation."""
    if not validate_interface(iface):
        return False, f"Invalid or missing interface: {iface}"
    if not validate_mac(mac):
        return False, f"Invalid MAC address: {mac}"

    rc, _, err = run_subprocess(["ip", "link", "set", "dev", iface, "down"])
    if rc != 0:
        return False, f"Unable to bring {iface} down: {err.strip()}"

    rc, _, err = run_subprocess(["ip", "link", "set", "dev", iface, "address", mac])
    if rc != 0:
        run_subprocess(["ip", "link", "set", "dev", iface, "up"])
        return False, f"Unable to set MAC on {iface}: {err.strip()}"

    rc, _, err = run_subprocess(["ip", "link", "set", "dev", iface, "up"])
    if rc != 0:
        return False, f"Unable to bring {iface} up: {err.strip()}"

    try:
        current = get_iface_mac(iface)
    except (OSError, ValueError) as exc:
        return False, f"Unable to verify MAC on {iface}: {exc}"
    if normalize_mac(current) != normalize_mac(mac):
        return False, f"MAC verification failed: got {current}, expected {mac}"
    return True, None



def restore_permanent_mac(iface: str) -> tuple[bool, str | None, str | None]:
    """Explicitly restore the driver-reported permanent MAC and prior NM profile."""
    if not validate_interface(iface):
        return False, None, f"Invalid or missing interface: {iface}"
    try:
        permanent_mac = get_permanent_mac(iface)
    except (OSError, ValueError) as exc:
        return False, None, f"Unable to determine permanent MAC: {exc}"

    state, detach_error = detach_network_manager(iface)
    if detach_error:
        restore_network_manager(iface, state)
        return False, permanent_mac, detach_error

    kill_process_on_iface("wpa_supplicant", iface)
    kill_process_on_iface("dhclient", iface)
    changed, mac_error = set_iface_mac(iface, permanent_mac)
    nm_restored, nm_error = restore_network_manager(iface, state)

    errors = [error for error in (mac_error, nm_error) if error]
    return changed and nm_restored, permanent_mac, "; ".join(errors) or None


def get_cached_lease_paths(iface: str) -> list[str]:
    """Return live, process-local private lease files for post-auth parsing."""
    return [
        path for path in _LEASE_CACHE_PATHS.get(iface, [])
        if os.path.isfile(path)
    ]


def _dhclient_temp_paths(family: str) -> tuple[str, str]:
    """Create private, unpredictable paths suitable for dhclient state files."""
    pid_fd, pid_path = tempfile.mkstemp(
        prefix=f"nacleaver-dhclient{family}-", suffix=".pid"
    )
    lease_fd, lease_path = tempfile.mkstemp(
        prefix=f"nacleaver-dhclient{family}-", suffix=".leases"
    )
    os.close(pid_fd)
    os.close(lease_fd)
    # dhclient creates and exclusively manages its own PID file. The randomized
    # name remains unguessable; removing the empty mkstemp file avoids parser
    # differences between dhclient versions.
    os.remove(pid_path)
    return pid_path, lease_path


def _remove_temp_path(path: str) -> None:
    try:
        os.remove(path)
    except FileNotFoundError:
        Cleanup.unregister_temp_file(path)
    except OSError:
        return
    else:
        Cleanup.unregister_temp_file(path)

def request_dhcp_lease(iface: str, timeout: int = 30) -> DHCPLeaseResult:
    """Obtain a DHCPv4 lease with isolated pid and lease files."""
    start = time.monotonic()
    if not validate_interface(iface):
        return DHCPLeaseResult(False, None, None, 1, 0.0, f"Invalid interface: {iface}")
    if not check_dependency("dhclient"):
        return DHCPLeaseResult(False, None, None, 127, 0.0, "dhclient is not installed")

    pid_path, lease_path = _dhclient_temp_paths("4")
    Cleanup.register_temp_file(pid_path)
    Cleanup.register_temp_file(lease_path)
    kill_process_on_iface("dhclient", iface)
    rc, stdout, stderr = run_subprocess([
        "dhclient", "-4", "-v", "-1", "-pf", pid_path, "-lf", lease_path, iface,
    ], timeout=max(1, int(timeout)))

    ip = get_iface_ip(iface)
    gateway = get_iface_gateway(iface)
    keep_lease = rc == 0 and bool(ip) and os.path.exists(lease_path)
    if keep_lease:
        _LEASE_CACHE_PATHS.setdefault(iface, []).append(lease_path)
    _remove_temp_path(pid_path)
    if not keep_lease:
        _remove_temp_path(lease_path)

    duration = time.monotonic() - start
    if rc != 0:
        detail = (stderr or stdout or f"dhclient exited with status {rc}").strip()
        return DHCPLeaseResult(False, None, None, rc, duration, detail)
    if not ip:
        return DHCPLeaseResult(False, None, gateway, rc, duration, "DHCP completed without assigning IPv4")
    return DHCPLeaseResult(True, ip, gateway, rc, duration)


def request_dhcp6_lease(iface: str, timeout: int = 30) -> DHCPLeaseResult:
    """Obtain or observe a usable IPv6 address using an isolated DHCPv6 client."""
    start = time.monotonic()
    if not validate_interface(iface):
        return DHCPLeaseResult(
            False, None, None, 1, 0.0, f"Invalid interface: {iface}", "ipv6"
        )

    # SLAAC may already have completed after authorization; retain it as
    # address-stage evidence and let interface-bound verification decide access.
    existing = get_iface_ipv6(iface)
    if existing:
        return DHCPLeaseResult(
            True,
            existing,
            get_iface_gateway6(iface),
            0,
            time.monotonic() - start,
            address_family="ipv6",
        )
    if not check_dependency("dhclient"):
        return DHCPLeaseResult(
            False, None, None, 127, time.monotonic() - start,
            "dhclient is not installed and no SLAAC address is present", "ipv6"
        )

    pid_path, lease_path = _dhclient_temp_paths("6")
    Cleanup.register_temp_file(pid_path)
    Cleanup.register_temp_file(lease_path)
    kill_process_on_iface("dhclient", iface)
    rc, stdout, stderr = run_subprocess([
        "dhclient", "-6", "-v", "-1", "-pf", pid_path, "-lf", lease_path, iface,
    ], timeout=max(1, int(timeout)))
    ip = get_iface_ipv6(iface)
    gateway = get_iface_gateway6(iface)
    keep_lease = bool(ip) and os.path.exists(lease_path)
    if keep_lease:
        _LEASE_CACHE_PATHS.setdefault(iface, []).append(lease_path)
    _remove_temp_path(pid_path)
    if not keep_lease:
        _remove_temp_path(lease_path)
    duration = time.monotonic() - start
    if rc != 0 and not ip:
        detail = (stderr or stdout or f"dhclient -6 exited with status {rc}").strip()
        return DHCPLeaseResult(False, None, gateway, rc, duration, detail, "ipv6")
    if not ip:
        return DHCPLeaseResult(
            False,
            None,
            gateway,
            rc,
            duration,
            "DHCPv6 completed without assigning usable IPv6",
            "ipv6",
        )
    return DHCPLeaseResult(True, ip, gateway, rc, duration, address_family="ipv6")


def request_network_lease(iface: str, timeout: int = 30) -> DHCPLeaseResult:
    """Try IPv4 and then IPv6 addressing, preserving both failure reasons."""
    started = time.monotonic()
    ipv4 = request_dhcp_lease(iface, timeout=timeout)
    if ipv4.success:
        return ipv4
    ipv6 = request_dhcp6_lease(iface, timeout=timeout)
    if ipv6.success:
        ipv6.duration_sec = time.monotonic() - started
        return ipv6
    return DHCPLeaseResult(
        False,
        None,
        ipv6.gateway or ipv4.gateway,
        ipv6.returncode if ipv6.returncode != 0 else ipv4.returncode,
        time.monotonic() - started,
        f"IPv4: {ipv4.error or 'failed'}; IPv6: {ipv6.error or 'failed'}",
        "dual",
    )


def ip_to_network(ip: str, netmask: str) -> str:
    """Return CIDR notation network string, e.g. '10.0.0.0/24'."""
    return str(ipaddress.ip_network(f"{ip}/{netmask}", strict=False))


class Cleanup:
    _original_macs: dict[str, str] = {}
    _nm_states: dict[str, NetworkManagerState] = {}
    _bridges: list[str] = []
    _nm_connections: list[str] = []
    _temp_files: list[str] = []
    _ebtables_rules: list[tuple[str, str, tuple[str, ...]]] = []
    _worker_pids: dict[int, int] = {}
    _live_workers: list[Any] = []
    _worker_stop_events: list[Any] = []
    _restore_mac_enabled: bool = True
    _running: bool = False
    _journal_path: Path | None = None

    @classmethod
    def _state_payload(cls) -> dict[str, Any]:
        return {
            "version": 1,
            "pid": os.getpid(),
            "process_start_ticks": cls._process_start_ticks(os.getpid()),
            "created_by": "NACleaver",
            "original_macs": dict(cls._original_macs),
            "network_manager": {
                iface: asdict(state) for iface, state in cls._nm_states.items()
            },
            "bridges": list(cls._bridges),
            "nm_connections": list(cls._nm_connections),
            "temp_files": list(cls._temp_files),
            "ebtables_rules": [
                {"table": table, "chain": chain, "rule": list(rule)}
                for table, chain, rule in cls._ebtables_rules
            ],
            "worker_processes": [
                {"pid": pid, "start_ticks": ticks}
                for pid, ticks in cls._worker_pids.items()
            ],
            "restore_mac_enabled": cls._restore_mac_enabled,
        }

    @classmethod
    def _has_tracked_state(cls) -> bool:
        return bool(
            cls._original_macs
            or cls._nm_states
            or cls._bridges
            or cls._nm_connections
            or cls._temp_files
            or cls._ebtables_rules
            or cls._worker_pids
        )

    @classmethod
    def enable_journal(cls, state_dir: str | Path | None = None) -> Path:
        """Enable an atomic root-only recovery journal for destructive state."""
        directory = Path(state_dir) if state_dir is not None else _DEFAULT_STATE_DIR
        directory.mkdir(parents=True, exist_ok=True, mode=0o700)
        if directory.is_symlink():
            raise RuntimeError(f"Refusing symlinked cleanup state directory: {directory}")
        stat_result = directory.stat()
        if stat_result.st_uid != os.geteuid():
            raise RuntimeError(f"Cleanup state directory is not owned by the current user: {directory}")
        if stat_result.st_mode & 0o077:
            os.chmod(directory, 0o700)
        cls._journal_path = directory / f"state-{os.getpid()}.json"
        cls._sync_journal()
        return cls._journal_path

    @classmethod
    def _sync_journal(cls) -> None:
        if cls._journal_path is None:
            return
        if not cls._has_tracked_state():
            try:
                cls._journal_path.unlink()
            except FileNotFoundError:
                pass
            else:
                if hasattr(os, "O_DIRECTORY"):
                    directory_fd = os.open(
                        cls._journal_path.parent, os.O_RDONLY | os.O_DIRECTORY
                    )
                    try:
                        os.fsync(directory_fd)
                    finally:
                        os.close(directory_fd)
            return
        payload = cls._state_payload()
        temporary = cls._journal_path.with_name(
            f".{cls._journal_path.name}.{time.monotonic_ns()}.tmp"
        )
        flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL
        if hasattr(os, "O_NOFOLLOW"):
            flags |= os.O_NOFOLLOW
        fd = os.open(temporary, flags, 0o600)
        try:
            with os.fdopen(fd, "w", encoding="utf-8") as handle:
                json.dump(payload, handle, indent=2)
                handle.flush()
                os.fsync(handle.fileno())
            os.replace(temporary, cls._journal_path)
            if hasattr(os, "O_DIRECTORY"):
                directory_fd = os.open(cls._journal_path.parent, os.O_RDONLY | os.O_DIRECTORY)
                try:
                    os.fsync(directory_fd)
                finally:
                    os.close(directory_fd)
        finally:
            try:
                temporary.unlink()
            except FileNotFoundError:
                pass

    @staticmethod
    def _process_is_alive(pid: int) -> bool:
        if pid <= 0:
            return False
        try:
            os.kill(pid, 0)
            return True
        except ProcessLookupError:
            return False
        except PermissionError:
            return True

    @staticmethod
    def _process_start_ticks(pid: int) -> int | None:
        try:
            # Field 22 follows a parenthesized comm value that may contain spaces.
            fields = Path(f"/proc/{pid}/stat").read_text().rsplit(")", 1)[1].split()
            if fields[0] in {"Z", "X"}:
                return None
            return int(fields[19])
        except (OSError, ValueError, IndexError):
            return None

    @classmethod
    def _reset_memory(cls) -> None:
        cls._original_macs = {}
        cls._nm_states = {}
        cls._bridges = []
        cls._nm_connections = []
        cls._temp_files = []
        cls._ebtables_rules = []
        cls._worker_pids = {}
        cls._live_workers = []
        cls._worker_stop_events = []
        cls._restore_mac_enabled = True
        cls._running = False
        cls._journal_path = None
        _LEASE_CACHE_PATHS.clear()

    @classmethod
    def _load_journal(cls, path: Path, payload: dict[str, Any]) -> None:
        if payload.get("version") != 1 or payload.get("created_by") != "NACleaver":
            raise ValueError("unsupported or foreign cleanup journal")
        original_macs = payload.get("original_macs", {})
        nm_states = payload.get("network_manager", {})
        bridges = payload.get("bridges", [])
        connections = payload.get("nm_connections", [])
        temp_files = payload.get("temp_files", [])
        rules = payload.get("ebtables_rules", [])
        workers = payload.get("worker_processes", [])
        if not isinstance(original_macs, dict) or not isinstance(nm_states, dict):
            raise ValueError("invalid interface state in cleanup journal")
        if not all(isinstance(value, list) for value in (bridges, connections, temp_files, rules, workers)):
            raise ValueError("invalid list state in cleanup journal")

        cls._reset_memory()
        for iface, mac in original_macs.items():
            if (
                not isinstance(iface, str)
                or not _IFACE_RE.fullmatch(iface)
                or not validate_mac(str(mac))
            ):
                raise ValueError("invalid MAC recovery record")
            cls._original_macs[iface] = normalize_mac(str(mac))
        for iface, state in nm_states.items():
            if not isinstance(iface, str) or not isinstance(state, dict):
                raise ValueError("invalid NetworkManager recovery record")
            if not _IFACE_RE.fullmatch(iface):
                raise ValueError("invalid NetworkManager interface record")
            available = state.get("available", False)
            managed = state.get("managed", False)
            connection_uuid = state.get("active_connection_uuid")
            connection_name = state.get("active_connection_name")
            if not isinstance(available, bool) or not isinstance(managed, bool):
                raise ValueError("invalid NetworkManager boolean recovery state")
            if connection_uuid is not None and not isinstance(connection_uuid, str):
                raise ValueError("invalid NetworkManager UUID recovery state")
            if connection_name is not None and not isinstance(connection_name, str):
                raise ValueError("invalid NetworkManager name recovery state")
            cls._nm_states[iface] = NetworkManagerState(
                available=available,
                managed=managed,
                active_connection_uuid=connection_uuid,
                active_connection_name=connection_name,
            )
        for bridge in bridges:
            if not isinstance(bridge, str) or not re.fullmatch(r"[A-Za-z0-9_.-]{1,15}", bridge):
                raise ValueError("invalid bridge recovery record")
            cls._bridges.append(bridge)
        if any(not isinstance(name, str) or not name for name in connections):
            raise ValueError("invalid NetworkManager connection recovery record")
        cls._nm_connections = list(connections)
        temp_root = Path(tempfile.gettempdir()).resolve()
        for item in temp_files:
            if not isinstance(item, str):
                raise ValueError("invalid temporary file recovery record")
            candidate = Path(item)
            if (
                candidate.parent.resolve() != temp_root
                or not candidate.name.startswith("nacleaver-")
            ):
                raise ValueError("invalid temporary file recovery record")
        cls._temp_files = list(temp_files)
        for rule in rules:
            if not isinstance(rule, dict):
                raise ValueError("invalid ebtables recovery record")
            table = rule.get("table")
            chain = rule.get("chain")
            arguments = rule.get("rule")
            if (
                table not in {"filter", "nat", "broute"}
                or not isinstance(chain, str)
                or not re.fullmatch(r"[A-Za-z0-9_-]{1,32}", chain)
                or not isinstance(arguments, list)
                or any(not isinstance(item, str) for item in arguments)
            ):
                raise ValueError("invalid ebtables recovery record")
            cls._ebtables_rules.append((table, chain, tuple(arguments)))
        for worker in workers:
            if not isinstance(worker, dict):
                raise ValueError("invalid relay worker recovery record")
            pid = worker.get("pid")
            ticks = worker.get("start_ticks")
            if type(pid) is not int or type(ticks) is not int or pid <= 1 or ticks <= 0:
                raise ValueError("invalid relay worker recovery record")
            cls._worker_pids[pid] = ticks
        cls._restore_mac_enabled = bool(payload.get("restore_mac_enabled", True))
        cls._journal_path = path

    @classmethod
    def recover_journals(
        cls,
        state_dir: str | Path | None = None,
        force: bool = False,
    ) -> list[dict[str, Any]]:
        """Recover stale state journals and return an auditable result per file."""
        directory = Path(state_dir) if state_dir is not None else _DEFAULT_STATE_DIR
        if not directory.exists():
            return []
        if directory.is_symlink() or directory.stat().st_uid != os.geteuid():
            raise RuntimeError(f"Unsafe cleanup state directory: {directory}")
        results: list[dict[str, Any]] = []
        for path in sorted(directory.glob("state-*.json")):
            record: dict[str, Any] = {"journal": str(path), "recovered": False}
            try:
                if path.is_symlink():
                    raise ValueError("refusing symlinked cleanup journal")
                stat_result = path.stat()
                if stat_result.st_uid != os.geteuid() or stat_result.st_mode & 0o077:
                    raise ValueError("journal ownership or permissions are unsafe")
                with path.open(encoding="utf-8") as handle:
                    payload = json.load(handle)
                pid = int(payload.get("pid", -1))
                record["pid"] = pid
                recorded_start = payload.get("process_start_ticks")
                current_start = cls._process_start_ticks(pid)
                same_process = cls._process_is_alive(pid) and (
                    recorded_start is None
                    or (current_start is not None and int(recorded_start) == current_start)
                )
                if not force and same_process:
                    record["skipped"] = "process is still running"
                    results.append(record)
                    continue
                cls._load_journal(path, payload)
                cls.run_all()
                record["recovered"] = not path.exists()
                if path.exists():
                    record["error"] = "one or more cleanup operations failed"
            except (OSError, ValueError, TypeError, json.JSONDecodeError) as exc:
                record["error"] = str(exc)
            finally:
                cls._reset_memory()
            results.append(record)
        return results

    @classmethod
    def register_mac(cls, iface: str, original_mac: str) -> None:
        cls._original_macs.setdefault(iface, original_mac)
        cls._sync_journal()

    @classmethod
    def register_network_manager(cls, iface: str, state: NetworkManagerState) -> None:
        cls._nm_states.setdefault(iface, state)
        cls._sync_journal()

    @classmethod
    def register_bridge(cls, bridge_name: str) -> None:
        if bridge_name not in cls._bridges:
            cls._bridges.append(bridge_name)
            cls._sync_journal()

    @classmethod
    def unregister_bridge(cls, bridge_name: str) -> None:
        if bridge_name in cls._bridges:
            cls._bridges.remove(bridge_name)
            cls._sync_journal()

    @classmethod
    def register_nm_connection(cls, connection_name: str) -> None:
        if connection_name not in cls._nm_connections:
            cls._nm_connections.append(connection_name)
            cls._sync_journal()

    @classmethod
    def unregister_nm_connection(cls, connection_name: str) -> None:
        if connection_name in cls._nm_connections:
            cls._nm_connections.remove(connection_name)
            cls._sync_journal()

    @classmethod
    def register_temp_file(cls, path: str) -> None:
        if path not in cls._temp_files:
            cls._temp_files.append(path)
            cls._sync_journal()

    @classmethod
    def unregister_temp_file(cls, path: str) -> None:
        if path in cls._temp_files:
            cls._temp_files.remove(path)
            cls._sync_journal()

    @classmethod
    def register_worker_process(cls, process: Any, stop_event: Any) -> None:
        """Keep a relay worker alive through verification and recover its PID after a crash."""
        pid = process.pid
        ticks = cls._process_start_ticks(pid) if isinstance(pid, int) else None
        if not pid or ticks is None:
            raise RuntimeError("Unable to identify relay worker for safe crash recovery")
        cls._worker_pids[pid] = ticks
        cls._live_workers.append(process)
        if stop_event not in cls._worker_stop_events:
            cls._worker_stop_events.append(stop_event)
        cls._sync_journal()

    @classmethod
    def relay_workers_healthy(cls) -> bool:
        return len(cls._live_workers) == len(cls._worker_pids) and all(
            process.is_alive() for process in cls._live_workers
        )

    @classmethod
    def stop_worker_processes(cls) -> bool:
        """Stop active relay workers before removing packet rules or the bridge."""
        logger = logging.getLogger("nacleaver")
        for event in cls._worker_stop_events:
            event.set()
        for process in cls._live_workers:
            process.join(timeout=3)
            if process.is_alive():
                process.terminate()
                process.join(timeout=1)
            if process.is_alive():
                process.kill()
                process.join(timeout=1)
        cls._live_workers = []
        cls._worker_stop_events = []

        for pid, ticks in list(cls._worker_pids.items()):
            current_ticks = cls._process_start_ticks(pid)
            if current_ticks is None or current_ticks != ticks:
                cls._worker_pids.pop(pid, None)
                continue
            # This branch handles children orphaned by a crashed parent. A PID
            # is never signaled unless its kernel start time still matches.
            try:
                os.kill(pid, signal.SIGTERM)
                deadline = time.monotonic() + 2
                while time.monotonic() < deadline and cls._process_start_ticks(pid) == ticks:
                    time.sleep(0.1)
                if cls._process_start_ticks(pid) == ticks:
                    os.kill(pid, signal.SIGKILL)
                    deadline = time.monotonic() + 1
                    while time.monotonic() < deadline and cls._process_start_ticks(pid) == ticks:
                        time.sleep(0.05)
            except ProcessLookupError:
                pass
            except OSError as exc:
                logger.error(f"Cleanup: relay worker {pid} could not be stopped: {exc}")
                continue
            if cls._process_start_ticks(pid) != ticks:
                cls._worker_pids.pop(pid, None)
            else:
                logger.error(f"Cleanup: relay worker {pid} is still present")
        cls._sync_journal()
        return not cls._worker_pids

    @classmethod
    def capture_interface(cls, iface: str) -> tuple[bool, str | None]:
        """Record interface/NM state without taking it away from NetworkManager."""
        if not validate_interface(iface):
            return False, f"Invalid or missing interface: {iface}"
        try:
            cls.register_mac(iface, get_iface_mac(iface))
        except OSError as exc:
            return False, f"Unable to read MAC for {iface}: {exc}"
        cls.register_network_manager(iface, get_network_manager_state(iface))
        return True, None

    @classmethod
    def register_ebtables_rule(cls, table: str, chain: str, rule: list[str]) -> None:
        entry = (table, chain, tuple(rule))
        if entry not in cls._ebtables_rules:
            cls._ebtables_rules.append(entry)
            cls._sync_journal()

    @classmethod
    def unregister_ebtables_rule(cls, table: str, chain: str, rule: list[str]) -> None:
        entry = (table, chain, tuple(rule))
        if entry in cls._ebtables_rules:
            cls._ebtables_rules.remove(entry)
            cls._sync_journal()

    @classmethod
    def disable_mac_restore(cls) -> None:
        cls._restore_mac_enabled = False
        cls._sync_journal()

    @classmethod
    def prepare_interface(cls, iface: str) -> tuple[bool, str | None]:
        """Capture state and prevent NetworkManager/DHCP ownership races."""
        captured, error = cls.capture_interface(iface)
        if not captured:
            return False, error
        state, error = detach_network_manager(iface)
        cls.register_network_manager(iface, state)
        return error is None, error

    @classmethod
    def restore_interface(cls, iface: str) -> bool:
        logger = logging.getLogger("nacleaver")
        success = True
        kill_process_on_iface("wpa_supplicant", iface)
        kill_process_on_iface("dhclient", iface)

        original_mac = cls._original_macs.get(iface)
        mac_restored = True
        if cls._restore_mac_enabled and original_mac:
            try:
                current_mac = get_iface_mac(iface)
            except OSError:
                current_mac = None
            if current_mac and normalize_mac(current_mac) == normalize_mac(original_mac):
                logger.debug(f"Cleanup: MAC on {iface} already matches {original_mac}")
            else:
                logger.info(f"Cleanup: restoring MAC {original_mac} on {iface}")
                mac_restored, error = set_iface_mac(iface, original_mac)
                if not mac_restored:
                    success = False
                    logger.error(f"Cleanup: MAC restore failed on {iface}: {error}")
                else:
                    logger.info(f"Cleanup: MAC restored and verified on {iface}")

        nm_state = cls._nm_states.get(iface)
        nm_restored = True
        if nm_state:
            nm_restored, error = restore_network_manager(iface, nm_state)
            if not nm_restored:
                success = False
                logger.error(f"Cleanup: {error}")

        if mac_restored or not cls._restore_mac_enabled:
            cls._original_macs.pop(iface, None)
        if nm_restored:
            cls._nm_states.pop(iface, None)
        cls._sync_journal()
        return success

    @classmethod
    def run_all(cls) -> bool:
        logger = logging.getLogger("nacleaver")
        if cls._running:
            return False
        cls._running = True
        try:
            cls.stop_worker_processes()
            # Remove packet interception while the referenced bridge ports
            # still exist, then tear down the bridge itself.
            for table, chain, rule in list(cls._ebtables_rules):
                rc, _, err = run_subprocess([
                    "ebtables", "-t", table, "-D", chain, *rule,
                ])
                if rc != 0:
                    logger.warning(f"Cleanup: ebtables rule removal failed: {err.strip()}")
                else:
                    cls.unregister_ebtables_rule(table, chain, list(rule))

            for bridge in list(cls._bridges):
                rc, _, err = run_subprocess(["ip", "link", "delete", bridge])
                missing = "cannot find device" in err.lower()
                if rc != 0 and not missing:
                    logger.warning(f"Cleanup: bridge {bridge} removal failed: {err.strip()}")
                else:
                    cls.unregister_bridge(bridge)

            for connection_name in list(cls._nm_connections):
                run_subprocess(["nmcli", "connection", "down", "id", connection_name], timeout=15)
                rc, _, err = run_subprocess(["nmcli", "connection", "delete", "id", connection_name])
                missing = "unknown connection" in err.lower()
                if rc != 0 and not missing:
                    logger.warning(
                        f"Cleanup: temporary NetworkManager connection {connection_name} "
                        f"removal failed: {err.strip()}"
                    )
                else:
                    cls.unregister_nm_connection(connection_name)

            for iface in list(set(cls._original_macs) | set(cls._nm_states)):
                try:
                    cls.restore_interface(iface)
                except Exception as exc:
                    logger.error(f"Cleanup: failed to restore {iface}: {exc}")

            for temp_path in list(cls._temp_files):
                try:
                    os.remove(temp_path)
                except FileNotFoundError:
                    cls._temp_files.remove(temp_path)
                except OSError as exc:
                    logger.warning(f"Cleanup: unable to remove {temp_path}: {exc}")
                else:
                    cls._temp_files.remove(temp_path)
        finally:
            cls._running = False
            cls._sync_journal()
        return not cls._has_tracked_state()


if __name__ == "__main__":
    require_root()
    print("Interfaces:", get_interfaces())
    print("Dependencies:", check_all_dependencies())
    print("Default interface:", get_default_interface())
