import fcntl
import json
import logging
import os
import re
import shutil
import socket
import struct
import subprocess
import sys
import time
from dataclasses import asdict, is_dataclass
from datetime import datetime
from pathlib import Path

import netifaces
from rich.console import Console
from rich.logging import RichHandler

console = Console()


def require_root() -> None:
    if os.geteuid() != 0:
        console.print("[bold red][!] NACleaver requires root privileges. Run with sudo.[/bold red]")
        sys.exit(1)


def get_interfaces() -> list[str]:
    interfaces = []
    try:
        for iface in os.listdir('/sys/class/net/'):
            if iface != 'lo' and os.path.exists(f'/sys/class/net/{iface}'):
                interfaces.append(iface)
    except OSError as e:
        logging.getLogger('nacleaver').warning(f"Failed to list interfaces: {e}")
    return interfaces


def get_iface_mac(iface: str) -> str:
    path = f'/sys/class/net/{iface}/address'
    if not os.path.exists(path):
        raise FileNotFoundError(f"Interface {iface} not found at {path}")
    with open(path) as f:
        return f.read().strip().lower()


def get_iface_ip(iface: str) -> str | None:
    try:
        addrs = netifaces.ifaddresses(iface)
        inet = addrs.get(netifaces.AF_INET)
        if inet:
            return inet[0]['addr']
    except (ValueError, KeyError, OSError):
        pass
    return None


def get_iface_netmask(iface: str) -> str | None:
    try:
        addrs = netifaces.ifaddresses(iface)
        inet = addrs.get(netifaces.AF_INET)
        if inet:
            return inet[0].get('netmask')
    except (ValueError, KeyError, OSError):
        pass
    return None


def get_iface_state(iface: str) -> str:
    path = f'/sys/class/net/{iface}/operstate'
    try:
        with open(path) as f:
            return f.read().strip()
    except OSError:
        return 'unknown'


def validate_mac(mac: str) -> bool:
    return bool(re.fullmatch(r'([0-9a-fA-F]{2}:){5}[0-9a-fA-F]{2}', mac))


def normalize_mac(mac: str) -> str:
    clean = mac.replace(':', '').replace('-', '').lower()
    return ':'.join(clean[i:i+2] for i in range(0, 12, 2))


def is_multicast_mac(mac: str) -> bool:
    first_octet = int(mac.replace(':', '').replace('-', '')[:2], 16)
    return bool(first_octet & 0x01)


def is_locally_administered_mac(mac: str) -> bool:
    first_octet = int(mac.replace(':', '').replace('-', '')[:2], 16)
    return bool(first_octet & 0x02)


def check_dependency(cmd: str) -> bool:
    return shutil.which(cmd) is not None


def check_all_dependencies() -> dict[str, bool]:
    tools = ['wpa_supplicant', 'wpa_cli', 'nmcli', 'dhclient', 'ip', 'ebtables', 'brctl', 'arping']
    return {tool: check_dependency(tool) for tool in tools}


def setup_logging(verbose: bool, output_dir: str = "output") -> logging.Logger:
    Path(output_dir).mkdir(parents=True, exist_ok=True)
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    log_file = f"{output_dir}/nacleaver_{timestamp}.log"

    logger = logging.getLogger('nacleaver')
    logger.setLevel(logging.DEBUG if verbose else logging.INFO)
    logger.handlers.clear()

    rich_handler = RichHandler(rich_tracebacks=True, markup=True, show_path=False)
    rich_handler.setLevel(logging.DEBUG if verbose else logging.INFO)
    logger.addHandler(rich_handler)

    file_handler = logging.FileHandler(log_file)
    file_handler.setLevel(logging.DEBUG)
    file_handler.setFormatter(logging.Formatter(
        '%(asctime)s - %(name)s - %(levelname)s - %(message)s'
    ))
    logger.addHandler(file_handler)

    return logger


def save_json_result(result: dict, output_dir: str = "output") -> str:
    Path(output_dir).mkdir(parents=True, exist_ok=True)
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    output_path = f"{output_dir}/nacleaver_{timestamp}.json"

    def default_serializer(obj):
        if is_dataclass(obj):
            return asdict(obj)
        if hasattr(obj, 'name'):
            return obj.name
        if hasattr(obj, '__dict__'):
            return obj.__dict__
        return str(obj)

    with open(output_path, 'w') as f:
        json.dump(result, f, indent=2, default=default_serializer)
    return output_path


def kill_process_on_iface(process_name: str, iface: str) -> None:
    subprocess.run(
        ["pkill", "-f", f"{process_name}.*{iface}"],
        capture_output=True
    )


def run_subprocess(cmd: list[str], timeout: int = 10) -> tuple[int, str, str]:
    try:
        result = subprocess.run(
            cmd, capture_output=True, text=True, timeout=timeout
        )
        return result.returncode, result.stdout, result.stderr
    except subprocess.TimeoutExpired:
        return 124, "", "timeout"
    except PermissionError:
        return 126, "", "permission denied"
    except Exception as e:
        return 1, "", str(e)


def get_default_interface() -> str | None:
    rc, out, _ = run_subprocess(["ip", "route", "show", "default"])
    if rc != 0:
        return None
    for line in out.splitlines():
        if line.startswith('default'):
            parts = line.split()
            try:
                dev_idx = parts.index('dev')
                return parts[dev_idx + 1]
            except (ValueError, IndexError):
                pass
    return None


def ip_to_network(ip: str, netmask: str) -> str:
    """Return CIDR notation network string, e.g. '10.0.0.0/24'."""
    ip_int = struct.unpack('!I', socket.inet_aton(ip))[0]
    mask_int = struct.unpack('!I', socket.inet_aton(netmask))[0]
    prefix_len = bin(mask_int).count('1')
    net_int = ip_int & mask_int
    net_str = socket.inet_ntoa(struct.pack('!I', net_int))
    return f"{net_str}/{prefix_len}"


class Cleanup:
    _original_macs: dict[str, str] = {}
    _bridges: list[str] = []
    _ebtables_modified: bool = False
    _restore_mac_enabled: bool = True

    @classmethod
    def register_mac(cls, iface: str, original_mac: str) -> None:
        cls._original_macs[iface] = original_mac

    @classmethod
    def register_bridge(cls, bridge_name: str) -> None:
        cls._bridges.append(bridge_name)

    @classmethod
    def set_ebtables_modified(cls) -> None:
        cls._ebtables_modified = True

    @classmethod
    def disable_mac_restore(cls) -> None:
        cls._restore_mac_enabled = False

    @classmethod
    def run_all(cls) -> None:
        logger = logging.getLogger('nacleaver')

        for iface in list(cls._original_macs.keys()):
            try:
                logger.info(f"Cleanup: killing wpa_supplicant on {iface}")
                kill_process_on_iface("wpa_supplicant", iface)
                kill_process_on_iface("dhclient", iface)
            except Exception as e:
                logger.debug(f"Cleanup: error killing processes on {iface}: {e}")

        for bridge in cls._bridges:
            try:
                logger.info(f"Cleanup: deleting bridge {bridge}")
                subprocess.run(["ip", "link", "delete", bridge], capture_output=True)
            except Exception as e:
                logger.debug(f"Cleanup: error deleting bridge {bridge}: {e}")

        if cls._ebtables_modified:
            try:
                logger.info("Cleanup: flushing ebtables BROUTING chain")
                subprocess.run(
                    ["ebtables", "-t", "broute", "-F", "BROUTING"],
                    capture_output=True
                )
            except Exception as e:
                logger.debug(f"Cleanup: error flushing ebtables: {e}")

        if cls._restore_mac_enabled:
            for iface, original_mac in cls._original_macs.items():
                try:
                    logger.info(f"Cleanup: restoring MAC {original_mac} on {iface}")
                    subprocess.run(["ip", "link", "set", iface, "down"], capture_output=True)
                    subprocess.run(["ip", "link", "set", iface, "address", original_mac], capture_output=True)
                    subprocess.run(["ip", "link", "set", iface, "up"], capture_output=True)
                    logger.info(f"Cleanup: MAC restored on {iface}")
                except Exception as e:
                    logger.debug(f"Cleanup: error restoring MAC on {iface}: {e}")


if __name__ == "__main__":
    require_root()
    print("Interfaces:", get_interfaces())
    print("Dependencies:", check_all_dependencies())
    print("Default interface:", get_default_interface())
