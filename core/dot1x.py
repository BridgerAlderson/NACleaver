import logging
import os
import secrets
import ssl
import string
import tempfile
import time
from dataclasses import dataclass, field
from enum import Enum

from core.utils import (
    Cleanup,
    check_dependency,
    get_iface_ip,
    get_iface_ipv6,
    kill_process_on_iface,
    request_network_lease,
    run_subprocess,
)

logger = logging.getLogger('nacleaver')


class EAPMethod(Enum):
    PEAP_MSCHAPV2 = "peap_mschapv2"
    TTLS_MSCHAPV2 = "ttls_mschapv2"
    TTLS_PAP      = "ttls_pap"
    # "pwd" is the standards-defined EAP method name, not a credential.
    PWD           = "pwd"  # nosec B105
    MD5           = "md5"
    TLS           = "tls"
    FAST_MSCHAPV2 = "fast_mschapv2"
    TEAP_MSCHAPV2 = "teap_mschapv2"
    SIM           = "sim"
    AKA           = "aka"
    AKA_PRIME     = "aka_prime"


DEFAULT_METHOD_ORDER = [
    EAPMethod.PEAP_MSCHAPV2,
    EAPMethod.TTLS_MSCHAPV2,
    EAPMethod.TTLS_PAP,
    EAPMethod.PWD,
    EAPMethod.MD5,
]

SIM_METHODS = {EAPMethod.SIM, EAPMethod.AKA, EAPMethod.AKA_PRIME}

# Public result sentinel; it never contains secret material.
REDACTED_PASSWORD = "[REDACTED]"  # nosec B105
_WPA_METHOD_CAPABILITY: dict[EAPMethod, tuple[bool, str | None]] = {}


def _wpa_quote(value: str) -> str:
    if "\n" in value or "\r" in value:
        raise ValueError("802.1X values cannot contain newlines")
    escaped = value.replace("\\", "\\\\").replace('"', '\\"')
    return f'"{escaped}"'


def _require_readable_file(label: str, path: str | None) -> None:
    if path and not os.path.isfile(path):
        raise ValueError(f"{label} file does not exist: {path}")


def _validate_wpa_method_support(config_path: str, method: EAPMethod) -> None:
    """Ask the installed wpa_supplicant parser whether an EAP method is compiled in."""
    cached = _WPA_METHOD_CAPABILITY.get(method)
    if cached is not None:
        supported, error = cached
        if not supported:
            raise ValueError(error or f"Installed wpa_supplicant does not support {method.value}")
        return
    check_iface = f"nacchk{os.getpid() % 100000}"
    rc, output, error = run_subprocess(
        [
            "wpa_supplicant", "-D", "none", "-i", check_iface,
            "-c", config_path, "-dd",
        ],
        timeout=1,
    )
    combined = f"{output}\n{error}"
    parse_lines = [
        line.strip() for line in combined.splitlines()
        if "unknown EAP method" in line
        or "failed to parse eap" in line
        or "failed to parse network block" in line
    ]
    if parse_lines:
        detail = (
            f"Installed wpa_supplicant does not support {method.value}: "
            f"{'; '.join(dict.fromkeys(parse_lines))}"
        )
        _WPA_METHOD_CAPABILITY[method] = (False, detail)
        raise ValueError(detail)
    # A timeout is expected: a valid foreground supplicant waits for events.
    # Other runtime errors are irrelevant here once the config parser accepted it.
    _WPA_METHOD_CAPABILITY[method] = (True, None)


def probe_wpa_method_support(method: EAPMethod) -> tuple[bool, str]:
    """Safely probe a compiled EAP method without touching a real interface."""
    config_path = None
    try:
        kwargs = {}
        if method in {
            EAPMethod.PEAP_MSCHAPV2,
            EAPMethod.TTLS_MSCHAPV2,
            EAPMethod.TTLS_PAP,
            EAPMethod.TEAP_MSCHAPV2,
        }:
            kwargs["insecure_no_server_cert"] = True
        config_path = generate_wpa_config(
            method,
            "nacleaver-capability-probe",
            "capability-probe-only",
            **kwargs,
        )
        _validate_wpa_method_support(config_path, method)
        return True, f"{method.value} is accepted by the installed wpa_supplicant parser"
    except (OSError, ValueError) as exc:
        return False, str(exc)
    finally:
        if config_path:
            try:
                os.remove(config_path)
            except FileNotFoundError:
                pass


def _wpa_tls_validation(
    server_ca_cert: str | None,
    server_domain: str | None,
    insecure_no_server_cert: bool,
) -> str:
    if server_ca_cert and insecure_no_server_cert:
        raise ValueError("server_ca_cert and insecure_no_server_cert are mutually exclusive")
    if server_ca_cert:
        _require_readable_file("server CA certificate", server_ca_cert)
        validation = f"    ca_cert={_wpa_quote(server_ca_cert)}\n"
    elif insecure_no_server_cert:
        validation = "    ca_cert=\"\"\n"
    else:
        defaults = ssl.get_default_verify_paths()
        if defaults.cafile and os.path.isfile(defaults.cafile):
            validation = f"    ca_cert={_wpa_quote(defaults.cafile)}\n"
        elif defaults.capath and os.path.isdir(defaults.capath):
            validation = f"    ca_path={_wpa_quote(defaults.capath)}\n"
        else:
            raise ValueError(
                "No system CA store found; provide --server-ca-cert or explicitly use "
                "--insecure-no-server-cert"
            )
    if server_domain:
        validation += f"    domain_suffix_match={_wpa_quote(server_domain)}\n"
    return validation


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
    method: str = "dot1x"
    address_family: str | None = None


def generate_wpa_config(
    method: EAPMethod,
    identity: str,
    password: str,
    client_cert: str | None = None,
    private_key: str | None = None,
    private_key_passwd: str | None = None,
    server_ca_cert: str | None = None,
    server_domain: str | None = None,
    anonymous_identity: str | None = None,
    insecure_no_server_cert: bool = False,
    pac_file: str | None = None,
    fast_provisioning: int = 0,
    sim_pin: str | None = None,
    sim_pcsc: str | None = "",
    sim_number: int | None = None,
) -> str:
    """Write a wpa_supplicant config for wired 802.1X. Returns the config file path."""
    base = (
        "ctrl_interface=/var/run/wpa_supplicant\n"
        "ctrl_interface_group=0\n"
        "ap_scan=0\n"
        "network={\n"
        "    key_mgmt=IEEE8021X\n"
        "    eapol_flags=0\n"
    )

    tls_validation = ""
    if method in {
        EAPMethod.PEAP_MSCHAPV2,
        EAPMethod.TTLS_MSCHAPV2,
        EAPMethod.TTLS_PAP,
        EAPMethod.TLS,
        EAPMethod.TEAP_MSCHAPV2,
    }:
        tls_validation = _wpa_tls_validation(
            server_ca_cert, server_domain, insecure_no_server_cert
        )
    outer_identity = (
        f"    anonymous_identity={_wpa_quote(anonymous_identity)}\n"
        if anonymous_identity else ""
    )

    if method == EAPMethod.PEAP_MSCHAPV2:
        eap_block = (
            "    eap=PEAP\n"
            "    phase1=\"peaplabel=0\"\n"
            "    phase2=\"auth=MSCHAPV2\"\n"
            f"{tls_validation}"
            f"{outer_identity}"
            f"    identity={_wpa_quote(identity)}\n"
            f"    password={_wpa_quote(password)}\n"
        )
    elif method == EAPMethod.TTLS_MSCHAPV2:
        eap_block = (
            "    eap=TTLS\n"
            "    phase2=\"auth=MSCHAPV2\"\n"
            f"{tls_validation}"
            f"{outer_identity}"
            f"    identity={_wpa_quote(identity)}\n"
            f"    password={_wpa_quote(password)}\n"
        )
    elif method == EAPMethod.TTLS_PAP:
        eap_block = (
            "    eap=TTLS\n"
            "    phase2=\"auth=PAP\"\n"
            f"{tls_validation}"
            f"{outer_identity}"
            f"    identity={_wpa_quote(identity)}\n"
            f"    password={_wpa_quote(password)}\n"
        )
    elif method == EAPMethod.PWD:
        eap_block = (
            "    eap=PWD\n"
            f"    identity={_wpa_quote(identity)}\n"
            f"    password={_wpa_quote(password)}\n"
        )
    elif method == EAPMethod.MD5:
        eap_block = (
            "    eap=MD5\n"
            "    key_mgmt=IEEE8021X\n"
            f"    identity={_wpa_quote(identity)}\n"
            f"    password={_wpa_quote(password)}\n"
        )
    elif method == EAPMethod.TLS:
        if not client_cert or not private_key:
            raise ValueError("EAP-TLS requires a client certificate and private key")
        _require_readable_file("client certificate", client_cert)
        _require_readable_file("private key", private_key)
        cert = client_cert
        key = private_key
        key_pass = private_key_passwd or ""
        eap_block = (
            "    eap=TLS\n"
            f"{tls_validation}"
            f"    client_cert={_wpa_quote(cert)}\n"
            f"    private_key={_wpa_quote(key)}\n"
            f"    private_key_passwd={_wpa_quote(key_pass)}\n"
            f"    identity={_wpa_quote(identity)}\n"
        )
    elif method == EAPMethod.FAST_MSCHAPV2:
        if not pac_file:
            raise ValueError("EAP-FAST requires a writable PAC file path")
        pac_parent = os.path.dirname(os.path.abspath(pac_file)) or "."
        if not os.path.isdir(pac_parent):
            raise ValueError(f"EAP-FAST PAC directory does not exist: {pac_parent}")
        if isinstance(fast_provisioning, bool) or fast_provisioning not in {0, 1, 2, 3}:
            raise ValueError("EAP-FAST provisioning must be 0, 1, 2, or 3")
        if fast_provisioning == 0 and not os.path.isfile(pac_file):
            raise ValueError(
                "EAP-FAST provisioning is disabled and the PAC file does not exist"
            )
        fast_tls_validation = ""
        if (
            fast_provisioning == 2
            or server_ca_cert
            or server_domain
            or insecure_no_server_cert
        ):
            fast_tls_validation = _wpa_tls_validation(
                server_ca_cert, server_domain, insecure_no_server_cert
            )
        eap_block = (
            "    eap=FAST\n"
            f"    phase1=\"fast_provisioning={fast_provisioning}\"\n"
            "    phase2=\"auth=MSCHAPV2\"\n"
            f"{fast_tls_validation}"
            f"{outer_identity}"
            f"    identity={_wpa_quote(identity)}\n"
            f"    password={_wpa_quote(password)}\n"
            f"    pac_file={_wpa_quote(os.path.abspath(pac_file))}\n"
        )
    elif method == EAPMethod.TEAP_MSCHAPV2:
        eap_block = (
            "    eap=TEAP\n"
            "    phase2=\"auth=MSCHAPV2\"\n"
            f"{tls_validation}"
            f"{outer_identity}"
            f"    identity={_wpa_quote(identity)}\n"
            f"    password={_wpa_quote(password)}\n"
        )
    elif method in SIM_METHODS:
        if sim_pcsc is None:
            raise ValueError(f"EAP-{method.name} requires a PC/SC SIM/USIM reader")
        if sim_number is not None and (isinstance(sim_number, bool) or sim_number < 0):
            raise ValueError("SIM number must be a non-negative integer")
        eap_name = {
            EAPMethod.SIM: "SIM",
            EAPMethod.AKA: "AKA",
            EAPMethod.AKA_PRIME: "AKA'",
        }[method]
        eap_block = f"    eap={eap_name}\n"
        if identity:
            eap_block += f"    identity={_wpa_quote(identity)}\n"
        if anonymous_identity:
            eap_block += f"    anonymous_identity={_wpa_quote(anonymous_identity)}\n"
        if sim_pin is not None:
            eap_block += f"    pin={_wpa_quote(sim_pin)}\n"
        eap_block += f"    pcsc={_wpa_quote(sim_pcsc)}\n"
        if sim_number is not None:
            eap_block += f"    phase1=\"sim_num={sim_number}\"\n"
    else:
        raise ValueError(f"Unknown EAP method: {method}")

    config = base + eap_block + "}\n"
    config_fd, config_path = tempfile.mkstemp(prefix="nacleaver-wpa-", suffix=".conf")
    try:
        with os.fdopen(config_fd, "w", encoding="utf-8") as handle:
            handle.write(config)
    except Exception:
        try:
            os.close(config_fd)
        except OSError:
            pass
        try:
            os.remove(config_path)
        except OSError:
            pass
        raise
    return config_path


def _try_wpa_supplicant(
    iface: str,
    method: EAPMethod,
    identity: str,
    password: str,
    timeout: int = 15,
    dhcp_timeout: int = 30,
    client_cert: str | None = None,
    private_key: str | None = None,
    private_key_passwd: str | None = None,
    server_ca_cert: str | None = None,
    server_domain: str | None = None,
    anonymous_identity: str | None = None,
    insecure_no_server_cert: bool = False,
    pac_file: str | None = None,
    fast_provisioning: int = 0,
    sim_pin: str | None = None,
    sim_pcsc: str | None = "",
    sim_number: int | None = None,
) -> tuple[bool, str | None]:
    """Authenticate with wpa_supplicant and require usable IPv4/IPv6."""
    # Build and validate all credential material before taking ownership of the
    # interface. A malformed engagement profile must not disrupt connectivity.
    config_path = generate_wpa_config(
        method, identity, password,
        client_cert=client_cert,
        private_key=private_key,
        private_key_passwd=private_key_passwd,
        server_ca_cert=server_ca_cert,
        server_domain=server_domain,
        anonymous_identity=anonymous_identity,
        insecure_no_server_cert=insecure_no_server_cert,
        pac_file=pac_file,
        fast_provisioning=fast_provisioning,
        sim_pin=sim_pin,
        sim_pcsc=sim_pcsc,
        sim_number=sim_number,
    )
    try:
        _validate_wpa_method_support(config_path, method)
    except Exception:
        try:
            os.remove(config_path)
        except OSError:
            pass
        raise
    Cleanup.register_temp_file(config_path)
    prepared, error = Cleanup.prepare_interface(iface)
    if not prepared:
        try:
            os.remove(config_path)
        except FileNotFoundError:
            Cleanup.unregister_temp_file(config_path)
        except OSError:
            pass
        else:
            Cleanup.unregister_temp_file(config_path)
        logger.debug(f"[dot1x] Interface ownership failed: {error}")
        Cleanup.restore_interface(iface)
        return False, None

    kill_process_on_iface("wpa_supplicant", iface)
    kill_process_on_iface("dhclient", iface)
    time.sleep(0.5)

    log_fd, log_path = tempfile.mkstemp(prefix=f"nacleaver-wpa-{iface}-", suffix=".log")
    os.close(log_fd)
    Cleanup.register_temp_file(log_path)
    try:
        rc, _, err = run_subprocess([
            "wpa_supplicant", "-B", "-D", "wired",
            "-i", iface,
            "-c", config_path,
            "-f", log_path,
        ])
        if rc != 0:
            logger.debug(f"[dot1x] wpa_supplicant launch failed (rc={rc}): {err}")
            return False, None

        fail_count = 0
        authenticated = False
        deadline = time.monotonic() + timeout
        while time.monotonic() < deadline:
            time.sleep(0.5)
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
                authenticated = True
                break
            if state in ("DISCONNECTED", "HELD"):
                fail_count += 1
                if fail_count >= 3:
                    break

        if not authenticated:
            kill_process_on_iface("wpa_supplicant", iface)
            return False, None

        logger.info(f"[dot1x] wpa_supplicant: {method.value} auth COMPLETED for {identity}")
        lease = request_network_lease(iface, timeout=dhcp_timeout)
        if not lease.success:
            logger.warning(f"[dot1x] Authentication completed but addressing failed: {lease.error}")
            kill_process_on_iface("wpa_supplicant", iface)
            return False, None

        # Keep wpa_supplicant alive until Cleanup so the authenticated session
        # remains valid during posture and post-auth checks.
        return True, lease.ip
    finally:
        try:
            os.remove(config_path)
        except FileNotFoundError:
            Cleanup.unregister_temp_file(config_path)
        except OSError:
            pass
        else:
            Cleanup.unregister_temp_file(config_path)

def _try_nmcli(
    iface: str,
    conn_name: str,
    method: EAPMethod,
    identity: str,
    password: str,
    timeout: int = 15,
    client_cert: str | None = None,
    private_key: str | None = None,
    private_key_passwd: str | None = None,
    server_ca_cert: str | None = None,
    server_domain: str | None = None,
    anonymous_identity: str | None = None,
    insecure_no_server_cert: bool = False,
    pac_file: str | None = None,
    fast_provisioning: int = 0,
    sim_pin: str | None = None,
    sim_pcsc: str | None = "",
    sim_number: int | None = None,
) -> tuple[bool, str | None]:
    """Authenticate through a disposable NetworkManager connection profile."""
    for label, value in {
        "identity": identity,
        "password": password,
        "private key password": private_key_passwd,
    }.items():
        if value is not None and ("\n" in value or "\r" in value):
            raise ValueError(f"802.1X {label} cannot contain newlines")
    if server_ca_cert and insecure_no_server_cert:
        raise ValueError("server_ca_cert and insecure_no_server_cert are mutually exclusive")
    _require_readable_file("server CA certificate", server_ca_cert)
    if method == EAPMethod.TLS:
        _require_readable_file("client certificate", client_cert)
        _require_readable_file("private key", private_key)
    if method in ({EAPMethod.FAST_MSCHAPV2, EAPMethod.TEAP_MSCHAPV2} | SIM_METHODS):
        raise ValueError(
            f"{method.value} requires the wpa_supplicant backend; "
            "NetworkManager support is not sufficiently portable"
        )
    captured, capture_error = Cleanup.capture_interface(iface)
    if not captured:
        logger.debug(f"[dot1x] Unable to capture interface state: {capture_error}")
        return False, None

    suffix = ''.join(
        secrets.choice(string.ascii_lowercase + string.digits) for _ in range(6)
    )
    attempt_conn = f"{conn_name}-{os.getpid()}-{suffix}"
    rc, _, err = run_subprocess([
        "nmcli", "connection", "add", "type", "ethernet",
        "ifname", iface, "con-name", attempt_conn,
        "connection.autoconnect", "no",
    ])
    if rc != 0:
        logger.debug(f"[dot1x] Unable to create temporary nmcli profile: {err}")
        return False, None
    Cleanup.register_nm_connection(attempt_conn)

    def delete_attempt() -> None:
        run_subprocess(["nmcli", "connection", "down", "id", attempt_conn], timeout=15)
        run_subprocess(["nmcli", "connection", "delete", "id", attempt_conn])
        Cleanup.unregister_nm_connection(attempt_conn)

    if method == EAPMethod.PEAP_MSCHAPV2:
        eap_val, phase2_val = "peap", "mschapv2"
    elif method == EAPMethod.TTLS_MSCHAPV2:
        eap_val, phase2_val = "ttls", "mschapv2"
    elif method == EAPMethod.TTLS_PAP:
        eap_val, phase2_val = "ttls", "pap"
    elif method == EAPMethod.PWD:
        eap_val, phase2_val = "pwd", None
    elif method == EAPMethod.MD5:
        eap_val, phase2_val = "md5", None
    elif method == EAPMethod.TLS:
        if not client_cert or not private_key:
            delete_attempt()
            raise ValueError("EAP-TLS requires --client-cert and --private-key")
        eap_val, phase2_val = "tls", None
    else:
        delete_attempt()
        raise ValueError(f"Unknown EAP method: {method}")

    # Keep the password out of argv and out of the persistent NM profile.
    modify_cmd = [
        "nmcli", "connection", "modify", attempt_conn,
        "802-1x.eap", eap_val,
        "802-1x.identity", identity,
        "802-1x.password-flags", "2",
        "802-1x.system-ca-certs", "no" if (server_ca_cert or insecure_no_server_cert) else "yes",
        "ipv4.method", "auto",
    ]
    if server_ca_cert:
        modify_cmd += ["802-1x.ca-cert", f"file://{os.path.abspath(server_ca_cert)}"]
    if server_domain:
        modify_cmd += ["802-1x.domain-suffix-match", server_domain]
    if anonymous_identity and method in {
        EAPMethod.PEAP_MSCHAPV2,
        EAPMethod.TTLS_MSCHAPV2,
        EAPMethod.TTLS_PAP,
    }:
        modify_cmd += ["802-1x.anonymous-identity", anonymous_identity]
    if phase2_val:
        modify_cmd += ["802-1x.phase2-auth", phase2_val]
    if method == EAPMethod.TLS:
        modify_cmd += [
            "802-1x.client-cert", f"file://{os.path.abspath(client_cert)}",
            "802-1x.private-key", f"file://{os.path.abspath(private_key)}",
        ]
        if private_key_passwd is not None:
            modify_cmd += ["802-1x.private-key-password-flags", "2"]

    rc, _, err = run_subprocess(modify_cmd)
    if rc != 0:
        delete_attempt()
        logger.debug(f"[dot1x] nmcli profile configuration failed: {err}")
        return False, None

    secret_path = None
    up_cmd = ["nmcli", "--wait", str(timeout), "connection", "up", "id", attempt_conn]
    try:
        secret_lines: list[str] = []
        if method != EAPMethod.TLS:
            secret_lines.append(f"802-1x.password:{password}")
        if method == EAPMethod.TLS and private_key_passwd is not None:
            secret_lines.append(f"802-1x.private-key-password:{private_key_passwd}")
        if secret_lines:
            secret_fd, secret_path = tempfile.mkstemp(prefix="nacleaver-nmcli-", suffix=".passwd")
            Cleanup.register_temp_file(secret_path)
            try:
                os.write(secret_fd, ("\n".join(secret_lines) + "\n").encode())
            finally:
                os.close(secret_fd)
            up_cmd += ["passwd-file", secret_path]

        rc, _, err = run_subprocess(up_cmd, timeout=timeout + 5)
    finally:
        if secret_path:
            try:
                os.remove(secret_path)
            except FileNotFoundError:
                Cleanup.unregister_temp_file(secret_path)
            except OSError:
                pass
            else:
                Cleanup.unregister_temp_file(secret_path)

    if rc != 0:
        delete_attempt()
        logger.debug(f"[dot1x] nmcli up failed (rc={rc}): {err}")
        return False, None

    ip = get_iface_ip(iface) or get_iface_ipv6(iface)
    if not ip:
        delete_attempt()
        return False, None

    logger.info(f"[dot1x] nmcli: {method.value} auth succeeded for {identity}, IP={ip}")
    return True, ip

def _select_backend(preferred: str) -> str:
    if preferred == "auto":
        if (
            check_dependency("wpa_supplicant")
            and check_dependency("wpa_cli")
            and check_dependency("dhclient")
        ):
            return "wpa_supplicant"
        elif check_dependency("nmcli"):
            return "nmcli"
        else:
            raise RuntimeError(
                "Neither a complete wpa_supplicant/wpa_cli/dhclient stack nor nmcli is available"
            )
    if preferred == "wpa_supplicant":
        missing = [
            name for name in ("wpa_supplicant", "wpa_cli", "dhclient")
            if not check_dependency(name)
        ]
        if missing:
            raise RuntimeError(f"Missing wpa_supplicant backend tools: {', '.join(missing)}")
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
    dhcp_timeout: int,
    backend: str,
    conn_name: str,
    client_cert: str | None,
    private_key: str | None,
    private_key_passwd: str | None,
    server_ca_cert: str | None,
    server_domain: str | None,
    anonymous_identity: str | None,
    insecure_no_server_cert: bool,
    pac_file: str | None,
    fast_provisioning: int,
    sim_pin: str | None,
    sim_pcsc: str | None,
    sim_number: int | None,
) -> tuple[bool, str | None, str | None]:
    """Single authentication attempt. Returns (success, obtained_ip, error)."""
    try:
        if backend == "wpa_supplicant":
            success, ip = _try_wpa_supplicant(
                iface, method, identity, password, timeout,
                dhcp_timeout=dhcp_timeout,
                client_cert=client_cert, private_key=private_key,
                private_key_passwd=private_key_passwd,
                server_ca_cert=server_ca_cert,
                server_domain=server_domain,
                anonymous_identity=anonymous_identity,
                insecure_no_server_cert=insecure_no_server_cert,
                pac_file=pac_file,
                fast_provisioning=fast_provisioning,
                sim_pin=sim_pin,
                sim_pcsc=sim_pcsc,
                sim_number=sim_number,
            )
        else:
            success, ip = _try_nmcli(
                iface, conn_name, method, identity, password, timeout,
                client_cert=client_cert, private_key=private_key,
                private_key_passwd=private_key_passwd,
                server_ca_cert=server_ca_cert,
                server_domain=server_domain,
                anonymous_identity=anonymous_identity,
                insecure_no_server_cert=insecure_no_server_cert,
                pac_file=pac_file,
                fast_provisioning=fast_provisioning,
                sim_pin=sim_pin,
                sim_pcsc=sim_pcsc,
                sim_number=sim_number,
            )
        return success, ip, None
    except Exception as e:
        logger.debug(f"[dot1x] Auth attempt error: {e}")
        return False, None, str(e)


def spray_credentials(
    iface: str,
    creds_file: str,
    methods: list[EAPMethod] = DEFAULT_METHOD_ORDER,
    timeout_per_attempt: int = 15,
    dhcp_timeout: int = 30,
    spray_delay: float = 2.0,
    backend: str = "auto",
    conn_name: str = "NACleaver-8021x",
    client_cert: str | None = None,
    private_key: str | None = None,
    private_key_passwd: str | None = None,
    server_ca_cert: str | None = None,
    server_domain: str | None = None,
    anonymous_identity: str | None = None,
    insecure_no_server_cert: bool = False,
    pac_file: str | None = None,
    fast_provisioning: int = 0,
    sim_pin: str | None = None,
    sim_pcsc: str | None = "",
    sim_number: int | None = None,
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
                timeout_per_attempt, dhcp_timeout, selected_backend, conn_name,
                client_cert, private_key, private_key_passwd,
                server_ca_cert, server_domain,
                anonymous_identity, insecure_no_server_cert,
                pac_file, fast_provisioning, sim_pin, sim_pcsc, sim_number,
            )
            duration = time.time() - t_start

            rec = AttemptRecord(
                method=method.value,
                identity=identity,
                password=REDACTED_PASSWORD,
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
                    password=REDACTED_PASSWORD,
                    obtained_ip=ip,
                    backend_used=selected_backend,
                    attempts=attempts,
                    address_family="ipv6" if ip and ":" in ip else "ipv4",
                )

            logger.info(f"[dot1x] FAIL: {identity}/{method.value}")
            time.sleep(spray_delay)

    Cleanup.restore_interface(iface)
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
    dhcp_timeout: int = 30,
    spray_delay: float = 2.0,
    backend: str = "auto",
    conn_name: str = "NACleaver-8021x",
    client_cert: str | None = None,
    private_key: str | None = None,
    private_key_passwd: str | None = None,
    server_ca_cert: str | None = None,
    server_domain: str | None = None,
    anonymous_identity: str | None = None,
    insecure_no_server_cert: bool = False,
    pac_file: str | None = None,
    fast_provisioning: int = 0,
    sim_pin: str | None = None,
    sim_pcsc: str | None = "",
    sim_number: int | None = None,
    verbose: bool = False,
) -> Dot1XResult:
    """Run 802.1X authentication, with optional credential spraying."""
    if creds_file:
        return spray_credentials(
            iface, creds_file, methods=methods,
            timeout_per_attempt=timeout, dhcp_timeout=dhcp_timeout,
            spray_delay=spray_delay,
            backend=backend, conn_name=conn_name,
            client_cert=client_cert, private_key=private_key,
            private_key_passwd=private_key_passwd,
            server_ca_cert=server_ca_cert, server_domain=server_domain,
            anonymous_identity=anonymous_identity,
            insecure_no_server_cert=insecure_no_server_cert,
            pac_file=pac_file,
            fast_provisioning=fast_provisioning,
            sim_pin=sim_pin,
            sim_pcsc=sim_pcsc,
            sim_number=sim_number,
            verbose=verbose,
        )

    if not identity and any(method not in SIM_METHODS for method in methods):
        raise ValueError("Must provide --username or --creds-file")

    selected_backend = _select_backend(backend)
    passwd = password or ''
    attempts: list[AttemptRecord] = []

    for method in methods:
        t_start = time.time()
        success, ip, err = _attempt_auth(
            iface, method, identity or "", passwd,
            timeout, dhcp_timeout, selected_backend, conn_name,
            client_cert, private_key, private_key_passwd,
            server_ca_cert, server_domain,
            anonymous_identity, insecure_no_server_cert,
            pac_file, fast_provisioning, sim_pin, sim_pcsc, sim_number,
        )
        duration = time.time() - t_start

        rec = AttemptRecord(
            method=method.value,
            identity=identity or "",
            password=REDACTED_PASSWORD,
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
                password=REDACTED_PASSWORD,
                obtained_ip=ip,
                backend_used=selected_backend,
                attempts=attempts,
                address_family="ipv6" if ip and ":" in ip else "ipv4",
            )

        logger.info(f"[dot1x] FAIL: {identity}/{method.value}")

    Cleanup.restore_interface(iface)
    return Dot1XResult(
        success=False,
        method_used=None,
        identity=identity,
        password=REDACTED_PASSWORD,
        obtained_ip=None,
        backend_used=selected_backend,
        attempts=attempts,
        error=(
            attempts[0].error
            if len(attempts) == 1 and attempts[0].error
            else "All EAP methods failed"
        ),
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
