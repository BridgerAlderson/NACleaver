#!/usr/bin/env python3
"""NACleaver — NAC Bypass Framework for Authorized Penetration Testing"""

import argparse
import atexit
import math
import re
import signal
import sys
from datetime import datetime
from pathlib import Path

from rich.console import Console
from rich.panel import Panel
from rich.table import Table

from core.utils import (
    Cleanup,
    check_all_dependencies,
    check_python_dependencies,
    config_value,
    get_iface_ip,
    get_iface_gateway,
    get_iface_gateway6,
    get_iface_ipv6,
    load_config,
    require_root,
    restore_permanent_mac,
    save_json_result,
    setup_logging,
    validate_interface,
)

console = Console()

EXIT_OK = 0
EXIT_FATAL = 1
EXIT_NOT_VERIFIED = 2


def _add_common_args(p: argparse.ArgumentParser) -> None:
    """Add flags after a subcommand without overwriting pre-command values."""
    p.add_argument("-i", "--interface", default=argparse.SUPPRESS,
                   help="Primary network interface")
    p.add_argument("--timeout", type=int, default=argparse.SUPPRESS,
                   help="Timeout per attempt in seconds")
    p.add_argument("--dhcp-timeout", type=int, default=argparse.SUPPRESS,
                   help="DHCP timeout in seconds")
    p.add_argument("--no-restore-mac", action="store_true", default=argparse.SUPPRESS,
                   help="Do not restore original MAC on exit")
    p.add_argument("--no-posture", action="store_true", default=argparse.SUPPRESS,
                   help="Skip posture bypass attempt after successful auth")
    p.add_argument("--no-post", action="store_true", default=argparse.SUPPRESS,
                   help="Skip post-auth network enumeration")
    p.add_argument("-o", "--output", default=argparse.SUPPRESS,
                   help="Output directory for logs and JSON results")
    p.add_argument("--config", default=argparse.SUPPRESS,
                   help="Configuration YAML path")
    p.add_argument("-v", "--verbose", action="store_true", default=argparse.SUPPRESS,
                   help="Verbose output")


def _add_auth_args(p: argparse.ArgumentParser) -> None:
    """Add 802.1X auth flags after dot1x/auto."""
    p.add_argument("-u", "--username", default=argparse.SUPPRESS,
                   help="Username for 802.1X")
    p.add_argument("-p", "--password", default=argparse.SUPPRESS,
                   help="Password for 802.1X")
    p.add_argument("-C", "--creds-file", default=argparse.SUPPRESS,
                   help="Credential file (user:pass per line)")
    p.add_argument("--eap-method", default=argparse.SUPPRESS,
                   choices=["peap", "ttls_mschapv2", "ttls_pap", "pwd", "md5", "tls",
                            "fast", "teap", "sim", "aka", "aka_prime", "auto"],
                   help="EAP method for 802.1X")
    p.add_argument("--spray-delay", type=float, default=argparse.SUPPRESS,
                   help="Delay between spray attempts in seconds")
    p.add_argument("--backend", default=argparse.SUPPRESS,
                   choices=["wpa_supplicant", "nmcli", "auto"],
                   help="802.1X backend")
    p.add_argument("--conn-name", default=argparse.SUPPRESS,
                   help="Temporary nmcli connection name prefix")
    p.add_argument("--client-cert", default=argparse.SUPPRESS,
                   help="Client certificate path for EAP-TLS")
    p.add_argument("--private-key", default=argparse.SUPPRESS,
                   help="Private key path for EAP-TLS")
    p.add_argument("--private-key-password", default=argparse.SUPPRESS,
                   help="Password for an encrypted EAP-TLS private key")
    p.add_argument("--server-ca-cert", default=argparse.SUPPRESS,
                   help="CA certificate used to validate the RADIUS server")
    p.add_argument("--server-domain", default=argparse.SUPPRESS,
                   help="Required RADIUS certificate domain suffix")
    p.add_argument("--anonymous-identity", default=argparse.SUPPRESS,
                   help="Outer identity for tunneled EAP methods")
    p.add_argument(
        "--insecure-no-server-cert",
        action="store_true",
        default=argparse.SUPPRESS,
        help="Explicitly disable RADIUS server certificate validation",
    )
    p.add_argument("--pac-file", default=argparse.SUPPRESS,
                   help="Writable PAC store for EAP-FAST")
    p.add_argument("--fast-provisioning", type=int, choices=[0, 1, 2, 3],
                   default=argparse.SUPPRESS,
                   help="EAP-FAST PAC provisioning mode (0 disabled; 1/2/3 enabled)")
    p.add_argument("--sim-pin", default=argparse.SUPPRESS,
                   help="PIN for the PC/SC SIM/USIM")
    p.add_argument("--sim-pcsc", nargs="?", const="", default=argparse.SUPPRESS,
                   help="PC/SC reader name; omit the value to select the first reader")
    p.add_argument("--sim-number", type=int, default=argparse.SUPPRESS,
                   help="Non-negative SIM slot identifier")

def _g(args: argparse.Namespace, key: str, default=None):
    """Return the first non-None value: subparser arg, then top-level arg, then default."""
    val = getattr(args, key, None)
    if val is not None:
        return val
    return default


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="nacleaver",
        description="NACleaver — NAC Bypass Framework for Authorized Penetration Testing",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  nacleaver -i eth0 doctor --mode all
  nacleaver -i eth0 recon
  nacleaver -i eth0 mab
  nacleaver -i eth0 mab --mac aa:bb:cc:dd:ee:ff
  nacleaver -i eth0 dot1x -u pentest -p 'Password123'
  nacleaver -i eth0 dot1x -C creds.txt --eap-method peap
  nacleaver -i eth0 relay -i2 eth1
  nacleaver -i eth0 auto -u pentest -p 'Password123'
        """,
    )
    parser.add_argument("-i", "--interface",
                        help="Primary network interface (e.g. eth0, ens33)")
    parser.add_argument("-i2", "--interface2",
                        help="Second interface — required for relay mode (e.g. eth1)")
    parser.add_argument("-u", "--username", help="Username for 802.1X")
    parser.add_argument("-p", "--password", default=None, help="Password for 802.1X")
    parser.add_argument("-C", "--creds-file", help="Credential file (user:pass per line)")
    parser.add_argument("-m", "--mac", help="Specific MAC to spoof in MAB mode")
    parser.add_argument("--timeout", type=int, default=None,
                        help="Timeout per attempt (default: config.yaml)")
    parser.add_argument("--dhcp-timeout", type=int, default=None,
                        help="DHCP timeout (default: config.yaml)")
    parser.add_argument("--harvest-duration", type=int, default=None,
                        help="MAC harvest duration (default: config.yaml)")
    parser.add_argument("--min-score", type=float, default=None,
                        help="Minimum automatic MAB candidate score")
    parser.add_argument("--eap-method",
                        choices=["peap", "ttls_mschapv2", "ttls_pap", "pwd", "md5", "tls",
                                 "fast", "teap", "sim", "aka", "aka_prime", "auto"],
                        default=None,
                        help="EAP method for 802.1X (default: config.yaml order)")
    parser.add_argument("--spray-delay", type=float, default=None,
                        help="Delay between spray attempts in seconds (default: 2.0)")
    parser.add_argument("--backend", choices=["wpa_supplicant", "nmcli", "auto"], default=None,
                        help="802.1X backend (default: auto)")
    parser.add_argument("--conn-name", default="NACleaver-8021x",
                        help="nmcli connection name (default: NACleaver-8021x)")
    parser.add_argument("--client-cert", help="Client certificate path for EAP-TLS")
    parser.add_argument("--private-key", help="Private key path for EAP-TLS")
    parser.add_argument("--private-key-password",
                        help="Password for an encrypted EAP-TLS private key")
    parser.add_argument("--server-ca-cert",
                        help="CA certificate used to validate the RADIUS server")
    parser.add_argument("--server-domain",
                        help="Required RADIUS certificate domain suffix")
    parser.add_argument("--anonymous-identity",
                        help="Outer identity for tunneled EAP methods")
    parser.add_argument(
        "--insecure-no-server-cert",
        action="store_true",
        default=None,
        help="Explicitly disable RADIUS server certificate validation",
    )
    parser.add_argument("--pac-file", help="Writable PAC store for EAP-FAST")
    parser.add_argument("--fast-provisioning", type=int, choices=[0, 1, 2, 3],
                        help="EAP-FAST PAC provisioning mode")
    parser.add_argument("--sim-pin", help="PIN for the PC/SC SIM/USIM")
    parser.add_argument("--sim-pcsc", nargs="?", const="",
                        help="PC/SC reader name; omit the value for the first reader")
    parser.add_argument("--sim-number", type=int, help="Non-negative SIM slot identifier")
    parser.add_argument("--no-restore-mac", action="store_true", default=None,
                        help="Do not restore original MAC on exit")
    parser.add_argument("--no-posture", action="store_true", default=None,
                        help="Skip posture bypass attempt after successful auth")
    parser.add_argument("--no-post", action="store_true", default=None,
                        help="Skip post-auth network enumeration")
    parser.add_argument("-o", "--output", help="Output directory for JSON results (default: output/)")
    parser.add_argument("--config", help="Configuration YAML path (default: project config.yaml)")
    parser.add_argument("-v", "--verbose", action="store_true", help="Verbose output")

    subparsers = parser.add_subparsers(dest="command", required=True)

    p_doctor = subparsers.add_parser(
        "doctor", help="Validate runtime, privileges, interfaces, and dependencies"
    )
    p_doctor.add_argument(
        "--mode",
        dest="doctor_mode",
        choices=["recon", "mab", "dot1x", "relay", "posture", "post", "all"],
        default="all",
        help="Check prerequisites for one execution mode (default: all)",
    )
    p_doctor.add_argument(
        "-i2", "--interface2", default=argparse.SUPPRESS,
        help="Second interface when checking relay mode",
    )
    p_doctor.add_argument(
        "-i", "--interface", default=argparse.SUPPRESS,
        help="Primary network interface",
    )
    p_doctor.add_argument(
        "-o", "--output", default=argparse.SUPPRESS,
        help="Output directory for logs and JSON results",
    )
    p_doctor.add_argument(
        "--config", default=argparse.SUPPRESS,
        help="Configuration YAML path",
    )
    p_doctor.add_argument(
        "-v", "--verbose", action="store_true", default=argparse.SUPPRESS,
        help="Verbose output",
    )

    p_recover = subparsers.add_parser(
        "recover", help="Recover stale NACleaver network state after an unclean exit"
    )
    p_recover.add_argument(
        "--force", action="store_true",
        help="Recover journals even when their recorded process still appears alive",
    )
    p_recover.add_argument(
        "-o", "--output", default=argparse.SUPPRESS,
        help="Output directory for logs and JSON results",
    )
    p_recover.add_argument(
        "-v", "--verbose", action="store_true", default=argparse.SUPPRESS,
        help="Verbose output",
    )

    p_recon = subparsers.add_parser("recon", help="Detect NAC type on the connected segment")
    _add_common_args(p_recon)

    p_mab = subparsers.add_parser("mab", help="MAB bypass via passive MAC harvesting and spoofing")
    p_mab.add_argument("-m", "--mac", default=argparse.SUPPRESS, help="Specific MAC to spoof")
    p_mab.add_argument("--harvest-duration", type=int, default=argparse.SUPPRESS,
                       help="MAC harvest duration in seconds")
    p_mab.add_argument("--min-score", type=float, default=argparse.SUPPRESS,
                       help="Minimum automatic candidate score")
    _add_common_args(p_mab)

    p_dot1x = subparsers.add_parser("dot1x", help="802.1X multi-EAP authentication bypass")
    _add_auth_args(p_dot1x)
    _add_common_args(p_dot1x)

    p_relay = subparsers.add_parser("relay", help="Transparent 802.1X bridge relay attack")
    p_relay.add_argument("-i2", "--interface2", default=argparse.SUPPRESS,
                         help="Endpoint-side interface for relay")
    _add_common_args(p_relay)

    p_posture = subparsers.add_parser("posture", help="Posture check detection and bypass only")
    _add_common_args(p_posture)

    p_auto = subparsers.add_parser("auto", help="Auto-detect NAC type and attempt all applicable bypasses")
    p_auto.add_argument("-i2", "--interface2", default=argparse.SUPPRESS,
                        help="Second interface for relay fallback")
    p_auto.add_argument("-m", "--mac", default=argparse.SUPPRESS,
                        help="Specific MAC for MAB mode")
    p_auto.add_argument("--harvest-duration", type=int, default=argparse.SUPPRESS,
                        help="MAC harvest duration in seconds")
    p_auto.add_argument("--min-score", type=float, default=argparse.SUPPRESS,
                        help="Minimum automatic MAB candidate score")
    _add_auth_args(p_auto)
    _add_common_args(p_auto)

    p_post = subparsers.add_parser("post", help="Post-bypass network enumeration")
    _add_common_args(p_post)

    p_restore = subparsers.add_parser(
        "restore-mac", help="Restore the interface's hardware/permanent MAC"
    )
    _add_common_args(p_restore)

    return parser


def _resolve_eap_methods(eap_method_str: str, configured_order: list[str] | None = None) -> list:
    from core.dot1x import EAPMethod, DEFAULT_METHOD_ORDER
    mapping = {
        "peap": EAPMethod.PEAP_MSCHAPV2,
        "peap_mschapv2": EAPMethod.PEAP_MSCHAPV2,
        "ttls_mschapv2": EAPMethod.TTLS_MSCHAPV2,
        "ttls_pap": EAPMethod.TTLS_PAP,
        "pwd": EAPMethod.PWD,
        "md5": EAPMethod.MD5,
        "tls": EAPMethod.TLS,
        "fast": EAPMethod.FAST_MSCHAPV2,
        "fast_mschapv2": EAPMethod.FAST_MSCHAPV2,
        "teap": EAPMethod.TEAP_MSCHAPV2,
        "teap_mschapv2": EAPMethod.TEAP_MSCHAPV2,
        "sim": EAPMethod.SIM,
        "aka": EAPMethod.AKA,
        "aka_prime": EAPMethod.AKA_PRIME,
    }
    if eap_method_str != "auto":
        return [mapping[eap_method_str]]
    if isinstance(configured_order, list) and configured_order:
        unknown = [name for name in configured_order if name not in mapping]
        if unknown:
            raise ValueError(
                f"unsupported EAP method(s) in dot1x.method_order: {', '.join(map(str, unknown))}"
            )
        methods = list(dict.fromkeys(mapping[name] for name in configured_order))
        if methods:
            return methods
    return DEFAULT_METHOD_ORDER


def _dependency_errors(
    command: str,
    dependencies: dict[str, bool],
    *,
    backend: str = "auto",
    interface2: str | None = None,
    dot1x_requested: bool = False,
    methods: list | None = None,
) -> list[str]:
    """Return deterministic, mode-aware dependency failures before state changes."""
    required_by_command = {
        "recon": {"ip"},
        "mab": {"ip", "dhclient", "pkill"},
        "relay": {"ip", "ebtables", "dhclient", "pkill"},
        "posture": {"ip"},
        "post": {"ip"},
        "restore-mac": {"ip", "pkill", "ethtool"},
        "auto": {"ip", "dhclient", "pkill"},
    }
    required = set(required_by_command.get(command, set()))
    errors: list[str] = []

    if command == "auto" and interface2:
        required.add("ebtables")

    needs_dot1x = command == "dot1x" or (command == "auto" and dot1x_requested)
    if needs_dot1x:
        required.add("ip")
        wpa_stack = {"wpa_supplicant", "wpa_cli", "dhclient", "pkill"}
        wpa_ready = all(dependencies.get(name, False) for name in wpa_stack)
        nmcli_ready = dependencies.get("nmcli", False)

        if backend == "wpa_supplicant":
            required.update(wpa_stack)
        elif backend == "nmcli":
            required.add("nmcli")
        elif not wpa_ready and not nmcli_ready:
            errors.append(
                "802.1X requires either the complete "
                "wpa_supplicant/wpa_cli/dhclient/pkill stack or nmcli"
            )
        elif not wpa_ready and nmcli_ready and methods:
            from core.dot1x import EAPMethod, SIM_METHODS

            wpa_only = {
                EAPMethod.FAST_MSCHAPV2,
                EAPMethod.TEAP_MSCHAPV2,
            } | SIM_METHODS
            if all(method in wpa_only for method in methods):
                errors.append(
                    "the selected EAP methods require the wpa_supplicant backend, "
                    "but its complete tool stack is unavailable"
                )

    missing = sorted(name for name in required if not dependencies.get(name, False))
    if missing:
        errors.append(f"missing required system tools: {', '.join(missing)}")
    return errors


def _result_exit_code(command: str, result: dict, *, save_failed: bool = False) -> int:
    """Map command results to stable automation-friendly process exit codes."""
    if save_failed:
        return EXIT_FATAL
    if result.get("cleanup", {}).get("success") is False:
        return EXIT_FATAL
    if command == "doctor":
        return EXIT_OK if result.get("doctor", {}).get("ready", False) else EXIT_NOT_VERIFIED
    if command == "posture":
        posture = result.get("posture", {})
        posture_type = posture.get("posture_type")
        posture_clear = posture.get("bypass_success", False) or (
            getattr(posture_type, "value", posture_type) == "none"
        )
        return (
            EXIT_OK
            if posture_clear and result.get("summary", {}).get("success", False)
            else EXIT_NOT_VERIFIED
        )
    if command in {"mab", "dot1x", "relay", "auto"}:
        return EXIT_OK if result.get("summary", {}).get("success", False) else EXIT_NOT_VERIFIED
    if command == "restore-mac":
        return (
            EXIT_OK
            if result.get("restore_mac", {}).get("success", False)
            else EXIT_NOT_VERIFIED
        )
    # recon and post are evidence-gathering commands. Reaching this point means
    # they completed; findings themselves are not process failures.
    if command in {"recon", "post"}:
        return EXIT_OK
    return EXIT_FATAL


def _print_recon_result(r) -> None:
    table = Table(title="Recon Results", show_header=True)
    table.add_column("Field", style="cyan")
    table.add_column("Value", style="white")
    table.add_row("NAC Type", r.nac_type.name)
    table.add_row("Assigned IPv4", str(r.interface_ip or r.dhcp_lease or "—"))
    table.add_row("Assigned IPv6", ", ".join(r.interface_ipv6) or "—")
    table.add_row("DHCP Offer", str(r.dhcp_offer or "—"))
    table.add_row("Connectivity", "verified" if r.connectivity_verified else "not verified")
    table.add_row("Gateway", str(r.dhcp_gateway or "—"))
    table.add_row("IPv6 Gateway", str(r.ipv6_gateway or "—"))
    table.add_row("IPv6 RA", "observed" if r.ipv6_ra_observed else "—")
    table.add_row("DHCPv6 Advertise", "observed" if r.dhcpv6_advertise else "—")
    table.add_row("IPv6 Prefixes", ", ".join(r.ipv6_prefixes) or "—")
    table.add_row("IPv6 DNS", ", ".join(r.ipv6_dns_servers) or "—")
    table.add_row("Subnet", str(r.dhcp_subnet or "—"))
    table.add_row("EAPOL Frames", str(r.raw_eapol_count))
    eap_names = [f"{t} ({__import__('core.recon', fromlist=['EAP_TYPE_NAMES']).EAP_TYPE_NAMES.get(t, '?')})"
                 for t in r.eap_methods_observed]
    table.add_row("EAP Methods", ", ".join(eap_names) or "—")
    table.add_row("Switch Vendor", str(r.switch_vendor or "—"))
    table.add_row("Switch Port", str(r.switch_port or "—"))
    table.add_row("Duration", f"{r.duration_sec:.1f}s")
    console.print(table)


def _print_doctor_result(result) -> None:
    table = Table(title=f"Doctor Results — {result.mode}", show_header=True)
    table.add_column("Check", style="cyan")
    table.add_column("Required")
    table.add_column("Status")
    table.add_column("Details", overflow="fold")
    for check in result.checks:
        status = "[green]PASS[/green]" if check.success else (
            "[red]FAIL[/red]" if check.required else "[yellow]WARN[/yellow]"
        )
        table.add_row(
            check.name,
            "yes" if check.required else "no",
            status,
            check.details,
        )
    console.print(table)
    if result.ready:
        console.print("[green][+] Environment is ready for the selected mode[/green]")
    else:
        console.print("[red][-] One or more required checks failed[/red]")


def _result_method(bypass_result: dict, recon_value) -> str:
    method = bypass_result.get("method")
    if method:
        return str(method)
    if hasattr(recon_value, "name"):
        return recon_value.name.lower()
    return str(recon_value or "unknown").lower()


def _attach_access_summary(
    result: dict,
    iface: str,
    obtained_ip: str | None,
    method: str,
    timeout: int,
    authorization_success: bool,
    verification_targets: list[dict] | None = None,
    verification_policy: str = "any",
):
    """Attach evidence without equating an assigned address with usable access."""
    import dataclasses
    from core.recon import verify_interface_access

    verification = None
    if obtained_ip:
        verification = verify_interface_access(
            iface,
            timeout=timeout,
            targets=verification_targets,
            policy=verification_policy,
        )
        result["verification"] = dataclasses.asdict(verification)
    access_verified = bool(verification and verification.connectivity_verified)
    result["summary"] = {
        "success": access_verified,
        "authorization_success": authorization_success,
        "outcome": (
            "verified_access" if access_verified
            else "restricted_or_unverified" if obtained_ip
            else "failed"
        ),
        "obtained_ip": obtained_ip,
        "bypass_method": method,
        "network_interface": iface if obtained_ip else None,
    }
    return verification


def cmd_auto(args, logger) -> dict:
    """Intelligent auto mode: recon → choose strategy → bypass → posture → post-auth."""
    from core.recon import run_recon, verify_interface_access, NacType
    from core.mab import run_mab_bypass
    from core.dot1x import run_dot1x, SIM_METHODS
    from core.relay import run_relay
    from core.posture import detect_and_bypass_posture
    from modules.post_auth import run_post_auth
    import dataclasses

    result: dict = {
        "timestamp": datetime.now().isoformat(),
        "interface": args.interface,
        "command": "auto",
    }

    methods = _resolve_eap_methods(args.eap_method, args.eap_method_order)

    console.print("\n[bold cyan][*] Phase 1: NAC Reconnaissance[/bold cyan]")
    recon = run_recon(
        args.interface, timeout=args.recon_timeout,
        dhcp_timeout=args.dhcp_timeout, http_timeout=args.recon_http_timeout,
        verbose=args.verbose,
        verification_targets=getattr(args, "verification_targets", []),
        verification_policy=getattr(args, "verification_policy", "any"),
    )
    result["recon"] = dataclasses.asdict(recon)
    console.print(f"[green][+] NAC Type: {recon.nac_type.name}[/green]")

    obtained_ip = None
    bypass_result = {}
    gateway = recon.dhcp_gateway
    access_iface = args.interface
    authorization_success = False
    posture_handled = False
    recon_address = recon.interface_ip or (
        recon.interface_ipv6[0] if recon.interface_ipv6 else None
    )
    gateway = gateway or recon.ipv6_gateway

    # The default public probe cannot classify internal-only engagements.
    # Check the operator's authoritative targets before changing an interface.
    pre_verified_access = recon.connectivity_verified
    configured_targets = getattr(args, "verification_targets", [])
    if recon_address and configured_targets and not pre_verified_access:
        pre_verification = verify_interface_access(
            args.interface,
            timeout=args.recon_http_timeout,
            targets=configured_targets,
            policy=getattr(args, "verification_policy", "any"),
        )
        result["pre_verification"] = dataclasses.asdict(pre_verification)
        pre_verified_access = pre_verification.connectivity_verified

    console.print("\n[bold cyan][*] Phase 2: Bypass[/bold cyan]")

    if recon_address and (recon.nac_type == NacType.OPEN or pre_verified_access):
        obtained_ip = recon_address
        bypass_result = {
            "method": "already_authorized",
            "success": True,
            "obtained_ip": obtained_ip,
            "details": "Interface already reaches an authorized verification target",
        }
        authorization_success = True
        console.print(f"[green][+] Connectivity already available: {obtained_ip}[/green]")

    elif recon.nac_type in (NacType.DOT1X, NacType.DOT1X_STRICT):
        if args.username or args.creds_file or any(method in SIM_METHODS for method in methods):
            console.print("[*] Attempting 802.1X authentication ...")
            r = run_dot1x(
                args.interface,
                identity=args.username,
                password=args.password,
                creds_file=args.creds_file,
                methods=methods,
                timeout=args.timeout,
                dhcp_timeout=args.dhcp_timeout,
                spray_delay=args.spray_delay,
                backend=args.backend,
                conn_name=args.conn_name,
                client_cert=args.client_cert,
                private_key=args.private_key,
                private_key_passwd=args.private_key_password,
                server_ca_cert=args.server_ca_cert,
                server_domain=args.server_domain,
                anonymous_identity=args.anonymous_identity,
                insecure_no_server_cert=args.insecure_no_server_cert,
                pac_file=args.pac_file,
                fast_provisioning=args.fast_provisioning,
                sim_pin=args.sim_pin,
                sim_pcsc=args.sim_pcsc,
                sim_number=args.sim_number,
                verbose=args.verbose,
            )
            bypass_result = dataclasses.asdict(r)
            if r.success:
                obtained_ip = r.obtained_ip
                authorization_success = True
                console.print(f"[green][+] 802.1X SUCCESS: {obtained_ip}[/green]")
            else:
                console.print("[red][-] 802.1X authentication failed[/red]")
                if args.interface2:
                    console.print(f"[*] Falling back to relay via {args.interface2} ...")
                    relay_result = run_relay(
                        args.interface, args.interface2,
                        auth_timeout=args.relay_timeout,
                        dhcp_timeout=args.dhcp_timeout,
                        bridge_name=args.relay_bridge_name,
                        verbose=args.verbose,
                    )
                    bypass_result = dataclasses.asdict(relay_result)
                    if relay_result.success:
                        obtained_ip = relay_result.obtained_ip
                        authorization_success = True
                        gateway = relay_result.gateway or gateway
                        access_iface = relay_result.network_interface or args.interface
                        console.print(f"[green][+] Relay fallback SUCCESS: {obtained_ip}[/green]")
        elif args.interface2:
            console.print(f"[*] No credentials — attempting relay via {args.interface2} ...")
            r = run_relay(
                args.interface, args.interface2,
                auth_timeout=args.relay_timeout,
                dhcp_timeout=args.dhcp_timeout,
                bridge_name=args.relay_bridge_name,
                verbose=args.verbose,
            )
            bypass_result = dataclasses.asdict(r)
            if r.success:
                obtained_ip = r.obtained_ip
                authorization_success = True
                gateway = r.gateway or gateway
                access_iface = r.network_interface or args.interface
                console.print(f"[green][+] Relay SUCCESS: {obtained_ip}[/green]")
            else:
                console.print("[red][-] Relay attack failed[/red]")
        else:
            console.print("[red][!] DOT1X detected but no credentials or second interface provided[/red]")
            console.print("[yellow][!] Use -u/-p for credentials or -i2 for relay mode[/yellow]")
            result["bypass"] = {"method": "none", "success": False, "error": "No credentials or relay interface"}
            result["summary"] = {
                "success": False,
                "authorization_success": False,
                "outcome": "failed",
                "obtained_ip": None,
                "bypass_method": "none",
                "network_interface": None,
            }
            return result

    elif recon.nac_type in (
        NacType.DHCP_ONLY, NacType.MAB_OR_OPEN,
        NacType.QUARANTINE_VLAN, NacType.UNKNOWN,
    ):
        console.print("[*] Attempting MAB bypass via MAC harvesting ...")
        r = run_mab_bypass(
            args.interface,
            target_mac=args.mac,
            harvest_duration=args.harvest_duration,
            min_score=args.min_score,
            dhcp_timeout=args.dhcp_timeout,
            no_restore=args.no_restore_mac,
            verbose=args.verbose,
        )
        bypass_result = dataclasses.asdict(r)
        if r.success:
            obtained_ip = r.obtained_ip
            authorization_success = True
            gateway = r.gateway or gateway
            console.print(f"[green][+] MAB SUCCESS: spoofed {r.spoofed_mac}, IP={obtained_ip}[/green]")
        else:
            console.print("[red][-] MAB bypass failed[/red]")
            # MAB failed — try 802.1X if we have credentials
            if args.username or args.creds_file or any(method in SIM_METHODS for method in methods):
                console.print("[*] Falling back to 802.1X ...")
                r2 = run_dot1x(
                    args.interface,
                    identity=args.username,
                    password=args.password,
                    creds_file=args.creds_file,
                    methods=methods,
                    timeout=args.timeout,
                    dhcp_timeout=args.dhcp_timeout,
                    spray_delay=args.spray_delay,
                    backend=args.backend,
                    conn_name=args.conn_name,
                    client_cert=args.client_cert,
                    private_key=args.private_key,
                    private_key_passwd=args.private_key_password,
                    server_ca_cert=args.server_ca_cert,
                    server_domain=args.server_domain,
                    anonymous_identity=args.anonymous_identity,
                    insecure_no_server_cert=args.insecure_no_server_cert,
                    pac_file=args.pac_file,
                    fast_provisioning=args.fast_provisioning,
                    sim_pin=args.sim_pin,
                    sim_pcsc=args.sim_pcsc,
                    sim_number=args.sim_number,
                    verbose=args.verbose,
                )
                if r2.success:
                    obtained_ip = r2.obtained_ip
                    authorization_success = True
                    bypass_result = dataclasses.asdict(r2)
                    console.print(f"[green][+] 802.1X fallback SUCCESS: {obtained_ip}[/green]")

            if not obtained_ip and args.interface2:
                console.print(f"[*] Falling back to relay via {args.interface2} ...")
                relay_result = run_relay(
                    args.interface, args.interface2,
                    auth_timeout=args.relay_timeout,
                    dhcp_timeout=args.dhcp_timeout,
                    bridge_name=args.relay_bridge_name,
                    verbose=args.verbose,
                )
                bypass_result = dataclasses.asdict(relay_result)
                if relay_result.success:
                    obtained_ip = relay_result.obtained_ip
                    authorization_success = True
                    gateway = relay_result.gateway or gateway
                    access_iface = relay_result.network_interface or args.interface
                    console.print(f"[green][+] Relay fallback SUCCESS: {obtained_ip}[/green]")

    elif recon.nac_type == NacType.CAPTIVE_PORTAL:
        console.print("[yellow][!] Captive portal detected — attempting posture bypass[/yellow]")
        pr = detect_and_bypass_posture(
            gateway or "", recon_address or recon.dhcp_lease or "",
            probe_timeout=args.posture_timeout, iface=access_iface,
            verbose=args.verbose,
            workflows=getattr(args, "posture_workflows", []),
            verification_targets=getattr(args, "verification_targets", []),
            verification_policy=getattr(args, "verification_policy", "any"),
            signatures=getattr(args, "posture_signatures", None),
        )
        bypass_result = dataclasses.asdict(pr)
        bypass_result.update({
            "method": "posture",
            "success": pr.bypass_success,
            "obtained_ip": recon_address,
        })
        result["posture"] = dataclasses.asdict(pr)
        posture_handled = True
        obtained_ip = recon_address
        authorization_success = pr.bypass_success
        if obtained_ip:
            console.print(f"[yellow][!] Using pre-assigned IP: {obtained_ip}[/yellow]")

    result["bypass"] = bypass_result

    if obtained_ip and not args.no_posture and not posture_handled:
        console.print("\n[bold cyan][*] Phase 3: Posture Check[/bold cyan]")
        posture_gw = gateway or ""
        pr = detect_and_bypass_posture(
            posture_gw, obtained_ip, probe_timeout=args.posture_timeout,
            iface=access_iface, verbose=args.verbose,
            workflows=getattr(args, "posture_workflows", []),
            verification_targets=getattr(args, "verification_targets", []),
            verification_policy=getattr(args, "verification_policy", "any"),
            signatures=getattr(args, "posture_signatures", None),
        )
        result["posture"] = dataclasses.asdict(pr)
        if pr.posture_type.value == "none":
            console.print("[green][+] No posture check detected[/green]")
        elif pr.bypass_success:
            console.print("[green][+] Posture bypass succeeded[/green]")
        else:
            console.print(f"[yellow][!] Posture: {pr.posture_type.value} — {pr.details}[/yellow]")

    verification = None
    access_verified = False
    if obtained_ip:
        verification = verify_interface_access(
            access_iface,
            timeout=args.recon_http_timeout,
            targets=getattr(args, "verification_targets", []),
            policy=getattr(args, "verification_policy", "any"),
        )
        result["verification"] = dataclasses.asdict(verification)
        access_verified = verification.connectivity_verified
        if access_verified:
            console.print(
                f"[green][+] Interface-bound access verified on {access_iface}[/green]"
            )
        else:
            console.print(
                f"[yellow][!] Authorization evidence exists, but usable access is not verified "
                f"(state={verification.state.name}, error={verification.error or 'none'})[/yellow]"
            )

    if obtained_ip and access_verified and not args.no_post:
        console.print("\n[bold cyan][*] Phase 4: Post-Auth Enumeration[/bold cyan]")
        pa = run_post_auth(
            access_iface, obtained_ip,
            arp_sweep=args.post_arp_sweep, port_scan=args.post_port_scan,
            arp_timeout=args.post_arp_timeout,
            port_scan_timeout=args.post_port_scan_timeout,
            ports=args.post_ports, max_hosts=args.post_max_hosts,
            nac_probe_timeout=args.post_nac_probe_timeout,
            nac_signatures=getattr(args, "posture_signatures", None),
            verbose=args.verbose,
        )
        result["post_auth"] = dataclasses.asdict(pa)
        console.print(f"[green][+] Discovered {len(pa.discovered_hosts)} hosts in {pa.subnet}[/green]")
        if pa.nac_server_type:
            console.print(f"[yellow][!] NAC server: {pa.nac_server_type} at {pa.nac_server_ip}[/yellow]")
    elif obtained_ip and not access_verified and not args.no_post:
        result["post_auth_skipped"] = (
            "Interface-bound usable access was not verified; active enumeration was skipped"
        )

    method = _result_method(
        bypass_result, result.get("recon", {}).get("nac_type")
    )
    if method == "relay" and not Cleanup.relay_workers_healthy():
        access_verified = False
        result["relay_forwarding_healthy"] = False
        console.print("[red][!] Relay forwarding stopped before assessment completed[/red]")
    result["summary"] = {
        "success": access_verified,
        "authorization_success": authorization_success,
        "outcome": (
            "verified_access" if access_verified
            else "restricted_or_unverified" if obtained_ip
            else "failed"
        ),
        "obtained_ip": obtained_ip,
        "bypass_method": method,
        "network_interface": access_iface if obtained_ip else None,
    }

    return result


def main():
    parser = build_parser()
    args = parser.parse_args()
    if args.command == "recover":
        require_root()
        output_dir = _g(args, "output", "output") or "output"
        verbose = bool(_g(args, "verbose", False))
        logger = setup_logging(verbose, output_dir)
        console.print(Panel.fit(
            "[bold red]NACleaver[/bold red] — Persistent State Recovery\n"
            "[dim]Only root-owned NACleaver journals are processed[/dim]",
            border_style="red",
        ))
        try:
            recovered = Cleanup.recover_journals(force=bool(args.force))
        except Exception as exc:
            console.print(f"[red][!] Recovery failed: {exc}[/red]")
            return 1
        result = {
            "timestamp": datetime.now().isoformat(),
            "command": "recover",
            "journals": recovered,
        }
        if not recovered:
            console.print("[green][+] No stale cleanup journal found[/green]")
        for record in recovered:
            if record.get("recovered"):
                console.print(f"[green][+] Recovered {record['journal']}[/green]")
            elif record.get("skipped"):
                console.print(
                    f"[yellow][!] Skipped {record['journal']}: {record['skipped']}[/yellow]"
                )
            else:
                console.print(
                    f"[red][-] Recovery incomplete for {record['journal']}: "
                    f"{record.get('error', 'unknown error')}[/red]"
                )
        try:
            path = save_json_result(result, output_dir)
            console.print(f"\n[green][+] Results saved to {path}[/green]")
        except Exception as exc:
            logger.warning(f"Failed to save recovery results: {exc}")
        return 0 if all(item.get("recovered") for item in recovered) else 2

    if not getattr(args, "interface", None):
        parser.error("-i/--interface is required")
    if args.command != "doctor" and not validate_interface(args.interface):
        parser.error(f"interface does not exist: {args.interface}")
    if getattr(args, "interface2", None):
        if args.command != "doctor" and not validate_interface(args.interface2):
            parser.error(f"second interface does not exist: {args.interface2}")
        if args.command != "doctor" and args.interface2 == args.interface:
            parser.error("primary and second interface must be different")
    if args.command != "doctor":
        require_root()
    try:
        config = load_config(args.config, strict=True)
    except ValueError as exc:
        parser.error(str(exc))

    cli_timeout = _g(args, "timeout")
    verbose = bool(_g(args, "verbose", False))
    no_restore_mac = bool(_g(args, "no_restore_mac", False))
    no_posture = bool(_g(args, "no_posture", False))
    no_post = bool(_g(args, "no_post", False))
    username = _g(args, "username")
    password = _g(args, "password", "") or ""
    creds_file = _g(args, "creds_file")
    mac = _g(args, "mac")
    try:
        harvest_dur = int(_g(args, "harvest_duration", config_value(config, "mab", "harvest_duration", 60)))
        min_score = float(_g(args, "min_score", config_value(config, "mab", "min_score", 15.0)))
    except (TypeError, ValueError) as exc:
        parser.error(f"invalid MAB numeric setting: {exc}")
    eap_method = _g(args, "eap_method", "auto")
    try:
        spray_delay = float(_g(args, "spray_delay", config_value(config, "dot1x", "spray_delay", 2.0)))
    except (TypeError, ValueError) as exc:
        parser.error(f"invalid dot1x.spray_delay: {exc}")
    backend = _g(args, "backend", config_value(config, "dot1x", "preferred_backend", "auto"))
    conn_name = _g(args, "conn_name", "NACleaver-8021x")
    client_cert = _g(args, "client_cert")
    private_key = _g(args, "private_key")
    private_key_password = _g(
        args,
        "private_key_password",
        config_value(config, "dot1x", "private_key_password", None),
    )
    server_ca_cert = _g(
        args, "server_ca_cert", config_value(config, "dot1x", "server_ca_cert", None)
    )
    server_domain = _g(
        args, "server_domain", config_value(config, "dot1x", "server_domain", None)
    )
    anonymous_identity = _g(
        args, "anonymous_identity", config_value(config, "dot1x", "anonymous_identity", None)
    )
    insecure_no_server_cert_value = _g(
        args,
        "insecure_no_server_cert",
        config_value(config, "dot1x", "insecure_no_server_cert", False),
    )
    if not isinstance(insecure_no_server_cert_value, bool):
        parser.error("dot1x.insecure_no_server_cert must be true or false")
    insecure_no_server_cert = insecure_no_server_cert_value
    pac_file = _g(args, "pac_file", config_value(config, "dot1x", "pac_file", None))
    fast_provisioning = _g(
        args, "fast_provisioning", config_value(config, "dot1x", "fast_provisioning", 0)
    )
    sim_pin = _g(args, "sim_pin", config_value(config, "dot1x", "sim_pin", None))
    sim_pcsc = _g(args, "sim_pcsc", config_value(config, "dot1x", "sim_pcsc", ""))
    sim_number = _g(args, "sim_number", config_value(config, "dot1x", "sim_number", None))
    interface2 = _g(args, "interface2")
    if args.command == "relay" and not interface2:
        parser.error("relay requires -i2/--interface2")

    try:
        recon_timeout = int(
            cli_timeout if cli_timeout is not None
            else config_value(config, "recon", "eapol_timeout", 30)
        )
        recon_http_timeout = int(config_value(config, "recon", "http_timeout", 5))
        auth_timeout = int(
            cli_timeout if cli_timeout is not None
            else config_value(config, "dot1x", "default_timeout", 15)
        )
        relay_timeout = int(
            cli_timeout if cli_timeout is not None
            else config_value(config, "relay", "auth_timeout", 90)
        )
        if _g(args, "dhcp_timeout") is not None:
            dhcp_timeout = int(_g(args, "dhcp_timeout"))
        elif args.command == "relay":
            dhcp_timeout = int(config_value(config, "relay", "dhcp_timeout", 15))
        elif args.command == "recon":
            dhcp_timeout = int(config_value(config, "recon", "dhcp_timeout", 10))
        else:
            dhcp_timeout = int(config_value(config, "mab", "dhcp_timeout", 30))

        posture_timeout = int(config_value(config, "posture", "probe_timeout", 5))
        post_arp_sweep = bool(config_value(config, "post_auth", "arp_sweep", True))
        post_port_scan = bool(config_value(config, "post_auth", "port_scan", True))
        post_arp_timeout = int(config_value(config, "post_auth", "arp_timeout", 2))
        post_port_scan_timeout = float(config_value(config, "post_auth", "port_scan_timeout", 0.5))
        configured_ports = config_value(config, "post_auth", "ports", [])
        post_ports = [int(port) for port in configured_ports] if isinstance(configured_ports, list) else None
        post_max_hosts = int(config_value(config, "post_auth", "max_hosts", 1024))
        post_nac_probe_timeout = float(config_value(config, "post_auth", "nac_probe_timeout", 1.0))
    except (TypeError, ValueError) as exc:
        parser.error(f"invalid numeric value in config: {exc}")
    method_order = config_value(config, "dot1x", "method_order", None)
    if method_order is not None and (
        not isinstance(method_order, list)
        or any(not isinstance(name, str) for name in method_order)
    ):
        parser.error("dot1x.method_order must be a list of EAP method names")
    try:
        configured_methods = _resolve_eap_methods(eap_method, method_order)
    except (KeyError, ValueError) as exc:
        parser.error(str(exc))
    from core.dot1x import EAPMethod, SIM_METHODS
    if EAPMethod.FAST_MSCHAPV2 in configured_methods and not pac_file:
        parser.error("EAP-FAST in the selected method set requires --pac-file or dot1x.pac_file")
    if any(method in SIM_METHODS for method in configured_methods) and sim_pcsc is None:
        parser.error("EAP-SIM/AKA/AKA' requires a PC/SC reader selection")
    wpa_only_methods = {EAPMethod.FAST_MSCHAPV2, EAPMethod.TEAP_MSCHAPV2} | SIM_METHODS
    if backend == "nmcli" and configured_methods and all(
        method in wpa_only_methods for method in configured_methods
    ):
        parser.error(
            "the selected EAP method set requires --backend wpa_supplicant or auto"
        )
    relay_bridge_name = str(config_value(config, "relay", "bridge_name", "nacleaver_br"))
    posture_workflows = config_value(config, "posture", "http_workflows", [])
    try:
        from core.posture import validate_workflows
        posture_workflows = validate_workflows(posture_workflows)
    except ValueError as exc:
        parser.error(str(exc))
    posture_signatures = config_value(config, "posture", "signatures", None)
    try:
        from core.fingerprints import validated_signatures
        posture_signatures = validated_signatures(posture_signatures)
    except ValueError as exc:
        parser.error(str(exc))
    verification_targets = config_value(config, "verification", "targets", [])
    verification_policy = str(
        config_value(config, "verification", "policy", "any")
    ).lower()
    if not isinstance(verification_targets, list):
        parser.error("verification.targets must be a list")
    if verification_policy not in {"any", "all"}:
        parser.error("verification.policy must be any or all")

    positive_values = {
        "timeout": auth_timeout,
        "recon timeout": recon_timeout,
        "recon HTTP timeout": recon_http_timeout,
        "relay timeout": relay_timeout,
        "DHCP timeout": dhcp_timeout,
        "harvest duration": harvest_dur,
        "posture timeout": posture_timeout,
        "post-auth ARP timeout": post_arp_timeout,
        "post-auth max hosts": post_max_hosts,
    }
    for label, value in positive_values.items():
        if value <= 0:
            parser.error(f"{label} must be greater than zero")
    if min_score < 0:
        parser.error("minimum MAB score cannot be negative")
    if not math.isfinite(min_score):
        parser.error("minimum MAB score must be finite")
    if not math.isfinite(spray_delay) or spray_delay < 0:
        parser.error("spray delay must be a finite, non-negative number")
    if not math.isfinite(post_port_scan_timeout) or post_port_scan_timeout <= 0:
        parser.error("post_auth.port_scan_timeout must be a finite positive number")
    if not math.isfinite(post_nac_probe_timeout) or post_nac_probe_timeout <= 0:
        parser.error("post_auth.nac_probe_timeout must be a finite positive number")
    if post_max_hosts > 4096:
        parser.error("post_auth.max_hosts cannot exceed 4096")
    if post_ports and any(port < 1 or port > 65535 for port in post_ports):
        parser.error("post_auth.ports must contain values from 1 to 65535")
    if backend not in {"auto", "wpa_supplicant", "nmcli"}:
        parser.error("dot1x.preferred_backend must be auto, wpa_supplicant, or nmcli")
    if server_ca_cert and insecure_no_server_cert:
        parser.error("--server-ca-cert and --insecure-no-server-cert are mutually exclusive")
    if isinstance(fast_provisioning, bool) or fast_provisioning not in {0, 1, 2, 3}:
        parser.error("dot1x.fast_provisioning must be 0, 1, 2, or 3")
    if sim_number is not None and (isinstance(sim_number, bool) or sim_number < 0):
        parser.error("dot1x.sim_number must be a non-negative integer")
    if args.command in {"dot1x", "auto"}:
        for label, value in {
            "client certificate": client_cert,
            "private key": private_key,
            "server CA certificate": server_ca_cert,
            "server domain": server_domain,
            "anonymous identity": anonymous_identity,
            "private key password": private_key_password,
            "PAC file": pac_file,
            "SIM PIN": sim_pin,
            "PC/SC reader": sim_pcsc,
        }.items():
            if value is not None and not isinstance(value, str):
                parser.error(f"{label} must be a string")
        auth_paths = {
            "credential file": creds_file,
            "client certificate": client_cert,
            "private key": private_key,
            "server CA certificate": server_ca_cert,
        }
        for label, path in auth_paths.items():
            if path and not Path(path).is_file():
                parser.error(f"{label} does not exist or is not a file: {path}")
        if bool(client_cert) != bool(private_key):
            parser.error("--client-cert and --private-key must be supplied together")
        if eap_method == "tls" and not (client_cert and private_key):
            parser.error("EAP-TLS requires --client-cert and --private-key")
        if eap_method == "fast" and not pac_file:
            parser.error("EAP-FAST requires --pac-file or dot1x.pac_file")
        for label, value in {
            "server domain": server_domain,
            "anonymous identity": anonymous_identity,
            "private key password": private_key_password,
            "SIM PIN": sim_pin,
            "PC/SC reader": sim_pcsc,
        }.items():
            if value and ("\n" in value or "\r" in value):
                parser.error(f"{label} cannot contain newlines")
    if not re.fullmatch(r"[A-Za-z0-9_.-]{1,15}", relay_bridge_name):
        parser.error("relay.bridge_name must be a valid Linux interface name (1-15 characters)")

    output_dir = _g(args, "output", "output") or "output"
    logger = setup_logging(verbose, output_dir)
    atexit.register(Cleanup.run_all)

    def handle_signal(signum, _frame):
        Cleanup.run_all()
        raise SystemExit(128 + signum)

    signal.signal(signal.SIGINT, handle_signal)
    signal.signal(signal.SIGTERM, handle_signal)

    deps = check_all_dependencies()
    dot1x_requested = bool(
        username
        or creds_file
        or any(method in SIM_METHODS for method in configured_methods)
    )
    dependency_errors = _dependency_errors(
        args.command,
        deps,
        backend=backend,
        interface2=interface2,
        dot1x_requested=dot1x_requested,
        methods=configured_methods,
    )
    if dependency_errors:
        for error in dependency_errors:
            console.print(f"[bold red][!] Dependency preflight failed: {error}[/bold red]")
        return EXIT_FATAL

    scapy_commands = {"recon", "mab", "relay", "auto"}
    if args.command == "post" and post_arp_sweep:
        scapy_commands.add("post")
    required_python_modules = ["scapy"] if args.command in scapy_commands else []
    python_deps = check_python_dependencies(required_python_modules)
    missing_python = sorted(
        name for name, available in python_deps.items() if not available
    )
    if missing_python:
        console.print(
            "[bold red][!] Missing Python module(s) for "
            f"{args.command}: {', '.join(missing_python)}[/bold red]"
        )
        console.print(
            f"[yellow][!] Install with the same interpreter: "
            f"{sys.executable} -m pip install -r requirements.txt[/yellow]"
        )
        return EXIT_FATAL

    # Do not create persistent recovery state until every fail-fast preflight
    # has passed. From this point onward commands may alter interface state.
    if args.command in {"mab", "dot1x", "relay", "auto"}:
        Cleanup.enable_journal()
    if no_restore_mac:
        Cleanup.disable_mac_restore()

    console.print(Panel.fit(
        "[bold red]NACleaver[/bold red] — NAC Bypass Framework\n"
        "[dim]For authorized penetration testing only[/dim]",
        border_style="red",
    ))

    result: dict = {
        "timestamp": datetime.now().isoformat(),
        "interface": args.interface,
        "command": args.command,
    }

    args.username = username
    args.password = password
    args.creds_file = creds_file
    args.mac = mac
    args.harvest_duration = harvest_dur
    args.min_score = min_score
    args.eap_method = eap_method
    args.eap_method_order = method_order
    args.spray_delay = spray_delay
    args.backend = backend
    args.conn_name = conn_name
    args.client_cert = client_cert
    args.private_key = private_key
    args.private_key_password = private_key_password
    args.server_ca_cert = server_ca_cert
    args.server_domain = server_domain
    args.anonymous_identity = anonymous_identity
    args.insecure_no_server_cert = insecure_no_server_cert
    args.pac_file = pac_file
    args.fast_provisioning = fast_provisioning
    args.sim_pin = sim_pin
    args.sim_pcsc = sim_pcsc
    args.sim_number = sim_number
    args.interface2 = interface2
    args.timeout = auth_timeout
    args.recon_timeout = recon_timeout
    args.recon_http_timeout = recon_http_timeout
    args.relay_timeout = relay_timeout
    args.relay_bridge_name = relay_bridge_name
    args.dhcp_timeout = dhcp_timeout
    args.posture_timeout = posture_timeout
    args.posture_workflows = posture_workflows
    args.posture_signatures = posture_signatures
    args.verification_targets = verification_targets
    args.verification_policy = verification_policy
    args.post_arp_sweep = post_arp_sweep
    args.post_port_scan = post_port_scan
    args.post_arp_timeout = post_arp_timeout
    args.post_port_scan_timeout = post_port_scan_timeout
    args.post_ports = post_ports
    args.post_max_hosts = post_max_hosts
    args.post_nac_probe_timeout = post_nac_probe_timeout
    args.verbose = verbose
    args.no_restore_mac = no_restore_mac
    args.no_posture = no_posture
    args.no_post = no_post

    try:
        if args.command == "doctor":
            from core.doctor import run_doctor
            import dataclasses
            r = run_doctor(
                args.interface,
                mode=args.doctor_mode,
                interface2=interface2,
            )
            _print_doctor_result(r)
            result["doctor"] = dataclasses.asdict(r)

        elif args.command == "recon":
            from core.recon import run_recon
            r = run_recon(
                args.interface, timeout=recon_timeout,
                dhcp_timeout=dhcp_timeout, http_timeout=recon_http_timeout,
                verbose=verbose,
                verification_targets=verification_targets,
                verification_policy=verification_policy,
            )
            _print_recon_result(r)
            import dataclasses
            result["recon"] = dataclasses.asdict(r)

        elif args.command == "mab":
            from core.mab import run_mab_bypass
            r = run_mab_bypass(
                args.interface,
                target_mac=mac,
                harvest_duration=harvest_dur,
                min_score=min_score, dhcp_timeout=dhcp_timeout,
                no_restore=no_restore_mac,
                verbose=verbose,
            )
            import dataclasses
            result["mab"] = dataclasses.asdict(r)
            verification = _attach_access_summary(
                result, args.interface, r.obtained_ip, "mab",
                recon_http_timeout, r.success,
                verification_targets, verification_policy,
            )
            if r.success:
                if verification and verification.connectivity_verified:
                    console.print(
                        f"[green][+] MAB access verified: spoofed {r.spoofed_mac}, "
                        f"IP={r.obtained_ip}[/green]"
                    )
                else:
                    state = verification.state.name if verification else "UNKNOWN"
                    console.print(
                        f"[yellow][!] MAC change and address assignment succeeded, but usable access "
                        f"was not verified (state={state})[/yellow]"
                    )
            else:
                console.print(f"[red][-] MAB bypass failed: {r.error}[/red]")

        elif args.command == "dot1x":
            from core.dot1x import run_dot1x
            methods = _resolve_eap_methods(eap_method, method_order)
            r = run_dot1x(
                args.interface,
                identity=username,
                password=password,
                creds_file=creds_file,
                methods=methods,
                timeout=auth_timeout,
                dhcp_timeout=dhcp_timeout,
                spray_delay=spray_delay,
                backend=backend,
                conn_name=conn_name,
                client_cert=client_cert,
                private_key=private_key,
                private_key_passwd=private_key_password,
                server_ca_cert=server_ca_cert,
                server_domain=server_domain,
                anonymous_identity=anonymous_identity,
                insecure_no_server_cert=insecure_no_server_cert,
                pac_file=pac_file,
                fast_provisioning=fast_provisioning,
                sim_pin=sim_pin,
                sim_pcsc=sim_pcsc,
                sim_number=sim_number,
                verbose=verbose,
            )
            import dataclasses
            result["dot1x"] = dataclasses.asdict(r)
            verification = _attach_access_summary(
                result, args.interface, r.obtained_ip, "dot1x",
                recon_http_timeout, r.success,
                verification_targets, verification_policy,
            )
            if r.success:
                if verification and verification.connectivity_verified:
                    console.print(
                        f"[green][+] 802.1X access verified: "
                        f"{r.method_used.value} → {r.obtained_ip}[/green]"
                    )
                else:
                    state = verification.state.name if verification else "UNKNOWN"
                    console.print(
                        f"[yellow][!] 802.1X and address assignment succeeded, but usable access "
                        f"was not verified (state={state})[/yellow]"
                    )
            else:
                console.print(f"[red][-] 802.1X failed: {r.error}[/red]")

        elif args.command == "relay":
            if not interface2:
                console.print("[red][!] Relay mode requires -i2/--interface2[/red]")
                sys.exit(1)
            from core.relay import run_relay
            r = run_relay(
                args.interface,
                interface2,
                auth_timeout=relay_timeout,
                dhcp_timeout=dhcp_timeout,
                bridge_name=relay_bridge_name,
                verbose=verbose,
            )
            import dataclasses
            result["relay"] = dataclasses.asdict(r)
            relay_iface = r.network_interface or args.interface
            verification = _attach_access_summary(
                result, relay_iface, r.obtained_ip, "relay",
                recon_http_timeout, r.success,
                verification_targets, verification_policy,
            )
            if r.success and not Cleanup.relay_workers_healthy():
                result["summary"]["success"] = False
                result["relay_forwarding_healthy"] = False
                console.print("[red][!] Relay forwarding stopped before assessment completed[/red]")
            if r.success:
                if result["summary"]["success"]:
                    console.print(
                        f"[green][+] Relay access verified: IP={r.obtained_ip}, "
                        f"frames={r.eapol_frames_relayed}[/green]"
                    )
                else:
                    state = verification.state.name if verification else "UNKNOWN"
                    console.print(
                        f"[yellow][!] Relay authentication and address assignment succeeded, but usable "
                        f"access was not verified (state={state})[/yellow]"
                    )
            else:
                console.print(f"[red][-] Relay failed: {r.error}[/red]")

        elif args.command == "posture":
            from core.posture import detect_and_bypass_posture
            ip = get_iface_ip(args.interface) or get_iface_ipv6(args.interface)
            if not ip:
                console.print("[red][!] No IP on interface — run a bypass first[/red]")
                sys.exit(1)
            r = detect_and_bypass_posture(
                gateway=(
                    get_iface_gateway(args.interface)
                    or get_iface_gateway6(args.interface)
                    or ""
                ),
                obtained_ip=ip,
                probe_timeout=posture_timeout,
                iface=args.interface,
                verbose=args.verbose,
                workflows=posture_workflows,
                verification_targets=verification_targets,
                verification_policy=verification_policy,
                signatures=posture_signatures,
            )
            import dataclasses
            result["posture"] = dataclasses.asdict(r)
            verification = _attach_access_summary(
                result, args.interface, ip, "posture",
                recon_http_timeout,
                r.bypass_success or r.posture_type.value == "none",
                verification_targets, verification_policy,
            )
            console.print(f"[*] Posture type: {r.posture_type.value}")
            if r.bypass_attempted:
                status = "[green]SUCCESS[/green]" if r.bypass_success else "[red]FAILED[/red]"
                console.print(f"[*] Bypass: {status}")
            if verification and not verification.connectivity_verified:
                console.print(
                    f"[yellow][!] Usable access is not verified "
                    f"(state={verification.state.name})[/yellow]"
                )

        elif args.command == "post":
            from modules.post_auth import run_post_auth
            ip = get_iface_ip(args.interface) or get_iface_ipv6(args.interface)
            if not ip:
                console.print("[red][!] No IP on interface — run a bypass first[/red]")
                sys.exit(1)
            r = run_post_auth(
                args.interface, ip, arp_sweep=post_arp_sweep,
                port_scan=post_port_scan, arp_timeout=post_arp_timeout,
                port_scan_timeout=post_port_scan_timeout,
                ports=post_ports, max_hosts=post_max_hosts,
                nac_probe_timeout=post_nac_probe_timeout,
                nac_signatures=posture_signatures,
                verbose=args.verbose,
            )
            import dataclasses
            result["post_auth"] = dataclasses.asdict(r)
            console.print(f"[green][+] Found {len(r.discovered_hosts)} hosts in {r.subnet}[/green]")
            if r.nac_server_type:
                console.print(f"[yellow][!] NAC: {r.nac_server_type} @ {r.nac_server_ip}[/yellow]")

        elif args.command == "restore-mac":
            success, permanent_mac, error = restore_permanent_mac(args.interface)
            result["restore_mac"] = {
                "success": success,
                "permanent_mac": permanent_mac,
                "error": error,
            }
            if success:
                console.print(
                    f"[green][+] Permanent MAC restored and verified: {permanent_mac}[/green]"
                )
            else:
                console.print(f"[red][-] Permanent MAC restore failed: {error}[/red]")

        elif args.command == "auto":
            result = cmd_auto(args, logger)

    except KeyboardInterrupt:
        console.print("\n[yellow][!] Interrupted by user[/yellow]")
        Cleanup.run_all()
        sys.exit(0)
    except Exception as e:
        console.print(f"[red][!] Fatal error: {e}[/red]")
        if args.verbose:
            import traceback
            traceback.print_exc()
        sys.exit(1)

    # Finish network restoration before deciding whether the command succeeded.
    # atexit remains as a fallback for exceptional paths and is idempotent.
    try:
        cleanup_success = Cleanup.run_all()
        cleanup_error = None
    except Exception as exc:
        cleanup_success = False
        cleanup_error = str(exc)
        logger.error(f"Cleanup failed: {exc}")
    result["cleanup"] = {
        "success": cleanup_success,
        "recovery_required": not cleanup_success,
        "error": cleanup_error,
    }
    if not cleanup_success:
        console.print("[red][!] Network cleanup incomplete; run recover before reuse[/red]")

    save_failed = False
    try:
        path = save_json_result(result, output_dir)
        console.print(f"\n[green][+] Results saved to {path}[/green]")
    except Exception as e:
        logger.warning(f"Failed to save results: {e}")
        save_failed = True

    return _result_exit_code(args.command, result, save_failed=save_failed)


if __name__ == "__main__":
    raise SystemExit(main())
