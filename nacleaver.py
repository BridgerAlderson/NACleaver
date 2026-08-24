#!/usr/bin/env python3
"""NACleaver — NAC Bypass Framework for Authorized Penetration Testing"""

import argparse
import atexit
import json
import logging
import signal
import sys
import time
from datetime import datetime
from pathlib import Path

from rich.console import Console
from rich.panel import Panel
from rich.table import Table
from rich import print as rprint

from core.utils import (
    Cleanup,
    check_all_dependencies,
    get_iface_ip,
    require_root,
    save_json_result,
    setup_logging,
)

console = Console()


def _add_common_args(p: argparse.ArgumentParser) -> None:
    """Add universal flags to a subparser so they work after the subcommand."""
    p.add_argument("--timeout", type=int, default=None,
                   help="Timeout per attempt in seconds")
    p.add_argument("--no-restore-mac", action="store_true", default=None,
                   help="Do not restore original MAC on exit")
    p.add_argument("--no-posture", action="store_true", default=None,
                   help="Skip posture bypass attempt after successful auth")
    p.add_argument("--no-post", action="store_true", default=None,
                   help="Skip post-auth network enumeration")
    p.add_argument("-v", "--verbose", action="store_true", default=None,
                   help="Verbose output")


def _add_auth_args(p: argparse.ArgumentParser) -> None:
    """Add 802.1X auth flags to a subparser (dot1x, auto)."""
    p.add_argument("-u", "--username", default=None, help="Username for 802.1X")
    p.add_argument("-p", "--password", default=None, help="Password for 802.1X")
    p.add_argument("-C", "--creds-file", default=None,
                   help="Credential file (user:pass per line)")
    p.add_argument("--eap-method", default=None,
                   choices=["peap", "ttls_mschapv2", "ttls_pap", "pwd", "md5", "tls", "auto"],
                   help="EAP method for 802.1X")
    p.add_argument("--spray-delay", type=float, default=None,
                   help="Delay between spray attempts in seconds")
    p.add_argument("--backend", default=None,
                   choices=["wpa_supplicant", "nmcli", "auto"],
                   help="802.1X backend")
    p.add_argument("--conn-name", default=None, help="nmcli connection name")
    p.add_argument("--client-cert", default=None,
                   help="Client certificate path for EAP-TLS")
    p.add_argument("--private-key", default=None,
                   help="Private key path for EAP-TLS")


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
  nacleaver -i eth0 recon
  nacleaver -i eth0 mab
  nacleaver -i eth0 mab --mac aa:bb:cc:dd:ee:ff
  nacleaver -i eth0 dot1x -u pentest -p 'Password123'
  nacleaver -i eth0 dot1x -C creds.txt --eap-method peap
  nacleaver -i eth0 relay -i2 eth1
  nacleaver -i eth0 auto -u pentest -p 'Password123'
        """,
    )
    parser.add_argument("-i", "--interface", required=True,
                        help="Primary network interface (e.g. eth0, ens33)")
    parser.add_argument("-i2", "--interface2",
                        help="Second interface — required for relay mode (e.g. eth1)")
    parser.add_argument("-u", "--username", help="Username for 802.1X")
    parser.add_argument("-p", "--password", default="", help="Password for 802.1X")
    parser.add_argument("-C", "--creds-file", help="Credential file (user:pass per line)")
    parser.add_argument("-m", "--mac", help="Specific MAC to spoof in MAB mode")
    parser.add_argument("--timeout", type=int, default=15,
                        help="Timeout per attempt in seconds (default: 15)")
    parser.add_argument("--harvest-duration", type=int, default=60,
                        help="MAC harvest duration for MAB mode (default: 60)")
    parser.add_argument("--eap-method",
                        choices=["peap", "ttls_mschapv2", "ttls_pap", "pwd", "md5", "tls", "auto"],
                        default="auto",
                        help="EAP method for 802.1X (default: auto/priority order)")
    parser.add_argument("--spray-delay", type=float, default=2.0,
                        help="Delay between spray attempts in seconds (default: 2.0)")
    parser.add_argument("--backend", choices=["wpa_supplicant", "nmcli", "auto"], default="auto",
                        help="802.1X backend (default: auto)")
    parser.add_argument("--conn-name", default="NACleaver-8021x",
                        help="nmcli connection name (default: NACleaver-8021x)")
    parser.add_argument("--client-cert", help="Client certificate path for EAP-TLS")
    parser.add_argument("--private-key", help="Private key path for EAP-TLS")
    parser.add_argument("--no-restore-mac", action="store_true",
                        help="Do not restore original MAC on exit")
    parser.add_argument("--no-posture", action="store_true",
                        help="Skip posture bypass attempt after successful auth")
    parser.add_argument("--no-post", action="store_true",
                        help="Skip post-auth network enumeration")
    parser.add_argument("-o", "--output", help="Output directory for JSON results (default: output/)")
    parser.add_argument("-v", "--verbose", action="store_true", help="Verbose output")

    subparsers = parser.add_subparsers(dest="command", required=True)

    p_recon = subparsers.add_parser("recon", help="Detect NAC type on the connected segment")
    _add_common_args(p_recon)

    p_mab = subparsers.add_parser("mab", help="MAB bypass via passive MAC harvesting and spoofing")
    p_mab.add_argument("-m", "--mac", default=None, help="Specific MAC to spoof")
    p_mab.add_argument("--harvest-duration", type=int, default=None,
                       help="MAC harvest duration in seconds")
    _add_common_args(p_mab)

    p_dot1x = subparsers.add_parser("dot1x", help="802.1X multi-EAP authentication bypass")
    _add_auth_args(p_dot1x)
    _add_common_args(p_dot1x)

    p_relay = subparsers.add_parser("relay", help="Transparent 802.1X bridge relay attack")
    p_relay.add_argument("-i2", "--interface2", default=None,
                         help="Endpoint-side interface for relay")
    _add_common_args(p_relay)

    p_posture = subparsers.add_parser("posture", help="Posture check detection and bypass only")
    _add_common_args(p_posture)

    p_auto = subparsers.add_parser("auto", help="Auto-detect NAC type and attempt all applicable bypasses")
    p_auto.add_argument("-i2", "--interface2", default=None,
                        help="Second interface for relay fallback")
    p_auto.add_argument("-m", "--mac", default=None, help="Specific MAC for MAB mode")
    p_auto.add_argument("--harvest-duration", type=int, default=None,
                        help="MAC harvest duration in seconds")
    _add_auth_args(p_auto)
    _add_common_args(p_auto)

    p_post = subparsers.add_parser("post", help="Post-bypass network enumeration")
    _add_common_args(p_post)

    return parser


def _resolve_eap_methods(eap_method_str: str) -> list:
    from core.dot1x import EAPMethod, DEFAULT_METHOD_ORDER
    if eap_method_str == "auto":
        return DEFAULT_METHOD_ORDER
    mapping = {
        "peap": EAPMethod.PEAP_MSCHAPV2,
        "ttls_mschapv2": EAPMethod.TTLS_MSCHAPV2,
        "ttls_pap": EAPMethod.TTLS_PAP,
        "pwd": EAPMethod.PWD,
        "md5": EAPMethod.MD5,
        "tls": EAPMethod.TLS,
    }
    return [mapping[eap_method_str]]


def _print_recon_result(r) -> None:
    table = Table(title="Recon Results", show_header=True)
    table.add_column("Field", style="cyan")
    table.add_column("Value", style="white")
    table.add_row("NAC Type", r.nac_type.name)
    table.add_row("DHCP Lease", str(r.dhcp_lease or "—"))
    table.add_row("Gateway", str(r.dhcp_gateway or "—"))
    table.add_row("Subnet", str(r.dhcp_subnet or "—"))
    table.add_row("EAPOL Frames", str(r.raw_eapol_count))
    eap_names = [f"{t} ({__import__('core.recon', fromlist=['EAP_TYPE_NAMES']).EAP_TYPE_NAMES.get(t, '?')})"
                 for t in r.eap_methods_observed]
    table.add_row("EAP Methods", ", ".join(eap_names) or "—")
    table.add_row("Switch Vendor", str(r.switch_vendor or "—"))
    table.add_row("Switch Port", str(r.switch_port or "—"))
    table.add_row("Duration", f"{r.duration_sec:.1f}s")
    console.print(table)


def cmd_auto(args, logger) -> dict:
    """Intelligent auto mode: recon → choose strategy → bypass → posture → post-auth."""
    from core.recon import run_recon, NacType
    from core.mab import run_mab_bypass
    from core.dot1x import run_dot1x
    from core.relay import run_relay
    from core.posture import detect_and_bypass_posture
    from modules.post_auth import run_post_auth
    import dataclasses

    result: dict = {
        "timestamp": datetime.now().isoformat(),
        "interface": args.interface,
        "command": "auto",
    }

    methods = _resolve_eap_methods(args.eap_method)

    console.print("\n[bold cyan][*] Phase 1: NAC Reconnaissance[/bold cyan]")
    recon = run_recon(args.interface, timeout=args.timeout, verbose=args.verbose)
    result["recon"] = dataclasses.asdict(recon)
    console.print(f"[green][+] NAC Type: {recon.nac_type.name}[/green]")

    obtained_ip = None
    bypass_result = {}
    gateway = recon.dhcp_gateway

    console.print("\n[bold cyan][*] Phase 2: Bypass[/bold cyan]")

    if recon.nac_type in (NacType.DOT1X, NacType.DOT1X_STRICT):
        if args.username or args.creds_file:
            console.print(f"[*] Attempting 802.1X authentication ...")
            r = run_dot1x(
                args.interface,
                identity=args.username,
                password=args.password,
                creds_file=args.creds_file,
                methods=methods,
                timeout=args.timeout,
                spray_delay=args.spray_delay,
                backend=args.backend,
                conn_name=args.conn_name,
                client_cert=args.client_cert,
                private_key=args.private_key,
                verbose=args.verbose,
            )
            bypass_result = dataclasses.asdict(r)
            if r.success:
                obtained_ip = r.obtained_ip
                console.print(f"[green][+] 802.1X SUCCESS: {obtained_ip}[/green]")
            else:
                console.print("[red][-] 802.1X authentication failed[/red]")
        elif args.interface2:
            console.print(f"[*] No credentials — attempting relay via {args.interface2} ...")
            r = run_relay(
                args.interface, args.interface2,
                auth_timeout=args.timeout * 6,
                verbose=args.verbose,
            )
            bypass_result = dataclasses.asdict(r)
            if r.success:
                obtained_ip = r.obtained_ip
                console.print(f"[green][+] Relay SUCCESS: {obtained_ip}[/green]")
            else:
                console.print("[red][-] Relay attack failed[/red]")
        else:
            console.print("[red][!] DOT1X detected but no credentials or second interface provided[/red]")
            console.print("[yellow][!] Use -u/-p for credentials or -i2 for relay mode[/yellow]")
            result["bypass"] = {"method": "none", "success": False, "error": "No credentials or relay interface"}
            result["summary"] = {"success": False, "obtained_ip": None, "bypass_method": "none"}
            return result

    elif recon.nac_type in (NacType.MAB_OR_OPEN, NacType.QUARANTINE_VLAN, NacType.UNKNOWN):
        console.print(f"[*] Attempting MAB bypass via MAC harvesting ...")
        r = run_mab_bypass(
            args.interface,
            target_mac=args.mac,
            harvest_duration=args.harvest_duration,
            no_restore=args.no_restore_mac,
            verbose=args.verbose,
        )
        bypass_result = dataclasses.asdict(r)
        if r.success:
            obtained_ip = r.obtained_ip
            console.print(f"[green][+] MAB SUCCESS: spoofed {r.spoofed_mac}, IP={obtained_ip}[/green]")
        else:
            console.print("[red][-] MAB bypass failed[/red]")
            # MAB failed — try 802.1X if we have credentials
            if (args.username or args.creds_file) and recon.nac_type in (NacType.QUARANTINE_VLAN, NacType.UNKNOWN):
                console.print("[*] Falling back to 802.1X ...")
                r2 = run_dot1x(
                    args.interface,
                    identity=args.username,
                    password=args.password,
                    creds_file=args.creds_file,
                    methods=methods,
                    timeout=args.timeout,
                    verbose=args.verbose,
                )
                if r2.success:
                    obtained_ip = r2.obtained_ip
                    bypass_result = dataclasses.asdict(r2)
                    console.print(f"[green][+] 802.1X fallback SUCCESS: {obtained_ip}[/green]")

    elif recon.nac_type == NacType.CAPTIVE_PORTAL:
        console.print("[yellow][!] Captive portal detected — attempting posture bypass[/yellow]")
        pr = detect_and_bypass_posture(gateway or "", recon.dhcp_lease or "", verbose=args.verbose)
        bypass_result = dataclasses.asdict(pr)
        if recon.dhcp_lease:
            obtained_ip = recon.dhcp_lease
            console.print(f"[yellow][!] Using pre-assigned IP: {obtained_ip}[/yellow]")

    result["bypass"] = bypass_result

    if obtained_ip and not args.no_posture:
        console.print("\n[bold cyan][*] Phase 3: Posture Check[/bold cyan]")
        posture_gw = gateway or ""
        pr = detect_and_bypass_posture(posture_gw, obtained_ip, verbose=args.verbose)
        result["posture"] = dataclasses.asdict(pr)
        if pr.posture_type.value == "none":
            console.print("[green][+] No posture check detected[/green]")
        elif pr.bypass_success:
            console.print(f"[green][+] Posture bypass succeeded[/green]")
        else:
            console.print(f"[yellow][!] Posture: {pr.posture_type.value} — {pr.details}[/yellow]")

    if obtained_ip and not args.no_post:
        console.print("\n[bold cyan][*] Phase 4: Post-Auth Enumeration[/bold cyan]")
        pa = run_post_auth(args.interface, obtained_ip, verbose=args.verbose)
        result["post_auth"] = dataclasses.asdict(pa)
        console.print(f"[green][+] Discovered {len(pa.discovered_hosts)} hosts in {pa.subnet}[/green]")
        if pa.nac_server_type:
            console.print(f"[yellow][!] NAC server: {pa.nac_server_type} at {pa.nac_server_ip}[/yellow]")

    result["summary"] = {
        "success": obtained_ip is not None,
        "obtained_ip": obtained_ip,
        "bypass_method": bypass_result.get("method", result["recon"]["nac_type"].lower() if "nac_type" in result.get("recon", {}) else "unknown"),
    }

    return result


def main():
    require_root()

    parser = build_parser()
    args = parser.parse_args()

    # subparser arg takes priority over top-level default
    verbose        = _g(args, 'verbose') or False
    timeout        = _g(args, 'timeout') or 15
    no_restore_mac = bool(_g(args, 'no_restore_mac'))
    no_posture     = bool(_g(args, 'no_posture'))
    no_post        = bool(_g(args, 'no_post'))
    username       = _g(args, 'username')
    password       = _g(args, 'password') or ""
    creds_file     = _g(args, 'creds_file')
    mac            = _g(args, 'mac')
    harvest_dur    = _g(args, 'harvest_duration') or 60
    eap_method     = _g(args, 'eap_method') or "auto"
    spray_delay    = _g(args, 'spray_delay') or 2.0
    backend        = _g(args, 'backend') or "auto"
    conn_name      = _g(args, 'conn_name') or "NACleaver-8021x"
    client_cert    = _g(args, 'client_cert')
    private_key    = _g(args, 'private_key')
    interface2     = _g(args, 'interface2')

    logger = setup_logging(verbose)

    # register before any ops so Ctrl+C and SIGTERM still restore MACs
    atexit.register(Cleanup.run_all)
    signal.signal(signal.SIGINT, lambda s, f: (Cleanup.run_all(), sys.exit(0)))
    signal.signal(signal.SIGTERM, lambda s, f: (Cleanup.run_all(), sys.exit(0)))

    if no_restore_mac:
        Cleanup.disable_mac_restore()

    deps = check_all_dependencies()
    missing = [k for k, v in deps.items() if not v]
    if missing:
        console.print(f"[yellow][!] Missing system tools: {', '.join(missing)}[/yellow]")
        console.print("[yellow][!] Dependent modules will be unavailable.[/yellow]")

    console.print(Panel.fit(
        "[bold red]NACleaver[/bold red] — NAC Bypass Framework\n"
        "[dim]For authorized penetration testing only[/dim]",
        border_style="red",
    ))

    output_dir = args.output or "output"
    result: dict = {
        "timestamp": datetime.now().isoformat(),
        "interface": args.interface,
        "command": args.command,
    }

    # write back so cmd_auto reads from args without calling _g() again
    args.username       = username
    args.password       = password
    args.creds_file     = creds_file
    args.mac            = mac
    args.harvest_duration = harvest_dur
    args.eap_method     = eap_method
    args.spray_delay    = spray_delay
    args.backend        = backend
    args.conn_name      = conn_name
    args.client_cert    = client_cert
    args.private_key    = private_key
    args.interface2     = interface2
    args.timeout        = timeout
    args.verbose        = verbose
    args.no_restore_mac = no_restore_mac
    args.no_posture     = no_posture
    args.no_post        = no_post

    try:
        if args.command == "recon":
            from core.recon import run_recon
            r = run_recon(args.interface, timeout=timeout, verbose=verbose)
            _print_recon_result(r)
            import dataclasses
            result["recon"] = dataclasses.asdict(r)

        elif args.command == "mab":
            from core.mab import run_mab_bypass
            r = run_mab_bypass(
                args.interface,
                target_mac=mac,
                harvest_duration=harvest_dur,
                no_restore=no_restore_mac,
                verbose=verbose,
            )
            import dataclasses
            result["mab"] = dataclasses.asdict(r)
            if r.success:
                console.print(f"[green][+] MAB bypass succeeded: spoofed {r.spoofed_mac}, IP={r.obtained_ip}[/green]")
            else:
                console.print(f"[red][-] MAB bypass failed: {r.error}[/red]")

        elif args.command == "dot1x":
            from core.dot1x import run_dot1x
            methods = _resolve_eap_methods(eap_method)
            r = run_dot1x(
                args.interface,
                identity=username,
                password=password,
                creds_file=creds_file,
                methods=methods,
                timeout=timeout,
                spray_delay=spray_delay,
                backend=backend,
                conn_name=conn_name,
                client_cert=client_cert,
                private_key=private_key,
                verbose=verbose,
            )
            import dataclasses
            result["dot1x"] = dataclasses.asdict(r)
            if r.success:
                console.print(f"[green][+] 802.1X succeeded: {r.method_used.value} → {r.obtained_ip}[/green]")
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
                auth_timeout=timeout * 6,
                verbose=verbose,
            )
            import dataclasses
            result["relay"] = dataclasses.asdict(r)
            if r.success:
                console.print(f"[green][+] Relay succeeded: IP={r.obtained_ip}, frames={r.eapol_frames_relayed}[/green]")
            else:
                console.print(f"[red][-] Relay failed: {r.error}[/red]")

        elif args.command == "posture":
            from core.posture import detect_and_bypass_posture
            ip = get_iface_ip(args.interface)
            if not ip:
                console.print("[red][!] No IP on interface — run a bypass first[/red]")
                sys.exit(1)
            r = detect_and_bypass_posture(
                gateway="",
                obtained_ip=ip,
                verbose=args.verbose,
            )
            import dataclasses
            result["posture"] = dataclasses.asdict(r)
            console.print(f"[*] Posture type: {r.posture_type.value}")
            if r.bypass_attempted:
                status = "[green]SUCCESS[/green]" if r.bypass_success else "[red]FAILED[/red]"
                console.print(f"[*] Bypass: {status}")

        elif args.command == "post":
            from modules.post_auth import run_post_auth
            ip = get_iface_ip(args.interface)
            if not ip:
                console.print("[red][!] No IP on interface — run a bypass first[/red]")
                sys.exit(1)
            r = run_post_auth(args.interface, ip, verbose=args.verbose)
            import dataclasses
            result["post_auth"] = dataclasses.asdict(r)
            console.print(f"[green][+] Found {len(r.discovered_hosts)} hosts in {r.subnet}[/green]")
            if r.nac_server_type:
                console.print(f"[yellow][!] NAC: {r.nac_server_type} @ {r.nac_server_ip}[/yellow]")

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

    try:
        path = save_json_result(result, output_dir)
        console.print(f"\n[green][+] Results saved to {path}[/green]")
    except Exception as e:
        logger.warning(f"Failed to save results: {e}")


if __name__ == "__main__":
    main()
