import logging
import socket
from dataclasses import dataclass, field
from enum import Enum
from typing import Any
from urllib.parse import urljoin, urlparse

import requests
import urllib3
from requests.adapters import HTTPAdapter
from urllib3.connection import HTTPConnection

from core.fingerprints import validated_signatures

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
    workflow_name: str | None = None
    workflow_steps: list[dict] = field(default_factory=list)
    product: str | None = None
    fingerprint_evidence: list[str] = field(default_factory=list)


@dataclass
class PostureWorkflowAttempt:
    attempted: bool
    success: bool
    workflow_name: str | None = None
    steps: list[dict] = field(default_factory=list)
    error: str | None = None


def _url_origin(url: str) -> tuple[str, str, int] | None:
    parsed = urlparse(url)
    if parsed.scheme not in {"http", "https"} or not parsed.hostname:
        return None
    default_port = 443 if parsed.scheme == "https" else 80
    return parsed.scheme, parsed.hostname.lower(), parsed.port or default_port


def _display_url(url: str) -> str:
    parsed = urlparse(url)
    path = parsed.path or "/"
    return f"{parsed.scheme}://{parsed.netloc}{path}"


def _posture_connectivity_verified(
    iface: str | None,
    timeout: int,
    verification_targets: list[dict] | None = None,
    verification_policy: str = "any",
) -> bool:
    if not iface:
        return False
    from core.recon import verify_interface_access
    return verify_interface_access(
        iface,
        timeout=timeout,
        targets=verification_targets,
        policy=verification_policy,
    ).connectivity_verified


def _bound_session(iface: str | None = None) -> requests.Session:
    """Create a proxy-free requests session optionally bound to one interface."""
    session = requests.Session()
    session.trust_env = False
    if iface:
        socket_options = list(HTTPConnection.default_socket_options)
        socket_options.append((
            socket.SOL_SOCKET,
            getattr(socket, "SO_BINDTODEVICE", 25),
            iface.encode() + b"\0",
        ))
        adapter = HTTPAdapter()
        adapter.init_poolmanager(
            connections=4,
            maxsize=4,
            block=False,
            socket_options=socket_options,
        )
        session.mount("http://", adapter)
        session.mount("https://", adapter)
    return session


def _tcp_probe(host: str, port: int, timeout: int, iface: str | None = None) -> bool:
    """Return True if TCP connection succeeds through the requested interface."""
    try:
        candidates = socket.getaddrinfo(host, port, socket.AF_UNSPEC, socket.SOCK_STREAM)
    except socket.gaierror:
        return False
    for family, socktype, proto, _, sockaddr in candidates:
        sock = socket.socket(family, socktype, proto)
        sock.settimeout(timeout)
        try:
            if iface:
                sock.setsockopt(
                    socket.SOL_SOCKET,
                    getattr(socket, "SO_BINDTODEVICE", 25),
                    iface.encode() + b"\0",
                )
            if family == socket.AF_INET6 and host.lower().startswith("fe80:") and iface:
                sockaddr = (sockaddr[0], sockaddr[1], sockaddr[2], socket.if_nametoindex(iface))
            if sock.connect_ex(sockaddr) == 0:
                return True
        except (socket.timeout, OSError):
            pass
        finally:
            sock.close()
    return False


def _url_address(host: str) -> str:
    return f"[{host}]" if ":" in host and not host.startswith("[") else host


def _http_get_text(
    url: str,
    timeout: int,
    ua: str = "",
    iface: str | None = None,
    verify_tls: bool = True,
) -> tuple[int, str, dict]:
    """Return (status, body, headers), forcing traffic through *iface* when set."""
    session = _bound_session(iface)
    try:
        headers = {"User-Agent": ua} if ua else {}
        resp = session.get(
            url,
            timeout=timeout,
            verify=verify_tls,
            allow_redirects=False,
            headers=headers,
        )
        return resp.status_code, resp.text, dict(resp.headers)
    except requests.exceptions.RequestException as exc:
        logger.debug(f"[posture] HTTP GET {url} error: {exc}")
        return 0, "", {}
    finally:
        session.close()

def detect_posture_check(
    gateway: str,
    obtained_ip: str,
    probe_timeout: int = 5,
    iface: str | None = None,
    signatures: list[dict] | None = None,
) -> PostureResult:
    """Run all posture detection probes and return the first match."""

    # Is HTTP traffic being intercepted? Never allow a second default route
    # (for example Wi-Fi) to answer on behalf of the tested Ethernet link.
    status = 0
    redirect_url = None
    if iface:
        from core.recon import _http_probe_bound
        bound_status, redirect_url, probe_error = _http_probe_bound(iface, probe_timeout)
        status = bound_status or 0
        if probe_error:
            logger.debug(f"[posture] Bound HTTP probe error: {probe_error}")
    else:
        session = _bound_session()
        try:
            response = session.get(
                "http://1.1.1.1",
                timeout=probe_timeout,
                allow_redirects=False,
            )
            status = response.status_code
            redirect_url = response.headers.get("Location", "")
        except requests.exceptions.RequestException as exc:
            logger.debug(f"[posture] HTTP probe error: {exc}")
        finally:
            session.close()

    if status in (301, 302, 303, 307, 308):
        logger.info(f"[posture] HTTP redirect detected → {redirect_url}")
        return PostureResult(
            posture_type=PostureType.HTTP_REDIRECT,
            posture_url=redirect_url,
            bypass_attempted=False,
            bypass_success=False,
            details=f"HTTP {status} redirect to {redirect_url}",
        )

    if not gateway:
        return PostureResult(
            posture_type=PostureType.NONE,
            posture_url=None,
            bypass_attempted=False,
            bypass_success=False,
            details="No posture check detected",
        )

    gateway_url = _url_address(gateway)
    http_cache: dict[tuple[str, bool], tuple[int, str, dict]] = {}
    port_cache: dict[int, bool] = {}
    for signature in validated_signatures(signatures):
        evidence: list[str] = []
        for port in signature["tcp_ports"]:
            if port not in port_cache:
                port_cache[port] = _tcp_probe(gateway, port, probe_timeout, iface)
            if port_cache[port]:
                evidence.append(f"TCP {port} open")
        for probe in signature["http_probes"]:
            if probe["port"] not in port_cache:
                port_cache[probe["port"]] = _tcp_probe(
                    gateway, probe["port"], probe_timeout, iface
                )
            if not port_cache[probe["port"]]:
                continue
            url = f"{probe['scheme']}://{gateway_url}:{probe['port']}/"
            cache_key = (url, probe["verify_tls"])
            if cache_key not in http_cache:
                http_cache[cache_key] = _http_get_text(
                    url,
                    probe_timeout,
                    iface=iface,
                    verify_tls=probe["verify_tls"],
                )
            http_status, body, headers = http_cache[cache_key]
            combined = (body + " " + " ".join(
                f"{key}:{value}" for key, value in headers.items()
            )).lower()
            matched = [marker for marker in probe["markers"] if marker in combined]
            if http_status and matched:
                tls_detail = (
                    "verified TLS"
                    if probe["scheme"] == "https" and probe["verify_tls"]
                    else "explicitly unverified TLS"
                    if probe["scheme"] == "https"
                    else "plain HTTP"
                )
                evidence.append(
                    f"{probe['scheme'].upper()} {probe['port']} marker(s) "
                    f"[{tls_detail}]: {', '.join(matched)}"
                )
        if evidence:
            posture_value = signature["posture_type"]
            try:
                posture_type = PostureType(posture_value)
            except ValueError:
                posture_type = PostureType.UNKNOWN
            workflow_template = signature.get("workflow_url")
            posture_url = (
                workflow_template.format(gateway=gateway_url)
                if workflow_template else None
            )
            logger.info(
                f"[posture] {signature['name']} fingerprint at {gateway}: "
                f"{'; '.join(evidence)}"
            )
            return PostureResult(
                posture_type=posture_type,
                posture_url=posture_url,
                bypass_attempted=False,
                bypass_success=False,
                details=f"{signature['name']} detected: {'; '.join(evidence)}",
                product=signature["name"],
                fingerprint_evidence=evidence,
            )

    return PostureResult(
        posture_type=PostureType.NONE,
        posture_url=None,
        bypass_attempted=False,
        bypass_success=False,
        details="No posture check detected",
    )


def _workflow_matches_host(workflow: dict, hostname: str) -> bool:
    patterns = workflow.get("match_hosts")
    if not isinstance(patterns, list) or not patterns:
        return False
    hostname = hostname.lower().rstrip(".")
    for pattern in patterns:
        if not isinstance(pattern, str):
            continue
        pattern = pattern.lower().strip().rstrip(".")
        if pattern.startswith("*."):
            suffix = pattern[1:]
            if hostname.endswith(suffix) and hostname != suffix[1:]:
                return True
        elif hostname == pattern:
            return True
    return False


def _workflow_matches_context(
    workflow: dict,
    hostname: str | None,
    posture_type: str | None,
    product: str | None,
) -> bool:
    if hostname and _workflow_matches_host(workflow, hostname):
        return True
    type_matches = workflow.get("match_posture_types", [])
    if isinstance(type_matches, list) and posture_type and any(
        isinstance(value, str) and value.lower() == posture_type.lower()
        for value in type_matches
    ):
        return True
    product_matches = workflow.get("match_products", [])
    if isinstance(product_matches, list) and product and any(
        isinstance(value, str) and value.lower() == product.lower()
        for value in product_matches
    ):
        return True
    return False


def _expected_statuses(value: Any) -> set[int]:
    if value is None:
        return {200}
    values = value if isinstance(value, list) else [value]
    statuses: set[int] = set()
    for item in values:
        if isinstance(item, bool):
            raise ValueError("expected_status cannot contain booleans")
        status = int(item)
        if status < 100 or status > 599:
            raise ValueError("expected_status must contain HTTP status codes")
        statuses.add(status)
    if not statuses:
        raise ValueError("expected_status cannot be empty")
    return statuses


def validate_workflows(workflows: list[dict] | None) -> list[dict]:
    """Validate engagement workflow structure before any network state changes."""
    if workflows is None:
        return []
    if not isinstance(workflows, list):
        raise ValueError("posture.http_workflows must be a list")
    for index, workflow in enumerate(workflows, start=1):
        if not isinstance(workflow, dict):
            raise ValueError(f"posture workflow {index} must be a mapping")
        name = workflow.get("name", f"workflow-{index}")
        if not isinstance(name, str) or not name.strip():
            raise ValueError(f"posture workflow {index} has an invalid name")
        has_matcher = False
        for key in ("match_hosts", "match_posture_types", "match_products"):
            values = workflow.get(key, [])
            if not isinstance(values, list) or any(
                not isinstance(value, str) or not value.strip() for value in values
            ):
                raise ValueError(f"posture workflow {name!r} has invalid {key}")
            has_matcher = has_matcher or bool(values)
        if not has_matcher:
            raise ValueError(f"posture workflow {name!r} needs at least one matcher")
        base_url = workflow.get("base_url")
        if base_url is not None:
            parsed = urlparse(base_url) if isinstance(base_url, str) else None
            if not parsed or parsed.scheme not in {"http", "https"} or not parsed.hostname:
                raise ValueError(f"posture workflow {name!r} has invalid base_url")
        verify_tls = workflow.get("verify_tls", True)
        if not isinstance(verify_tls, bool):
            raise ValueError(f"posture workflow {name!r} verify_tls must be boolean")
        steps = workflow.get("steps")
        if not isinstance(steps, list) or not steps:
            raise ValueError(f"posture workflow {name!r} needs at least one step")
        for step_index, step in enumerate(steps, start=1):
            if not isinstance(step, dict):
                raise ValueError(f"posture workflow {name!r} step {step_index} must be a mapping")
            method = str(step.get("method", "GET")).upper()
            if method not in {"GET", "POST", "PUT", "PATCH"}:
                raise ValueError(f"posture workflow {name!r} step {step_index} has invalid method")
            target = step.get("url", step.get("path", ""))
            if not isinstance(target, str):
                raise ValueError(f"posture workflow {name!r} step {step_index} has invalid target")
            headers = step.get("headers", {})
            if not isinstance(headers, dict) or any(
                not isinstance(key, str) or not isinstance(value, str)
                for key, value in headers.items()
            ):
                raise ValueError(f"posture workflow {name!r} step {step_index} has invalid headers")
            bodies = [body for body in ("json", "form", "body") if body in step]
            if len(bodies) > 1:
                raise ValueError(
                    f"posture workflow {name!r} step {step_index} has multiple request bodies"
                )
            if "form" in step and not isinstance(step["form"], dict):
                raise ValueError(f"posture workflow {name!r} step {step_index} form must be a mapping")
            if "body" in step and not isinstance(step["body"], str):
                raise ValueError(f"posture workflow {name!r} step {step_index} body must be a string")
            _expected_statuses(step.get("expected_status"))
            if "allow_redirects" in step and not isinstance(step["allow_redirects"], bool):
                raise ValueError(
                    f"posture workflow {name!r} step {step_index} allow_redirects must be boolean"
                )
    return workflows


def _json_path_value(payload: Any, path: str) -> tuple[bool, Any]:
    current = payload
    for component in path.split("."):
        if not isinstance(current, dict) or component not in current:
            return False, None
        current = current[component]
    return True, current


def _response_matches(step: dict, response: requests.Response) -> tuple[bool, str]:
    statuses = _expected_statuses(step.get("expected_status"))
    if response.status_code not in statuses:
        return False, f"HTTP {response.status_code}; expected {sorted(statuses)}"

    expected_json = step.get("expected_json")
    if expected_json is not None:
        if not isinstance(expected_json, dict) or not expected_json:
            raise ValueError("expected_json must be a non-empty mapping")
        try:
            payload = response.json()
        except (ValueError, requests.exceptions.JSONDecodeError):
            return False, "response is not JSON"
        for path, expected in expected_json.items():
            found, actual = _json_path_value(payload, str(path))
            if not found or actual != expected:
                return False, f"JSON field {path!r} did not match"

    body_contains = step.get("body_contains")
    if body_contains is not None:
        needles = body_contains if isinstance(body_contains, list) else [body_contains]
        if not needles or any(not isinstance(item, str) for item in needles):
            raise ValueError("body_contains must be a string or non-empty string list")
        if any(item not in response.text for item in needles):
            return False, "response body did not contain every required value"
    return True, "response matched"


def _step_request(step: dict, portal_url: str) -> tuple[str, str, dict]:
    if not isinstance(step, dict):
        raise ValueError("workflow steps must be mappings")
    method = str(step.get("method", "GET")).upper()
    if method not in {"GET", "POST", "PUT", "PATCH"}:
        raise ValueError(f"unsupported workflow method: {method}")

    target = step.get("url", step.get("path", ""))
    if not isinstance(target, str):
        raise ValueError("workflow step url/path must be a string")
    target_url = urljoin(portal_url, target)
    parsed = urlparse(target_url)
    if parsed.scheme not in {"http", "https"} or not parsed.hostname:
        raise ValueError("workflow target must be an HTTP(S) URL")
    if _url_origin(target_url) != _url_origin(portal_url):
        raise ValueError("workflow steps must stay on the same origin as the detected portal")

    headers = step.get("headers", {})
    if not isinstance(headers, dict) or any(
        not isinstance(key, str) or not isinstance(value, str)
        for key, value in headers.items()
    ):
        raise ValueError("workflow headers must be a string mapping")

    request_kwargs: dict[str, Any] = {"headers": headers}
    bodies = [name for name in ("json", "form", "body") if name in step]
    if len(bodies) > 1:
        raise ValueError("a workflow step may define only one of json, form, or body")
    if "json" in step:
        request_kwargs["json"] = step["json"]
    elif "form" in step:
        if not isinstance(step["form"], dict):
            raise ValueError("workflow form must be a mapping")
        request_kwargs["data"] = step["form"]
    elif "body" in step:
        if not isinstance(step["body"], str):
            raise ValueError("workflow body must be a string")
        request_kwargs["data"] = step["body"]
    return method, target_url, request_kwargs


def bypass_http_posture(
    posture_url: str | None,
    workflows: list[dict] | None = None,
    probe_timeout: int = 5,
    iface: str | None = None,
    verification_targets: list[dict] | None = None,
    verification_policy: str = "any",
    posture_type: str | None = None,
    product: str | None = None,
) -> PostureWorkflowAttempt:
    """Run an explicitly configured portal workflow and verify resulting access.

    No generic compliance claims are fabricated. A workflow is selected only when
    its configured host matcher matches the detected redirect host, every step is
    constrained to that same origin, and final connectivity succeeds on *iface*.
    """
    if not isinstance(workflows, list) or not workflows:
        return PostureWorkflowAttempt(
            False,
            False,
            error="no HTTP posture workflow configured for this engagement",
        )

    parsed_portal = urlparse(posture_url or "")
    portal_hostname = parsed_portal.hostname
    workflow = next(
        (
            candidate for candidate in workflows
            if isinstance(candidate, dict)
            and _workflow_matches_context(
                candidate, portal_hostname, posture_type, product
            )
        ),
        None,
    )
    if workflow is None:
        context = portal_hostname or product or posture_type or "detected posture context"
        return PostureWorkflowAttempt(
            False,
            False,
            error=f"no configured workflow matches {context}",
        )

    effective_url = posture_url or workflow.get("base_url")
    if not isinstance(effective_url, str):
        return PostureWorkflowAttempt(
            False, False, error="matched agent workflow requires an HTTP(S) base_url"
        )
    parsed_portal = urlparse(effective_url)
    if parsed_portal.scheme not in {"http", "https"} or not parsed_portal.hostname:
        return PostureWorkflowAttempt(False, False, error="invalid posture workflow base URL")

    name = str(workflow.get("name") or parsed_portal.hostname)
    steps = workflow.get("steps")
    if not isinstance(steps, list) or not steps:
        return PostureWorkflowAttempt(
            False, False, workflow_name=name, error="matched workflow has no steps"
        )

    verify_tls = workflow.get("verify_tls", True)
    if not isinstance(verify_tls, bool):
        return PostureWorkflowAttempt(
            False, False, workflow_name=name, error="verify_tls must be boolean"
        )

    session = _bound_session(iface)
    step_results: list[dict] = []
    try:
        for index, step in enumerate(steps, start=1):
            step_name = str(step.get("name", f"step-{index}")) if isinstance(step, dict) else f"step-{index}"
            try:
                method, target_url, request_kwargs = _step_request(step, effective_url)
                allow_redirects = step.get("allow_redirects", False)
                if not isinstance(allow_redirects, bool):
                    raise ValueError("allow_redirects must be boolean")
                response = session.request(
                    method,
                    target_url,
                    timeout=probe_timeout,
                    verify=verify_tls,
                    allow_redirects=allow_redirects,
                    **request_kwargs,
                )
                response_chain = [*getattr(response, "history", []), response]
                if any(
                    getattr(item, "url", None)
                    and _url_origin(item.url) != _url_origin(effective_url)
                    for item in response_chain
                ):
                    raise ValueError("workflow response redirected outside the portal origin")
                matched, detail = _response_matches(step, response)
                step_results.append({
                    "name": step_name,
                    "method": method,
                    "url": _display_url(target_url),
                    "status": response.status_code,
                    "success": matched,
                    "details": detail,
                })
                if not matched:
                    return PostureWorkflowAttempt(
                        True, False, name, step_results, f"workflow step failed: {step_name}"
                    )
            except (ValueError, requests.exceptions.RequestException) as exc:
                step_results.append({
                    "name": step_name,
                    "success": False,
                    "details": str(exc),
                })
                return PostureWorkflowAttempt(
                    True, False, name, step_results, f"workflow step error: {step_name}: {exc}"
                )
    finally:
        session.close()

    connectivity = _posture_connectivity_verified(
        iface,
        probe_timeout,
        verification_targets=verification_targets,
        verification_policy=verification_policy,
    )
    if not connectivity:
        return PostureWorkflowAttempt(
            True,
            False,
            name,
            step_results,
            "workflow completed but interface-bound access was not verified",
        )
    return PostureWorkflowAttempt(True, True, name, step_results)


def detect_and_bypass_posture(
    gateway: str,
    obtained_ip: str,
    probe_timeout: int = 5,
    iface: str | None = None,
    verbose: bool = False,
    workflows: list[dict] | None = None,
    verification_targets: list[dict] | None = None,
    verification_policy: str = "any",
    signatures: list[dict] | None = None,
) -> PostureResult:
    """Detect posture check and attempt bypass if applicable."""
    result = detect_posture_check(
        gateway, obtained_ip, probe_timeout, iface=iface, signatures=signatures
    )

    if result.posture_type == PostureType.NONE:
        if verbose:
            logger.info("[posture] No posture check detected — no bypass needed")
        return result

    logger.info(f"[posture] Posture check detected: {result.posture_type.value}")

    attempt = bypass_http_posture(
        result.posture_url,
        workflows=workflows,
        probe_timeout=probe_timeout,
        iface=iface,
        verification_targets=verification_targets,
        verification_policy=verification_policy,
        posture_type=result.posture_type.value,
        product=result.product,
    )
    result.bypass_attempted = attempt.attempted
    result.bypass_success = attempt.success
    result.workflow_name = attempt.workflow_name
    result.workflow_steps = attempt.steps
    result.error = attempt.error
    if attempt.success:
        result.details = (
            f"Configured posture workflow succeeded for "
            f"{result.product or result.posture_type.value}"
        )
    elif not attempt.attempted:
        result.details = (
            f"Posture detected ({result.product or result.posture_type.value}); "
            f"{attempt.error}"
        )
    else:
        result.details = (
            f"Configured posture workflow failed for "
            f"{result.product or result.posture_type.value}: {attempt.error}"
        )

    return result


if __name__ == "__main__":
    import sys
    from rich import print as rprint
    from core.utils import (
        require_root, setup_logging, get_iface_ip, get_iface_ipv6,
        get_iface_gateway, get_iface_gateway6,
    )
    require_root()
    setup_logging(verbose=True)
    if len(sys.argv) < 2:
        print("Usage: sudo python3 core/posture.py <iface>")
        sys.exit(1)
    iface = sys.argv[1]
    ip = get_iface_ip(iface) or get_iface_ipv6(iface)
    if not ip:
        print(f"No IP on {iface}")
        sys.exit(1)
    gateway = get_iface_gateway(iface) or get_iface_gateway6(iface) or ""
    result = detect_and_bypass_posture(
        gateway=gateway, obtained_ip=ip, iface=iface, verbose=True
    )
    rprint(result)
