"""Validated, data-driven NAC product fingerprints.

These signatures are evidence rules, not product exploits. Engagement-specific
signatures can replace or extend the built-ins without changing scanner code.
"""

from copy import deepcopy
from typing import Any


DEFAULT_NAC_SIGNATURES: list[dict[str, Any]] = [
    {
        "name": "Cisco Identity Services Engine",
        "posture_type": "cisco_ise_agent",
        "tcp_ports": [8905],
        "http_probes": [
            {
                "scheme": "https",
                "port": 8443,
                "markers": ["identity services engine", "cisco ise"],
                "verify_tls": True,
            }
        ],
        "workflow_url": "https://{gateway}:8443/",
        "rdns_markers": ["ise"],
    },
    {
        "name": "Aruba ClearPass",
        "posture_type": "aruba_clearpass",
        "tcp_ports": [8081],
        "http_probes": [
            {
                "scheme": "https",
                "port": 8081,
                "markers": ["clearpass", "aruba"],
                "verify_tls": True,
            }
        ],
        "workflow_url": "https://{gateway}:8081/",
        "rdns_markers": ["clearpass"],
    },
    {
        "name": "Forescout",
        "posture_type": "forescout_agent",
        "tcp_ports": [1040],
        "http_probes": [],
        "workflow_url": None,
        "rdns_markers": ["forescout", "counteract"],
    },
    {
        "name": "Fortinet FortiNAC",
        "posture_type": "unknown",
        "tcp_ports": [],
        "http_probes": [
            {
                "scheme": "https",
                "port": 8443,
                "markers": ["fortinac", "fortinet"],
                "verify_tls": True,
            }
        ],
        "workflow_url": "https://{gateway}:8443/",
        "rdns_markers": ["fortinac"],
    },
    {
        "name": "PacketFence",
        "posture_type": "unknown",
        "tcp_ports": [],
        "http_probes": [
            {
                "scheme": "https",
                "port": 1443,
                "markers": ["packetfence"],
                "verify_tls": True,
            }
        ],
        "workflow_url": "https://{gateway}:1443/",
        "rdns_markers": ["packetfence"],
    },
]


def validated_signatures(signatures: list[dict] | None) -> list[dict[str, Any]]:
    """Return normalized signatures, using built-ins only when none are supplied."""
    source = DEFAULT_NAC_SIGNATURES if signatures is None else signatures
    if not isinstance(source, list):
        raise ValueError("NAC signatures must be a list")
    normalized: list[dict[str, Any]] = []
    for index, raw in enumerate(source, start=1):
        if not isinstance(raw, dict):
            raise ValueError(f"NAC signature {index} must be a mapping")
        name = raw.get("name")
        posture_type = raw.get("posture_type", "unknown")
        if not isinstance(name, str) or not name.strip():
            raise ValueError(f"NAC signature {index} needs a name")
        if not isinstance(posture_type, str) or not posture_type.strip():
            raise ValueError(f"NAC signature {name!r} has invalid posture_type")
        tcp_ports = raw.get("tcp_ports", [])
        probes = raw.get("http_probes", [])
        rdns = raw.get("rdns_markers", [])
        if not isinstance(tcp_ports, list) or any(
            isinstance(port, bool) or not isinstance(port, int) or not 1 <= port <= 65535
            for port in tcp_ports
        ):
            raise ValueError(f"NAC signature {name!r} has invalid tcp_ports")
        if not isinstance(rdns, list) or any(
            not isinstance(marker, str) or not marker.strip() for marker in rdns
        ):
            raise ValueError(f"NAC signature {name!r} has invalid rdns_markers")
        normalized_probes: list[dict[str, Any]] = []
        if not isinstance(probes, list):
            raise ValueError(f"NAC signature {name!r} has invalid http_probes")
        for probe in probes:
            if not isinstance(probe, dict):
                raise ValueError(f"NAC signature {name!r} HTTP probes must be mappings")
            scheme = probe.get("scheme", "https")
            port = probe.get("port")
            markers = probe.get("markers", [])
            verify_tls = probe.get("verify_tls", True)
            if scheme not in {"http", "https"}:
                raise ValueError(f"NAC signature {name!r} has invalid HTTP scheme")
            if isinstance(port, bool) or not isinstance(port, int) or not 1 <= port <= 65535:
                raise ValueError(f"NAC signature {name!r} has invalid HTTP port")
            if not isinstance(markers, list) or not markers or any(
                not isinstance(marker, str) or not marker.strip() for marker in markers
            ):
                raise ValueError(f"NAC signature {name!r} needs HTTP markers")
            if not isinstance(verify_tls, bool):
                raise ValueError(
                    f"NAC signature {name!r} HTTP verify_tls must be boolean"
                )
            normalized_probes.append({
                "scheme": scheme,
                "port": port,
                "markers": [marker.lower() for marker in markers],
                "verify_tls": verify_tls,
            })
        workflow_url = raw.get("workflow_url")
        if workflow_url is not None and (
            not isinstance(workflow_url, str)
            or "{gateway}" not in workflow_url
            or not workflow_url.startswith(("http://", "https://"))
        ):
            raise ValueError(
                f"NAC signature {name!r} workflow_url must be HTTP(S) and contain {{gateway}}"
            )
        normalized.append({
            "name": name.strip(),
            "posture_type": posture_type.strip(),
            "tcp_ports": list(dict.fromkeys(tcp_ports)),
            "http_probes": normalized_probes,
            "workflow_url": workflow_url,
            "rdns_markers": [marker.lower() for marker in rdns],
        })
    return deepcopy(normalized)
