import pytest

from core import posture, recon
from core.fingerprints import validated_signatures


class FakeResponse:
    status_code = 200
    text = "accepted"
    headers = {}

    def __init__(self, payload):
        self._payload = payload

    def json(self):
        return self._payload


class FakeGetSession:
    def __init__(self):
        self.verify = None

    def get(self, url, **kwargs):
        self.verify = kwargs["verify"]
        return FakeResponse({})

    def close(self):
        pass


def test_posture_redirect_probe_uses_selected_interface(monkeypatch):
    calls = []
    monkeypatch.setattr(
        recon, "_http_probe_bound",
        lambda iface, timeout: (calls.append((iface, timeout)) or 302, "http://portal/", None),
    )
    result = posture.detect_posture_check("", "10.0.0.4", probe_timeout=2, iface="eth0")
    assert result.posture_type is posture.PostureType.HTTP_REDIRECT
    assert result.posture_url == "http://portal/"
    assert calls == [("eth0", 2)]


def test_http_posture_does_not_fabricate_compliance_without_workflow():
    attempt = posture.bypass_http_posture(
        "https://portal.client.example/login",
        workflows=[],
        iface="eth0",
    )
    assert not attempt.attempted
    assert not attempt.success
    assert "no HTTP posture workflow" in attempt.error


class FakeSession:
    def __init__(self):
        self.calls = []
        self.closed = False

    def request(self, method, url, **kwargs):
        self.calls.append((method, url, kwargs))
        return FakeResponse({"result": {"status": "accepted"}})

    def close(self):
        self.closed = True


def test_configured_posture_workflow_requires_real_final_verification(monkeypatch):
    session = FakeSession()
    monkeypatch.setattr(posture, "_bound_session", lambda iface: session)
    monkeypatch.setattr(posture, "_posture_connectivity_verified", lambda *a, **k: True)
    workflow = [{
        "name": "client-portal",
        "match_hosts": ["portal.client.example"],
        "verify_tls": True,
        "steps": [{
            "name": "accept",
            "method": "POST",
            "path": "/api/accept",
            "json": {"accepted": True},
            "expected_status": [200],
            "expected_json": {"result.status": "accepted"},
        }],
    }]
    attempt = posture.bypass_http_posture(
        "https://portal.client.example/login",
        workflows=workflow,
        iface="eth0",
    )
    assert attempt.attempted and attempt.success
    assert attempt.workflow_name == "client-portal"
    assert session.calls[0][0:2] == (
        "POST", "https://portal.client.example/api/accept"
    )
    assert session.closed


def test_posture_workflow_rejects_cross_origin_steps(monkeypatch):
    session = FakeSession()
    monkeypatch.setattr(posture, "_bound_session", lambda iface: session)
    workflow = [{
        "name": "unsafe",
        "match_hosts": ["portal.client.example"],
        "steps": [{"url": "https://other.example/submit"}],
    }]
    attempt = posture.bypass_http_posture(
        "https://portal.client.example/login",
        workflows=workflow,
        iface="eth0",
    )
    assert attempt.attempted and not attempt.success
    assert "same origin" in attempt.steps[0]["details"]
    assert not session.calls


def test_data_driven_product_fingerprint(monkeypatch):
    monkeypatch.setattr(recon, "_http_probe_bound", lambda *a, **k: (204, None, None))
    monkeypatch.setattr(posture, "_tcp_probe", lambda host, port, *a, **k: port == 9443)
    monkeypatch.setattr(posture, "_http_get_text", lambda *a, **k: (0, "", {}))
    signatures = [{
        "name": "Client NAC",
        "posture_type": "unknown",
        "tcp_ports": [9443],
        "http_probes": [],
        "workflow_url": "https://{gateway}:9443/",
        "rdns_markers": ["client-nac"],
    }]
    result = posture.detect_posture_check(
        "2001:db8::1", "2001:db8::9", iface="eth0", signatures=signatures
    )
    assert result.product == "Client NAC"
    assert result.posture_url == "https://[2001:db8::1]:9443/"
    assert result.fingerprint_evidence == ["TCP 9443 open"]


def test_fingerprint_https_verifies_tls_by_default(monkeypatch):
    session = FakeGetSession()
    monkeypatch.setattr(posture, "_bound_session", lambda iface: session)
    status, _body, _headers = posture._http_get_text(
        "https://nac.client.example/", 1, iface="eth0"
    )
    assert status == 200
    assert session.verify is True

    signatures = validated_signatures([{
        "name": "Client NAC",
        "posture_type": "unknown",
        "tcp_ports": [],
        "http_probes": [{
            "scheme": "https",
            "port": 443,
            "markers": ["client"],
        }],
        "workflow_url": None,
        "rdns_markers": [],
    }])
    assert signatures[0]["http_probes"][0]["verify_tls"] is True


def test_fingerprint_signature_rejects_invalid_tls_setting():
    with pytest.raises(ValueError, match="verify_tls"):
        validated_signatures([{
            "name": "Client NAC",
            "posture_type": "unknown",
            "tcp_ports": [],
            "http_probes": [{
                "scheme": "https",
                "port": 443,
                "markers": ["client"],
                "verify_tls": "no",
            }],
            "workflow_url": None,
            "rdns_markers": [],
        }])


def test_agent_workflow_can_match_product_and_base_url(monkeypatch):
    session = FakeSession()
    monkeypatch.setattr(posture, "_bound_session", lambda iface: session)
    monkeypatch.setattr(posture, "_posture_connectivity_verified", lambda *a, **k: True)
    attempt = posture.bypass_http_posture(
        None,
        workflows=[{
            "name": "client-agent-api",
            "match_products": ["Client NAC"],
            "base_url": "https://nac.client.example/",
            "steps": [{"path": "/authorized", "expected_status": 200}],
        }],
        product="Client NAC",
        posture_type="unknown",
        iface="eth0",
    )
    assert attempt.attempted and attempt.success
    assert session.calls[0][1] == "https://nac.client.example/authorized"


def test_workflow_validation_rejects_unmatched_or_empty_workflow():
    import pytest
    with pytest.raises(ValueError, match="matcher"):
        posture.validate_workflows([{"name": "bad", "steps": [{"path": "/"}]}])
    with pytest.raises(ValueError, match="at least one step"):
        posture.validate_workflows([{"name": "bad", "match_hosts": ["portal"], "steps": []}])
