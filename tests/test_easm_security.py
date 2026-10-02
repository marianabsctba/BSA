from fastapi.testclient import TestClient
from app.main import app
from app.security import validate_external_target

client = TestClient(app)


def login():
    response = client.post(
        "/api/v1/auth/login",
        json={"email": "admin@besafe.local", "password": "Bsa-Test-Only-2026!"},
    )
    assert response.status_code == 200
    return {}


def test_external_target_blocks_private_and_loopback_addresses():
    for target in ("127.0.0.1", "http://127.0.0.1", "http://10.0.0.1", "http://192.168.1.1"):
        try:
            validate_external_target(target)
            assert False, f"private target was accepted: {target}"
        except ValueError:
            pass


def test_external_target_rejects_non_http_schemes():
    for target in ("file:///etc/passwd", "ftp://example.com", "javascript:alert(1)"):
        try:
            validate_external_target(target)
            assert False, f"unsafe scheme was accepted: {target}"
        except ValueError:
            pass


def test_easm_bounds_are_enforced():
    h = login()
    assert client.post("/api/v1/easm/discover/example.com?max_depth=-1", headers=h).status_code == 400
    assert client.post("/api/v1/easm/discover/example.com?max_depth=4", headers=h).status_code == 400
    assert client.post("/api/v1/easm/discover/example.com?max_assets=0", headers=h).status_code == 400
    assert client.post("/api/v1/easm/discover/example.com?max_assets=101", headers=h).status_code == 400


def test_discovery_routes_use_store_tenant_scope(monkeypatch):
    h = login()

    fake = {
        "target": "example.com",
        "url": "https://example.com",
        "checks": ["dns", "http", "tls", "ct"],
        "evidence": [],
        "evidence_count": 0,
        "confidence": 0,
    }

    monkeypatch.setattr("app.main.collect_target", lambda *args, **kwargs: fake)
    monkeypatch.setattr("app.main.correlate_evidence", lambda *args, **kwargs: [])

    for path in (
        "/api/v1/discovery/example.com/changes",
        "/api/v1/discovery/example.com/graph",
        "/api/v1/discovery/example.com/correlation",
    ):
        response = client.post(path, headers=h)
        assert response.status_code != 500, path
