import pytest
from app.security import validate_external_target, validate_redirect

def test_security_blocks_local_targets():
    for target in ("http://127.0.0.1","http://localhost","http://10.0.0.1","http://169.254.169.254"):
        with pytest.raises(ValueError):
            validate_external_target(target)

def test_security_accepts_public_hostname():
    host,url=validate_external_target("https://example.com")
    assert host=="example.com"
    assert url=="https://example.com"

def test_security_blocks_private_redirect():
    with pytest.raises(ValueError):
        validate_redirect("http://127.0.0.1/admin")

def test_security_headers_are_present():
    from fastapi.testclient import TestClient
    from app.main import app
    response=TestClient(app).get("/health")
    assert response.headers["x-content-type-options"]=="nosniff"
    assert response.headers["x-frame-options"]=="DENY"
    assert response.headers["referrer-policy"]=="no-referrer"


def test_cookie_mutation_requires_csrf_marker(monkeypatch):
    from fastapi.testclient import TestClient
    from app.main import app
    monkeypatch.setenv("BSA_ENV","production")
    client=TestClient(app)
    blocked=client.post("/api/v1/auth/logout",cookies={"bsa_session":"invalid-session"})
    assert blocked.status_code==403
    assert blocked.json()["detail"]=="csrf request marker required"

    marked=client.post(
        "/api/v1/auth/logout",
        cookies={"bsa_session":"invalid-session"},
        headers={"X-Requested-With":"BeSafeASM"},
    )
    assert marked.status_code==401
