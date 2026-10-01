from fastapi.testclient import TestClient
from app.main import app

client = TestClient(app)


def test_login_and_me():
    response = client.post("/api/v1/auth/login", json={"email": "admin@besafe.local", "password": "Bsa-Test-Only-2026!"})
    assert response.status_code == 200
    assert "bsa_session" in response.cookies
    me = client.get("/api/v1/auth/me")
    assert me.status_code == 200
    assert me.json()["role"] == "admin"
    assert me.json()["tenant_id"] == "tenant-demo"


def test_api_requires_authentication():
    unauthenticated = TestClient(app)
    response = unauthenticated.get("/api/v1/assets")
    assert response.status_code == 401


def test_admin_audit_is_tenant_scoped():
    response = client.post("/api/v1/auth/login", json={"email": "admin@besafe.local", "password": "Bsa-Test-Only-2026!"})
    audit = client.get("/api/v1/audit")
    assert audit.status_code == 200
    assert any(item["action"] == "login" for item in audit.json())

def test_logout_revokes_session_cookie():
    response = client.post("/api/v1/auth/login", json={"email": "admin@besafe.local", "password": "Bsa-Test-Only-2026!"})
    assert response.status_code == 200
    assert client.get("/api/v1/auth/me").status_code == 200
    logout = client.post("/api/v1/auth/logout")
    assert logout.status_code == 200
    assert client.get("/api/v1/auth/me").status_code == 401
