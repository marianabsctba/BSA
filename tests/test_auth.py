from fastapi.testclient import TestClient
from app.main import app

client = TestClient(app)


def test_login_and_me():
    response = client.post("/api/v1/auth/login", json={"email": "admin@besafe.local", "password": "Bsa-Test-Only-2026!"})
    assert response.status_code == 200
    token = response.json()["access_token"]
    me = client.get("/api/v1/auth/me", headers={"Authorization": f"Bearer {token}"})
    assert me.status_code == 200
    assert me.json()["role"] == "admin"
    assert me.json()["tenant_id"] == "tenant-demo"


def test_api_requires_authentication():
    response = client.get("/api/v1/assets")
    assert response.status_code == 401


def test_admin_audit_is_tenant_scoped():
    response = client.post("/api/v1/auth/login", json={"email": "admin@besafe.local", "password": "Bsa-Test-Only-2026!"})
    token = response.json()["access_token"]
    audit = client.get("/api/v1/audit", headers={"Authorization": f"Bearer {token}"})
    assert audit.status_code == 200
    assert any(item["action"] == "login" for item in audit.json())
