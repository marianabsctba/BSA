from fastapi.testclient import TestClient
from app.main import app

client=TestClient(app)

def test_custom_role_rejects_unknown_permission():
    r=client.post("/api/v1/auth/login",json={"email":"admin@besafe.local","password":"Bsa-Test-Only-2026!"})
    assert r.status_code==200
    token=r.cookies.get("bsa_session")
    r=client.post("/api/v1/rbac/custom-roles",cookies={"bsa_session":token},json={"name":"SOC Read Only","permissions":["assets:read","not:a:permission"]})
    assert r.status_code==400
