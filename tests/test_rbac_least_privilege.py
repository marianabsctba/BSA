from fastapi.testclient import TestClient
from app.main import app
import uuid

client=TestClient(app)

def login():
    r=client.post("/api/v1/auth/login",json={"email":"admin@besafe.local","password":"Bsa-Test-Only-2026!"})
    assert r.status_code==200
    return r.cookies.get("bsa_session")

def test_rbac_permission_catalog_is_exposed():
    token=login()
    r=client.get("/api/v1/auth/permissions",cookies={"bsa_session":token})
    assert r.status_code==200
    body=r.json()
    assert body["role"] in {"admin","superadmin","manager","analyst","viewer"}
    assert isinstance(body["permissions"],list)

def test_admin_cannot_grant_superadmin_role():
    token=login()
    r=client.post("/api/v1/users",cookies={"bsa_session":token},json={
        "email":f"rbac-test-{uuid.uuid4().hex}@besafe.local","name":"RBAC Test",
        "password":"Long-Test-Only-Password-2026!","role":"superadmin"
    })
    assert r.status_code in {400,403,409}
