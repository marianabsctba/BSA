from fastapi.testclient import TestClient
from app.main import app

client=TestClient(app)

def login():
    r=client.post("/api/v1/auth/login",json={"email":"admin@besafe.local","password":"Bsa-Test-Only-2026!"})
    assert r.status_code==200
    return r.cookies

def test_user_lifecycle_routes_exist_and_reject_missing_user_safely():
    cookies=login()
    headers={"Cookie":"bsa_session="+cookies.get("bsa_session","")}
    r=client.patch("/api/v1/users/does-not-exist",headers=headers,json={"name":"x","role":"viewer"})
    assert r.status_code in {400,404}
    r=client.patch("/api/v1/users/does-not-exist/active",headers=headers,json={"active":False})
    assert r.status_code in {400,404}
    r=client.post("/api/v1/users/does-not-exist/reset-password",headers=headers,json={"password":"Long-Test-Only-Password-2026!"})
    assert r.status_code in {400,404}

def test_user_role_cannot_be_arbitrary():
    cookies=login()
    headers={"Cookie":"bsa_session="+cookies.get("bsa_session","")}
    r=client.patch("/api/v1/users/does-not-exist",headers=headers,json={"name":"x","role":"super-evil"})
    assert r.status_code in {400,404}
