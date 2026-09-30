from fastapi.testclient import TestClient
from app.main import app

client = TestClient(app)

def login():
    r=client.post("/api/v1/auth/login",json={"email":"admin@besafe.local","password":"ChangeMe!123"})
    assert r.status_code==200
    return {"Authorization":"Bearer "+r.json()["access_token"]}

def test_scope_admin_lifecycle():
    h=login()
    r=client.post("/api/v1/scopes",headers=h,json={"name":"Internet APIs","pattern":"*.example.org"})
    assert r.status_code==200
    scope_id=r.json()["id"]
    scopes=client.get("/api/v1/scopes",headers=h)
    assert scopes.status_code==200
    assert any(x["id"]==scope_id for x in scopes.json())

def test_scope_blocks_unassigned_non_admin():
    # The bootstrap admin is intentionally full-scope; this asserts the helper contract
    from app.scope import asset_in_scope
    from app.auth import Principal
    p=Principal("u","tenant-demo","u@example.org","analyst","Analyst")
    assert asset_in_scope(p,"example.org") is False
