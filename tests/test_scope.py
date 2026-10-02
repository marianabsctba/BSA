from fastapi.testclient import TestClient
from app.main import app

client = TestClient(app)

def login():
    r=client.post("/api/v1/auth/login",json={"email":"admin@besafe.local","password":"Bsa-Test-Only-2026!"})
    assert r.status_code==200
    return {}

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


def test_active_scan_scope_is_separate_from_visibility_scope(tmp_path, monkeypatch):
    import app.auth as auth
    import app.scope as scope
    monkeypatch.setattr(auth,"DB_PATH",str(tmp_path/"auth.db"))
    monkeypatch.setattr(scope,"_db",auth._db)
    monkeypatch.setenv("BSA_ENV","production")

    conn=auth._db()
    conn.execute("INSERT OR IGNORE INTO tenants(id,name) VALUES(?,?)",("tenant-x","Tenant X"))
    conn.execute(
        "INSERT INTO users(id,tenant_id,email,name,password_hash,role,created_at) VALUES(?,?,?,?,?,?,?)",
        ("u1","tenant-x","u1@example.org","U1",auth._hash("VeryStrongPass123!"),"admin",1),
    )
    conn.commit(); conn.close()

    p=auth.Principal("u1","tenant-x","u1@example.org","admin","U1")
    monkeypatch.setattr(scope,"_verify_dns_txt",lambda domain,challenge: True)
    proof=scope.create_domain_ownership_proof(p,"example.org","dns_txt")
    assert scope.verify_domain_ownership_proof(p,proof["proof_id"])["verified"] is True

    visible=scope.create_scope(p,"Visible","*.example.org")
    scope.assign_scope(p,"u1",visible["id"])
    assert scope.asset_in_scope(p,"api.example.org") is True
    assert scope.active_scan_in_scope(p,"api.example.org") is False

    active=scope.create_scan_scope(p,"Active","api.example.org")
    scope.assign_scan_scope(p,"u1",active["id"])
    assert scope.active_scan_in_scope(p,"api.example.org") is True
    assert scope.active_scan_in_scope(p,"other.example.org") is False
