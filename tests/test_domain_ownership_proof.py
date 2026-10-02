import time

from app import auth, scope


def _principal(user_id: str, tenant_id: str, role: str="admin"):
    return auth.Principal(user_id,tenant_id,f"{user_id}@example.test",role,user_id)


def _seed_tenant(conn, tenant_id: str, user_id: str, role: str="admin"):
    conn.execute("INSERT INTO tenants(id,name) VALUES(?,?)",(tenant_id,tenant_id))
    conn.execute(
        "INSERT INTO users(id,tenant_id,email,name,password_hash,role,created_at) VALUES(?,?,?,?,?,?,?)",
        (user_id,tenant_id,f"{user_id}@example.test",user_id,auth._hash("VeryStrongPass123!"),role,int(time.time())),
    )


def test_production_scan_scope_requires_verified_domain_ownership(tmp_path, monkeypatch):
    monkeypatch.setattr(auth,"DB_PATH",str(tmp_path/"auth.db"))
    monkeypatch.setenv("BSA_ENV","production")
    conn=auth._db()
    _seed_tenant(conn,"tenant-a","admin-a")
    conn.commit(); conn.close()
    admin=_principal("admin-a","tenant-a")

    try:
        scope.create_scan_scope(admin,"Example","example.org")
    except PermissionError as exc:
        assert "verified domain ownership proof" in str(exc)
    else:
        raise AssertionError("production scan scope accepted without ownership proof")


def test_verified_dns_proof_allows_production_scan_scope(tmp_path, monkeypatch):
    monkeypatch.setattr(auth,"DB_PATH",str(tmp_path/"auth.db"))
    monkeypatch.setenv("BSA_ENV","production")
    monkeypatch.setattr(scope,"_verify_dns_txt",lambda domain,challenge: True)
    conn=auth._db()
    _seed_tenant(conn,"tenant-a","admin-a")
    conn.commit(); conn.close()
    admin=_principal("admin-a","tenant-a")

    proof=scope.create_domain_ownership_proof(admin,"example.org","dns_txt")
    verified=scope.verify_domain_ownership_proof(admin,proof["proof_id"])
    assert verified["verified"] is True

    created=scope.create_scan_scope(admin,"Example","*.example.org")
    assert created["ownership_verified"] is True
    assert created["overlap_approved_by_superadmin"] is False


def test_cross_tenant_domain_overlap_requires_superadmin(tmp_path, monkeypatch):
    monkeypatch.setattr(auth,"DB_PATH",str(tmp_path/"auth.db"))
    monkeypatch.setenv("BSA_ENV","production")
    monkeypatch.setattr(scope,"_verify_dns_txt",lambda domain,challenge: True)
    conn=auth._db()
    _seed_tenant(conn,"tenant-a","admin-a")
    _seed_tenant(conn,"tenant-b","admin-b")
    _seed_tenant(conn,"tenant-c","super-c","superadmin")
    conn.commit(); conn.close()

    admin_a=_principal("admin-a","tenant-a")
    admin_b=_principal("admin-b","tenant-b")
    super_c=_principal("super-c","tenant-c","superadmin")

    for principal in (admin_a,admin_b,super_c):
        proof=scope.create_domain_ownership_proof(principal,"example.org","dns_txt")
        assert scope.verify_domain_ownership_proof(principal,proof["proof_id"])["verified"] is True

    scope.create_scan_scope(admin_a,"A","example.org")

    try:
        scope.create_scan_scope(admin_b,"B","api.example.org")
    except PermissionError as exc:
        assert "superadmin approval" in str(exc)
    else:
        raise AssertionError("cross-tenant overlap accepted for tenant admin")

    approved=scope.create_scan_scope(super_c,"C","*.example.org")
    assert approved["overlap_approved_by_superadmin"] is True


def test_ownership_challenge_never_uses_global_or_public_suffix(tmp_path, monkeypatch):
    monkeypatch.setattr(auth,"DB_PATH",str(tmp_path/"auth.db"))
    conn=auth._db()
    _seed_tenant(conn,"tenant-a","admin-a")
    conn.commit(); conn.close()
    admin=_principal("admin-a","tenant-a")

    for invalid in ("*","com"):
        try:
            scope.create_domain_ownership_proof(admin,invalid,"dns_txt")
        except ValueError:
            pass
        else:
            raise AssertionError(f"invalid ownership target accepted: {invalid}")
