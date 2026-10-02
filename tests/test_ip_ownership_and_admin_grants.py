import time

import pytest

from app import auth, scope
from app import scan_authorization as grants


def _seed_user(conn, user_id: str, tenant_id: str, role: str):
    conn.execute(
        "INSERT INTO users(id,tenant_id,email,name,password_hash,role,created_at) VALUES(?,?,?,?,?,?,?)",
        (user_id,tenant_id,f"{user_id}@example.test",user_id,auth._hash("VeryStrongPass123!"),role,int(time.time())),
    )


def test_production_public_ip_scope_requires_strong_ownership(tmp_path, monkeypatch):
    monkeypatch.setattr(auth,"DB_PATH",str(tmp_path/"auth.db"))
    monkeypatch.setenv("BSA_ENV","production")
    conn=auth._db()
    conn.execute("INSERT INTO tenants(id,name) VALUES(?,?)",("tenant-a","Tenant A"))
    _seed_user(conn,"admin-a","tenant-a","admin")
    conn.commit(); conn.close()

    admin=auth.Principal("admin-a","tenant-a","admin-a@example.test","admin","Admin A")
    with pytest.raises(PermissionError,match="public IP ownership approval"):
        scope.create_scan_scope(admin,"Public IP","8.8.8.8")


def test_superadmin_contract_reference_allows_public_ip_scope(tmp_path, monkeypatch):
    monkeypatch.setattr(auth,"DB_PATH",str(tmp_path/"auth.db"))
    monkeypatch.setenv("BSA_ENV","production")
    conn=auth._db()
    conn.execute("INSERT INTO tenants(id,name) VALUES(?,?)",("tenant-a","Tenant A"))
    _seed_user(conn,"super-a","tenant-a","superadmin")
    conn.commit(); conn.close()

    principal=auth.Principal("super-a","tenant-a","super-a@example.test","superadmin","Super A")
    approval=scope.create_ip_ownership_approval(
        principal,"8.8.8.8","CONTRACT-2026-001","contract",ttl_seconds=3600
    )
    created=scope.create_scan_scope(
        principal,"Public IP","8.8.8.8",ownership_ref=approval["authorization_ref"]
    )
    assert created["ownership_verified"] is True
    assert created["ownership_ref"]=="CONTRACT-2026-001"


def test_admin_cannot_cross_approve_scan_grant_for_another_admin(tmp_path, monkeypatch):
    monkeypatch.setattr(auth,"DB_PATH",str(tmp_path/"auth.db"))
    conn=auth._db()
    conn.execute("INSERT INTO tenants(id,name) VALUES(?,?)",("tenant-a","Tenant A"))
    _seed_user(conn,"admin-a","tenant-a","admin")
    _seed_user(conn,"admin-b","tenant-a","admin")
    conn.commit(); conn.close()

    admin_a=auth.Principal("admin-a","tenant-a","admin-a@example.test","admin","Admin A")
    active=scope.create_scan_scope(admin_a,"Example","example.org")
    scope.assign_scan_scope(admin_a,"admin-b",active["id"])

    with pytest.raises(PermissionError,match="superadmin approval"):
        grants.create_authorization_grant(admin_a,"admin-b","AUTH-ADMIN","example.org",ttl_seconds=300)


def test_superadmin_can_approve_public_ip_for_another_tenant(tmp_path, monkeypatch):
    monkeypatch.setattr(auth,"DB_PATH",str(tmp_path/"auth.db"))
    monkeypatch.setenv("BSA_ENV","production")
    conn=auth._db()
    conn.execute("INSERT INTO tenants(id,name) VALUES(?,?)",("tenant-a","Tenant A"))
    conn.execute("INSERT INTO tenants(id,name) VALUES(?,?)",("tenant-b","Tenant B"))
    _seed_user(conn,"super-a","tenant-a","superadmin")
    _seed_user(conn,"admin-b","tenant-b","admin")
    conn.commit(); conn.close()

    superadmin=auth.Principal(
        "super-a","tenant-a","super-a@example.test","superadmin","Super A"
    )
    admin_b=auth.Principal(
        "admin-b","tenant-b","admin-b@example.test","admin","Admin B"
    )

    approval=scope.create_ip_ownership_approval(
        superadmin,
        "8.8.8.8",
        "CONTRACT-TENANT-B",
        "contract",
        ttl_seconds=3600,
        tenant_id="tenant-b",
    )
    assert approval["tenant_id"]=="tenant-b"

    created=scope.create_scan_scope(
        admin_b,
        "Tenant B public IP",
        "8.8.8.8",
        ownership_ref="CONTRACT-TENANT-B",
    )
    assert created["tenant_id"]=="tenant-b"
    assert created["ownership_verified"] is True


def test_superadmin_target_tenant_must_exist(tmp_path, monkeypatch):
    monkeypatch.setattr(auth,"DB_PATH",str(tmp_path/"auth.db"))
    conn=auth._db()
    conn.execute("INSERT INTO tenants(id,name) VALUES(?,?)",("tenant-a","Tenant A"))
    _seed_user(conn,"super-a","tenant-a","superadmin")
    conn.commit(); conn.close()
    superadmin=auth.Principal(
        "super-a","tenant-a","super-a@example.test","superadmin","Super A"
    )
    with pytest.raises(ValueError,match="target tenant not found"):
        scope.create_ip_ownership_approval(
            superadmin,
            "8.8.8.8",
            "CONTRACT-MISSING",
            tenant_id="tenant-missing",
        )
