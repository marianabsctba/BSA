import json
import time

import pytest

import app.auth as auth


def _principal(user_id, tenant_id, role="admin"):
    return auth.Principal(user_id, tenant_id, f"{user_id}@example.org", role, user_id)


def test_custom_role_names_are_isolated_per_tenant(tmp_path, monkeypatch):
    monkeypatch.setattr(auth, "DB_PATH", str(tmp_path / "auth.db"))

    conn=auth._db()
    conn.execute("INSERT INTO tenants(id,name) VALUES(?,?)",("tenant-a","Tenant A"))
    conn.execute("INSERT INTO tenants(id,name) VALUES(?,?)",("tenant-b","Tenant B"))
    conn.commit(); conn.close()

    a=_principal("a-admin","tenant-a")
    b=_principal("b-admin","tenant-b")

    role_a=auth.create_custom_role(a,"SOC Read",["assets:read"])
    role_b=auth.create_custom_role(b,"SOC Read",["findings:read"])

    assert role_a["name"]==role_b["name"]=="custom:soc-read"
    assert auth.role_permissions(role_a["name"],"tenant-a")==["assets:read"]
    assert auth.role_permissions(role_b["name"],"tenant-b")==["findings:read"]


def test_audit_read_permission_does_not_require_users_write(tmp_path, monkeypatch):
    monkeypatch.setattr(auth, "DB_PATH", str(tmp_path / "auth.db"))

    conn=auth._db()
    conn.execute("INSERT INTO tenants(id,name) VALUES(?,?)",("tenant-a","Tenant A"))
    conn.execute(
        "INSERT INTO custom_roles(name,tenant_id,permissions,created_at) VALUES(?,?,?,?)",
        ("custom:auditor","tenant-a",json.dumps(["audit:read"]),int(time.time())),
    )
    conn.commit(); conn.close()

    principal=_principal("auditor","tenant-a","custom:auditor")
    auth.audit(principal,"read","asset","ast-1",{"source":"test"})
    rows=auth.list_audit(principal)

    assert len(rows)==1
    assert rows[0]["tenant_id"]=="tenant-a"

    conn=auth._db()
    conn.execute(
        "INSERT INTO custom_roles(name,tenant_id,permissions,created_at) VALUES(?,?,?,?)",
        ("custom:no-audit","tenant-a",json.dumps(["assets:read"]),int(time.time())),
    )
    conn.commit(); conn.close()

    denied=_principal("reader","tenant-a","custom:no-audit")
    with pytest.raises(PermissionError,match="audit:read required"):
        auth.list_audit(denied)
