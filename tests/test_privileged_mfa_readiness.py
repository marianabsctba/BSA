import json

from app import auth
from app.mfa_readiness import privileged_mfa_readiness


def _seed(tmp_path,monkeypatch):
    monkeypatch.setattr(auth,"DB_PATH",str(tmp_path/"auth.db"))
    monkeypatch.setattr(auth,"JWT_SECRET","j"*48)
    monkeypatch.setattr(auth,"MFA_KEY","m"*48)
    conn=auth._db()
    conn.execute("INSERT INTO tenants(id,name) VALUES(?,?)",("tenant-a","Tenant A"))
    for user_id,role in (("admin-a","admin"),("super-a","superadmin"),("analyst-a","analyst")):
        conn.execute(
            "INSERT INTO users(id,tenant_id,email,name,password_hash,role,created_at) VALUES(?,?,?,?,?,?,?)",
            (user_id,"tenant-a",f"{user_id}@example.org",user_id,auth._hash("CorrectHorseBattery1!"),role,1),
        )
    conn.commit(); conn.close()


def _enable_mfa(user_id):
    conn=auth._db()
    conn.execute(
        "INSERT INTO users_mfa(user_id,secret,enabled,created_at,last_counter) VALUES(?,?,1,?,NULL)",
        (user_id,auth._encrypt_mfa_secret(auth.generate_mfa_secret()),1),
    )
    conn.commit(); conn.close()


def test_privileged_mfa_readiness_degrades_without_policy_and_enrollment(tmp_path,monkeypatch):
    _seed(tmp_path,monkeypatch)
    result=privileged_mfa_readiness()
    assert result["status"]=="degraded"
    assert result["tenants_checked"]==1
    assert result["tenants_not_ready"]==1
    assert result["tenants_missing_policy"]==1
    assert result["privileged_users_without_mfa"]==2
    assert "tenant-a" not in json.dumps(result)
    assert "admin-a" not in json.dumps(result)


def test_privileged_mfa_readiness_is_healthy_when_policy_and_factors_are_active(tmp_path,monkeypatch):
    _seed(tmp_path,monkeypatch)
    _enable_mfa("admin-a")
    _enable_mfa("super-a")
    conn=auth._db()
    conn.execute(
        "INSERT INTO tenant_security_policy(tenant_id,mfa_required_roles,updated_at) VALUES(?,?,?)",
        ("tenant-a",json.dumps(["admin","superadmin"]),1),
    )
    conn.commit(); conn.close()
    result=privileged_mfa_readiness()
    assert result["status"]=="healthy"
    assert result["tenants_not_ready"]==0
    assert result["privileged_users_without_mfa"]==0


def test_tenant_without_privileged_users_does_not_block_readiness(tmp_path,monkeypatch):
    monkeypatch.setattr(auth,"DB_PATH",str(tmp_path/"auth.db"))
    conn=auth._db()
    conn.execute("INSERT INTO tenants(id,name) VALUES(?,?)",("tenant-viewer","Viewer Tenant"))
    conn.execute(
        "INSERT INTO users(id,tenant_id,email,name,password_hash,role,created_at) VALUES(?,?,?,?,?,?,?)",
        ("viewer","tenant-viewer","viewer@example.org","Viewer",auth._hash("CorrectHorseBattery1!"),"viewer",1),
    )
    conn.commit(); conn.close()
    result=privileged_mfa_readiness()
    assert result["status"]=="healthy"
    assert result["tenants_checked"]==0
