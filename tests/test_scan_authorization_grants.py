import time
from types import SimpleNamespace

import app.auth as auth
import app.scan_authorization as grants
import app.worker as worker
from app import job_queue


def _setup_user(tmp_path, monkeypatch, role="admin"):
    monkeypatch.setattr(auth,"DB_PATH",str(tmp_path/"auth.db"))
    conn=auth._db()
    conn.execute("INSERT INTO tenants(id,name) VALUES(?,?)",("tenant-a","Tenant A"))
    conn.execute(
        "INSERT INTO users(id,tenant_id,email,name,password_hash,role,created_at) VALUES(?,?,?,?,?,?,?)",
        ("u1","tenant-a","u1@example.org","User One",auth._hash("VeryStrongPass123!"),role,int(time.time())),
    )
    conn.commit(); conn.close()
    return auth.Principal("u1","tenant-a","u1@example.org",role,"User One")


def test_scan_authorization_grant_expires_and_revokes(tmp_path, monkeypatch):
    principal=_setup_user(tmp_path,monkeypatch)
    admin=principal
    grant=grants.create_authorization_grant(admin,"u1","AUTH-1","example.org",ttl_seconds=60)

    assert grants.authorization_grant_valid(principal,"AUTH-1","api.example.org",now=grant["created_at"]+1)
    assert not grants.authorization_grant_valid(principal,"AUTH-1","other.org",now=grant["created_at"]+1)
    assert not grants.authorization_grant_valid(principal,"AUTH-1","api.example.org",now=grant["expires_at"]+1)

    revoked=grants.revoke_authorization_grant(admin,grant["grant_id"])
    assert revoked["revoked"] is True
    assert not grants.authorization_grant_valid(principal,"AUTH-1","api.example.org",now=grant["created_at"]+1)


def test_worker_fails_when_current_user_loses_discovery_permission(tmp_path, monkeypatch):
    principal=_setup_user(tmp_path,monkeypatch)
    monkeypatch.setenv("BSA_JOBS_DB",str(tmp_path/"jobs.db"))

    job=job_queue.enqueue_assessment(principal,"example.org","surface","AUTH-1")

    conn=auth._db()
    conn.execute("UPDATE users SET role='viewer' WHERE id='u1'")
    conn.commit(); conn.close()

    assert worker.run_once() is True
    final=job_queue.get_job(job["job_id"],"tenant-a")
    assert final["status"]=="failed"
    assert "discovery:run" in final["error"]


def test_worker_fails_when_scan_grant_revoked_before_execution(tmp_path, monkeypatch):
    principal=_setup_user(tmp_path,monkeypatch)
    monkeypatch.setenv("BSA_JOBS_DB",str(tmp_path/"jobs.db"))
    monkeypatch.setenv("BSA_ENV","production")

    grant=grants.create_authorization_grant(principal,"u1","AUTH-1","example.org",ttl_seconds=300)

    import app.scope as scope
    monkeypatch.setattr(scope,"active_scan_in_scope",lambda *args,**kwargs: True)
    monkeypatch.setattr(worker,"active_scan_in_scope",lambda *args,**kwargs: True)

    job=job_queue.enqueue_assessment(principal,"example.org","surface","AUTH-1")
    grants.revoke_authorization_grant(principal,grant["grant_id"])

    assert worker.run_once() is True
    final=job_queue.get_job(job["job_id"],"tenant-a")
    assert final["status"]=="failed"
    assert "authorization grant" in final["error"]
