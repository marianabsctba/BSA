from types import SimpleNamespace
from datetime import datetime, timezone

import app.auth as auth
import app.history as history
import app.job_queue as job_queue
import app.store as store
from app.models import Asset, AssetType, Finding, Severity
from app.tenant_lifecycle import retire_tenant, tenant_purge_preview, purge_tenant


def _superadmin():
    return auth.Principal("root","tenant-root","root@example.org","superadmin","Root")


def test_tenant_purge_is_scoped_and_preserves_audit_by_default(tmp_path, monkeypatch):
    auth_db=tmp_path/"auth.db"
    hist_db=tmp_path/"history.db"
    jobs_db=tmp_path/"jobs.db"
    store_db=tmp_path/"store.db"
    monkeypatch.setattr(auth,"DB_PATH",str(auth_db))
    monkeypatch.setenv("BSA_HISTORY_DB",str(hist_db))
    monkeypatch.setenv("BSA_JOBS_DB",str(jobs_db))
    monkeypatch.setenv("BSA_STORE_DB",str(store_db))

    conn=auth._db()
    conn.execute("INSERT INTO tenants(id,name) VALUES(?,?)",("tenant-root","Root"))
    conn.execute("INSERT INTO tenants(id,name) VALUES(?,?)",("tenant-a","Tenant A"))
    conn.execute("INSERT INTO tenants(id,name) VALUES(?,?)",("tenant-b","Tenant B"))
    conn.execute(
        "INSERT INTO users(id,tenant_id,email,name,password_hash,role,created_at) VALUES(?,?,?,?,?,?,?)",
        ("ua","tenant-a","a@example.org","A",auth._hash("VeryStrongPass123!"),"admin",1),
    )
    conn.execute(
        "INSERT INTO users(id,tenant_id,email,name,password_hash,role,created_at) VALUES(?,?,?,?,?,?,?)",
        ("ub","tenant-b","b@example.org","B",auth._hash("VeryStrongPass123!"),"admin",1),
    )
    conn.commit(); conn.close()

    pa=auth.Principal("ua","tenant-a","a@example.org","admin","A")
    pb=auth.Principal("ub","tenant-b","b@example.org","admin","B")
    auth.audit(pa,"read","asset","a1",{})
    auth.audit(pb,"read","asset","b1",{})

    ja=job_queue.enqueue_assessment(pa,"a.example.org","surface","AUTH-A")
    jb=job_queue.enqueue_assessment(pb,"b.example.org","surface","AUTH-B")
    assert ja and jb

    now=datetime.now(timezone.utc).isoformat()
    store.ASSETS[:]=[
        Asset(tenant_id="tenant-a",id="a1",value="a.example.org",type=AssetType.DOMAIN,first_seen=now,last_seen=now),
        Asset(tenant_id="tenant-b",id="b1",value="b.example.org",type=AssetType.DOMAIN,first_seen=now,last_seen=now),
    ]
    store.FINDINGS[:]=[
        Finding(tenant_id="tenant-a",id="fa",asset_id="a1",title="A",severity=Severity.LOW),
        Finding(tenant_id="tenant-b",id="fb",asset_id="b1",title="B",severity=Severity.LOW),
    ]
    store.persist_state(store.ASSETS,store.FINDINGS)

    preview=tenant_purge_preview("tenant-a")
    assert preview["counts"]["users"]==1
    assert preview["counts"]["assessment_jobs"]==1

    result=purge_tenant(_superadmin(),"tenant-a")
    assert result["purged"] is True
    assert job_queue.get_job(ja["job_id"],"tenant-a") is None
    assert job_queue.get_job(jb["job_id"],"tenant-b") is not None
    assert all(x.tenant_id!="tenant-a" for x in store.ASSETS)
    assert any(x.tenant_id=="tenant-b" for x in store.ASSETS)

    conn=auth._db()
    assert conn.execute("SELECT 1 FROM tenants WHERE id='tenant-a'").fetchone() is None
    assert conn.execute("SELECT 1 FROM tenants WHERE id='tenant-b'").fetchone() is not None
    assert conn.execute("SELECT COUNT(*) FROM audit_log WHERE tenant_id='tenant-a'").fetchone()[0]==1
    conn.close()


def test_retire_revokes_sessions_and_deactivates_users(tmp_path, monkeypatch):
    monkeypatch.setattr(auth,"DB_PATH",str(tmp_path/"auth.db"))
    conn=auth._db()
    conn.execute("INSERT INTO tenants(id,name) VALUES(?,?)",("tenant-root","Root"))
    conn.execute("INSERT INTO tenants(id,name) VALUES(?,?)",("tenant-a","Tenant A"))
    conn.execute(
        "INSERT INTO users(id,tenant_id,email,name,password_hash,role,created_at) VALUES(?,?,?,?,?,?,?)",
        ("ua","tenant-a","a@example.org","A",auth._hash("VeryStrongPass123!"),"admin",1),
    )
    conn.execute(
        "INSERT INTO sessions(jti,user_id,tenant_id,created_at,expires_at) VALUES(?,?,?,?,?)",
        ("s1","ua","tenant-a",1,9999999999),
    )
    conn.commit(); conn.close()

    result=retire_tenant(_superadmin(),"tenant-a")
    assert result["retired"] is True
    conn=auth._db()
    assert conn.execute("SELECT active FROM tenants WHERE id='tenant-a'").fetchone()["active"]==0
    assert conn.execute("SELECT active FROM users WHERE id='ua'").fetchone()["active"]==0
    assert conn.execute("SELECT revoked_at FROM sessions WHERE jti='s1'").fetchone()["revoked_at"] is not None
    conn.close()


def test_persisted_store_survives_restart_simulation(tmp_path, monkeypatch):
    monkeypatch.setenv("BSA_STORE_DB",str(tmp_path/"store.db"))
    now=datetime.now(timezone.utc).isoformat()
    asset=Asset(tenant_id="tenant-a",id="a1",value="api.example.org",type=AssetType.DOMAIN,first_seen=now,last_seen=now)
    finding=Finding(tenant_id="tenant-a",id="f1",asset_id="a1",title="Exposure",severity=Severity.HIGH)
    store.persist_state([asset],[finding])

    assets,findings=store._load_persisted()
    assert [x.id for x in assets]==["a1"]
    assert [x.id for x in findings]==["f1"]
    assert assets[0].tenant_id=="tenant-a"
    assert findings[0].tenant_id=="tenant-a"


def test_job_survives_database_reopen(tmp_path, monkeypatch):
    monkeypatch.setenv("BSA_JOBS_DB",str(tmp_path/"jobs.db"))
    principal=SimpleNamespace(
        tenant_id="tenant-a",user_id="u1",email="u1@example.org",role="admin",name="U1",
    )
    job=job_queue.enqueue_assessment(principal,"example.org","surface","AUTH-1")
    reopened=job_queue.get_job(job["job_id"],"tenant-a")
    assert reopened is not None
    assert reopened["status"]=="queued"
