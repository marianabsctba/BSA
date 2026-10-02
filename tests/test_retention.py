import time
from datetime import datetime, timezone, timedelta

import app.auth as auth
import app.history as history
import app.job_queue as job_queue
from app.retention import (
    get_retention_policy,
    set_retention_policy,
    retention_preview,
    apply_retention,
)


def _principal(tmp_path, monkeypatch):
    monkeypatch.setattr(auth,"DB_PATH",str(tmp_path/"auth.db"))
    conn=auth._db()
    conn.execute("INSERT INTO tenants(id,name) VALUES(?,?)",("tenant-a","Tenant A"))
    conn.execute(
        "INSERT INTO users(id,tenant_id,email,name,password_hash,role,created_at) VALUES(?,?,?,?,?,?,?)",
        ("u1","tenant-a","u1@example.org","User One",auth._hash("VeryStrongPass123!"),"admin",int(time.time())),
    )
    conn.commit(); conn.close()
    return auth.Principal("u1","tenant-a","u1@example.org","admin","User One")


def test_retention_policy_defaults_and_can_be_overridden(tmp_path, monkeypatch):
    principal=_principal(tmp_path,monkeypatch)
    default=get_retention_policy("tenant-a")
    assert default["retention_days"]==180
    assert default["source"]=="default"

    updated=set_retention_policy(principal,90)
    assert updated["retention_days"]==90
    assert updated["source"]=="tenant"


def test_retention_dry_run_and_apply_only_remove_old_terminal_data(tmp_path, monkeypatch):
    principal=_principal(tmp_path,monkeypatch)
    monkeypatch.setenv("BSA_JOBS_DB",str(tmp_path/"jobs.db"))
    monkeypatch.setenv("BSA_HISTORY_DB",str(tmp_path/"history.db"))
    set_retention_policy(principal,30)

    now=1_800_000_000
    old=now-40*86400
    fresh=now-5*86400

    # jobs: old terminal is eligible, fresh terminal and old running are preserved
    conn=job_queue._db()
    base=("tenant-a","u1","u1@example.org","admin","User One","example.org","surface","AUTH-1")
    conn.execute("""INSERT INTO assessment_jobs(
        job_id,tenant_id,user_id,email,role,name,target,profile,authorization_ref,status,created_at,completed_at
    ) VALUES(?,?,?,?,?,?,?,?,?,?,?,?)""",("old-done",*base,"succeeded",old,old))
    conn.execute("""INSERT INTO assessment_jobs(
        job_id,tenant_id,user_id,email,role,name,target,profile,authorization_ref,status,created_at,completed_at
    ) VALUES(?,?,?,?,?,?,?,?,?,?,?,?)""",("fresh-done",*base,"failed",fresh,fresh))
    conn.execute("""INSERT INTO assessment_jobs(
        job_id,tenant_id,user_id,email,role,name,target,profile,authorization_ref,status,created_at,started_at
    ) VALUES(?,?,?,?,?,?,?,?,?,?,?,?)""",("old-running",*base,"running",old,old))
    conn.commit(); conn.close()

    old_iso=datetime.fromtimestamp(old,tz=timezone.utc).isoformat()
    fresh_iso=datetime.fromtimestamp(fresh,tz=timezone.utc).isoformat()
    conn=history._history_db()
    conn.execute(
        """INSERT INTO asset_observations(
            tenant_id,fingerprint,observed_at,confidence,evidence_count,sources_json,tags_json,evidence_refs_json
        ) VALUES(?,?,?,?,?,?,?,?)""",
        ("tenant-a","fp-old",old_iso,80,1,"[]","[]","[]"),
    )
    conn.execute(
        """INSERT INTO asset_observations(
            tenant_id,fingerprint,observed_at,confidence,evidence_count,sources_json,tags_json,evidence_refs_json
        ) VALUES(?,?,?,?,?,?,?,?)""",
        ("tenant-a","fp-fresh",fresh_iso,80,1,"[]","[]","[]"),
    )
    conn.commit(); conn.close()

    # audit must remain untouched
    auth.audit(principal,"read","asset","a1",{})

    preview=retention_preview("tenant-a",now=now)
    assert preview["counts"]["assessment_jobs"]==1
    assert preview["counts"]["asset_observations"]==1
    assert "audit_log" in preview["preserved"]

    result=apply_retention(principal,now=now)
    assert result["deleted"]["assessment_jobs"]==1
    assert result["deleted"]["asset_observations"]==1

    conn=job_queue._db()
    states={r["job_id"]:r["status"] for r in conn.execute(
        "SELECT job_id,status FROM assessment_jobs ORDER BY job_id"
    ).fetchall()}
    conn.close()
    assert "old-done" not in states
    assert states["fresh-done"]=="failed"
    assert states["old-running"]=="running"

    conn=history._history_db()
    fps=[r["fingerprint"] for r in conn.execute(
        "SELECT fingerprint FROM asset_observations ORDER BY fingerprint"
    ).fetchall()]
    conn.close()
    assert fps==["fp-fresh"]

    conn=auth._db()
    assert conn.execute("SELECT COUNT(*) FROM audit_log WHERE tenant_id='tenant-a'").fetchone()[0]==1
    conn.close()
