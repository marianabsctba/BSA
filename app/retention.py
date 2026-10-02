import time
from datetime import datetime, timezone

from . import auth, history, job_queue


DEFAULT_RETENTION_DAYS = 180
MIN_RETENTION_DAYS = 30
MAX_RETENTION_DAYS = 3650


def ensure_retention_schema():
    conn=auth._db()
    conn.execute("""CREATE TABLE IF NOT EXISTS tenant_retention(
        tenant_id TEXT PRIMARY KEY,
        retention_days INTEGER NOT NULL,
        updated_at INTEGER NOT NULL,
        updated_by TEXT NOT NULL
    )""")
    conn.commit(); conn.close()


def get_retention_policy(tenant_id: str) -> dict:
    ensure_retention_schema()
    conn=auth._db()
    row=conn.execute(
        "SELECT retention_days,updated_at,updated_by FROM tenant_retention WHERE tenant_id=?",
        (tenant_id,),
    ).fetchone()
    conn.close()
    if not row:
        return {
            "tenant_id":tenant_id,
            "retention_days":DEFAULT_RETENTION_DAYS,
            "source":"default",
            "updated_at":None,
            "updated_by":None,
        }
    return {
        "tenant_id":tenant_id,
        "retention_days":int(row["retention_days"]),
        "source":"tenant",
        "updated_at":row["updated_at"],
        "updated_by":row["updated_by"],
    }


def set_retention_policy(principal, retention_days: int) -> dict:
    if not auth.can(principal,"tenant:manage") and principal.role not in {"admin","superadmin"}:
        raise PermissionError("tenant management permission required")
    days=int(retention_days)
    if days<MIN_RETENTION_DAYS or days>MAX_RETENTION_DAYS:
        raise ValueError(f"retention_days must be between {MIN_RETENTION_DAYS} and {MAX_RETENTION_DAYS}")
    ensure_retention_schema()
    now=int(time.time())
    conn=auth._db()
    conn.execute(
        """INSERT INTO tenant_retention(tenant_id,retention_days,updated_at,updated_by)
           VALUES(?,?,?,?)
           ON CONFLICT(tenant_id) DO UPDATE SET
             retention_days=excluded.retention_days,
             updated_at=excluded.updated_at,
             updated_by=excluded.updated_by""",
        (principal.tenant_id,days,now,principal.user_id),
    )
    conn.commit(); conn.close()
    return get_retention_policy(principal.tenant_id)


def _iso_cutoff(days: int, now: int) -> str:
    return datetime.fromtimestamp(now-days*86400,tz=timezone.utc).isoformat()


def _count(conn, table: str, where: str, args: tuple) -> int:
    exists=conn.execute(
        "SELECT 1 FROM sqlite_master WHERE type='table' AND name=?",(table,)
    ).fetchone()
    if not exists:
        return 0
    return int(conn.execute(f"SELECT COUNT(*) FROM {table} WHERE {where}",args).fetchone()[0])


def _delete(conn, table: str, where: str, args: tuple) -> int:
    exists=conn.execute(
        "SELECT 1 FROM sqlite_master WHERE type='table' AND name=?",(table,)
    ).fetchone()
    if not exists:
        return 0
    return int(conn.execute(f"DELETE FROM {table} WHERE {where}",args).rowcount)


def retention_preview(tenant_id: str, now: int | None=None) -> dict:
    now=int(now or time.time())
    policy=get_retention_policy(tenant_id)
    days=int(policy["retention_days"])
    cutoff_epoch=now-days*86400
    cutoff_iso=_iso_cutoff(days,now)
    counts={}

    conn=job_queue._db()
    counts["assessment_jobs"]=_count(
        conn,"assessment_jobs",
        "tenant_id=? AND status IN ('succeeded','failed','cancelled') AND completed_at IS NOT NULL AND completed_at<?",
        (tenant_id,cutoff_epoch),
    )
    conn.close()

    conn=history._history_db()
    counts["asset_observations"]=_count(
        conn,"asset_observations","tenant_id=? AND observed_at<?",(tenant_id,cutoff_iso)
    )
    counts["discovery_runs"]=_count(
        conn,"discovery_runs","tenant_id=? AND observed_at<?",(tenant_id,cutoff_iso)
    )
    counts["lifecycle_snapshots"]=_count(
        conn,"lifecycle_snapshots","tenant_id=? AND observed_at<?",(tenant_id,cutoff_iso)
    )
    counts["ctem_verifications"]=_count(
        conn,"ctem_verifications","tenant_id=? AND verified_at<?",(tenant_id,cutoff_iso)
    )
    counts["ctem_operations"]=_count(
        conn,"ctem_operations","tenant_id=? AND created_at<?",(tenant_id,cutoff_iso)
    )
    conn.close()

    conn=auth._db()
    counts["expired_sessions"]=_count(
        conn,"sessions","tenant_id=? AND expires_at<?",(tenant_id,cutoff_epoch)
    )
    counts["revoked_sessions"]=_count(
        conn,"sessions","tenant_id=? AND revoked_at IS NOT NULL AND revoked_at<?",(tenant_id,cutoff_epoch)
    )
    conn.close()

    return {
        "tenant_id":tenant_id,
        "retention_days":days,
        "cutoff_epoch":cutoff_epoch,
        "cutoff_iso":cutoff_iso,
        "counts":counts,
        "total_records":sum(counts.values()),
        "preserved":["audit_log","assets","findings","ctem_items","ctem_plans","digital_risk","takedowns"],
    }


def apply_retention(principal, now: int | None=None) -> dict:
    if not auth.can(principal,"tenant:manage") and principal.role not in {"admin","superadmin"}:
        raise PermissionError("tenant management permission required")
    now=int(now or time.time())
    preview=retention_preview(principal.tenant_id,now=now)
    cutoff_epoch=preview["cutoff_epoch"]
    cutoff_iso=preview["cutoff_iso"]
    tenant_id=principal.tenant_id
    deleted={}

    conn=job_queue._db()
    deleted["assessment_jobs"]=_delete(
        conn,"assessment_jobs",
        "tenant_id=? AND status IN ('succeeded','failed','cancelled') AND completed_at IS NOT NULL AND completed_at<?",
        (tenant_id,cutoff_epoch),
    )
    conn.commit(); conn.close()

    conn=history._history_db()
    for table,column in (
        ("asset_observations","observed_at"),
        ("discovery_runs","observed_at"),
        ("lifecycle_snapshots","observed_at"),
        ("ctem_verifications","verified_at"),
        ("ctem_operations","created_at"),
    ):
        deleted[table]=_delete(
            conn,table,f"tenant_id=? AND {column}<?",(tenant_id,cutoff_iso)
        )
    conn.commit(); conn.close()

    conn=auth._db()
    deleted["expired_sessions"]=_delete(
        conn,"sessions","tenant_id=? AND expires_at<?",(tenant_id,cutoff_epoch)
    )
    deleted["revoked_sessions"]=_delete(
        conn,"sessions","tenant_id=? AND revoked_at IS NOT NULL AND revoked_at<?",(tenant_id,cutoff_epoch)
    )
    conn.commit(); conn.close()

    return {
        **preview,
        "deleted":deleted,
        "deleted_total":sum(deleted.values()),
        "applied":True,
    }
