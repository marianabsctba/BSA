import sqlite3

from . import auth, history, job_queue
from . import digital_risk, ctem_store
from .repositories.assets_findings import asset_finding_repository


def _table_exists(conn: sqlite3.Connection, table: str) -> bool:
    row=conn.execute("SELECT 1 FROM sqlite_master WHERE type='table' AND name=?",(table,)).fetchone()
    return bool(row)


def _count(conn: sqlite3.Connection, table: str, where: str, args: tuple) -> int:
    if not _table_exists(conn,table):
        return 0
    return int(conn.execute(f"SELECT COUNT(*) FROM {table} WHERE {where}",args).fetchone()[0])


def _delete(conn: sqlite3.Connection, table: str, where: str, args: tuple) -> int:
    if not _table_exists(conn,table):
        return 0
    return int(conn.execute(f"DELETE FROM {table} WHERE {where}",args).rowcount)


def retire_tenant(principal, tenant_id: str) -> dict:
    if principal.role!="superadmin":
        raise PermissionError("superadmin required")
    if tenant_id==principal.tenant_id:
        raise ValueError("cannot retire current tenant")
    conn=auth._db()
    tenant=conn.execute("SELECT id,name,active FROM tenants WHERE id=?",(tenant_id,)).fetchone()
    if not tenant:
        conn.close()
        raise ValueError("tenant not found")
    conn.execute("UPDATE tenants SET active=0 WHERE id=?",(tenant_id,))
    conn.execute(
        "UPDATE sessions SET revoked_at=strftime('%s','now') WHERE tenant_id=? AND revoked_at IS NULL",
        (tenant_id,),
    )
    conn.execute("UPDATE users SET active=0 WHERE tenant_id=?",(tenant_id,))
    conn.commit(); conn.close()
    return {"tenant_id":tenant_id,"retired":True}


def tenant_purge_preview(tenant_id: str, preserve_audit: bool=True) -> dict:
    counts={}

    conn=auth._db()
    users=[r["id"] for r in conn.execute("SELECT id FROM users WHERE tenant_id=?",(tenant_id,)).fetchall()]
    counts["users"]=_count(conn,"users","tenant_id=?",(tenant_id,))
    counts["sessions"]=_count(conn,"sessions","tenant_id=?",(tenant_id,))
    counts["custom_roles"]=_count(conn,"custom_roles","tenant_id=?",(tenant_id,))
    counts["scopes"]=_count(conn,"scopes","tenant_id=?",(tenant_id,))
    counts["scan_scopes"]=_count(conn,"scan_scopes","tenant_id=?",(tenant_id,))
    counts["asset_groups"]=_count(conn,"asset_groups","tenant_id=?",(tenant_id,))
    counts["audit_log"]=0 if preserve_audit else _count(conn,"audit_log","tenant_id=?",(tenant_id,))
    counts["users_mfa"]=sum(_count(conn,"users_mfa","user_id=?",(uid,)) for uid in users)
    counts["ctem_plans"]=_count(conn,"ctem_plans","tenant_id=?",(tenant_id,))
    counts["ctem_history"]=_count(conn,"ctem_history","tenant_id=?",(tenant_id,))
    counts["digital_risk"]=_count(conn,"digital_risk","tenant_id=?",(tenant_id,))
    counts["takedowns"]=_count(conn,"takedowns","tenant_id=?",(tenant_id,))
    conn.close()

    conn=history._history_db()
    for table in ("asset_observations","discovery_runs","ctem_items","ctem_verifications","lifecycle_snapshots","ctem_operations"):
        counts[table]=_count(conn,table,"tenant_id=?",(tenant_id,))
    conn.close()

    conn=job_queue._db()
    counts["assessment_jobs"]=_count(conn,"assessment_jobs","tenant_id=?",(tenant_id,))
    conn.close()

    storage_counts=asset_finding_repository().tenant_record_counts(tenant_id)
    counts["assets"]=int(storage_counts.get("assets",0))
    counts["findings"]=int(storage_counts.get("findings",0))

    return {
        "tenant_id":tenant_id,
        "preserve_audit":preserve_audit,
        "counts":counts,
        "total_records":sum(counts.values()),
    }


def purge_tenant(principal, tenant_id: str, preserve_audit: bool=True) -> dict:
    if principal.role!="superadmin":
        raise PermissionError("superadmin required")
    if tenant_id==principal.tenant_id:
        raise ValueError("cannot purge current tenant")

    preview=tenant_purge_preview(tenant_id,preserve_audit=preserve_audit)

    # Validate the tenant before touching any backend, then remove the active
    # asset/finding store first. If PostgreSQL is selected and unavailable,
    # purge fails closed while tenant identity and access metadata still exist.
    conn=auth._db()
    tenant=conn.execute("SELECT id FROM tenants WHERE id=?",(tenant_id,)).fetchone()
    conn.close()
    if not tenant:
        raise ValueError("tenant not found")

    storage_deleted=asset_finding_repository().purge_tenant(tenant_id)

    conn=auth._db()
    users=[r["id"] for r in conn.execute("SELECT id FROM users WHERE tenant_id=?",(tenant_id,)).fetchall()]
    scope_ids=[r["id"] for r in conn.execute("SELECT id FROM scopes WHERE tenant_id=?",(tenant_id,)).fetchall()] if _table_exists(conn,"scopes") else []
    scan_scope_ids=[r["id"] for r in conn.execute("SELECT id FROM scan_scopes WHERE tenant_id=?",(tenant_id,)).fetchall()] if _table_exists(conn,"scan_scopes") else []

    for uid in users:
        _delete(conn,"users_mfa","user_id=?",(uid,))
        _delete(conn,"user_scopes","user_id=?",(uid,))
        _delete(conn,"user_scan_scopes","user_id=?",(uid,))
    for sid in scope_ids:
        _delete(conn,"user_scopes","scope_id=?",(sid,))
    for sid in scan_scope_ids:
        _delete(conn,"user_scan_scopes","scope_id=?",(sid,))

    for table in ("sessions","custom_roles","scopes","scan_scopes","asset_groups","ctem_plans","ctem_history","digital_risk","takedowns"):
        _delete(conn,table,"tenant_id=?",(tenant_id,))
    if not preserve_audit:
        _delete(conn,"audit_log","tenant_id=?",(tenant_id,))
    _delete(conn,"users","tenant_id=?",(tenant_id,))
    conn.execute("DELETE FROM tenants WHERE id=?",(tenant_id,))
    conn.commit(); conn.close()

    conn=history._history_db()
    for table in ("asset_observations","discovery_runs","ctem_items","ctem_verifications","lifecycle_snapshots","ctem_operations"):
        _delete(conn,table,"tenant_id=?",(tenant_id,))
    conn.commit(); conn.close()

    conn=job_queue._db()
    _delete(conn,"assessment_jobs","tenant_id=?",(tenant_id,))
    conn.commit(); conn.close()

    result={**preview,"purged":True}
    result["deleted_asset_records"]={
        "assets":int(storage_deleted.get("assets",0)),
        "findings":int(storage_deleted.get("findings",0)),
    }
    return result
