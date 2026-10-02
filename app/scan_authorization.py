import secrets
import time

from .auth import _db, can, Principal
from .scope import _scope_hostname_from_value, _scope_pattern_matches, validate_active_scope_pattern, ensure_scope_schema


def ensure_authorization_schema():
    conn=_db()
    conn.execute("""CREATE TABLE IF NOT EXISTS active_scan_grants(
        grant_id TEXT PRIMARY KEY,
        tenant_id TEXT NOT NULL,
        user_id TEXT NOT NULL,
        authorization_ref TEXT NOT NULL,
        pattern TEXT NOT NULL,
        created_at INTEGER NOT NULL,
        expires_at INTEGER NOT NULL,
        revoked_at INTEGER,
        created_by TEXT NOT NULL
    )""")
    conn.execute(
        "CREATE UNIQUE INDEX IF NOT EXISTS idx_active_scan_grant_ref ON active_scan_grants(tenant_id,authorization_ref)"
    )
    conn.execute(
        "CREATE INDEX IF NOT EXISTS idx_active_scan_grant_lookup ON active_scan_grants(tenant_id,user_id,expires_at,revoked_at)"
    )
    conn.commit(); conn.close()


def create_authorization_grant(principal: Principal, user_id: str, authorization_ref: str,
                               pattern: str, ttl_seconds: int = 3600) -> dict:
    if principal.role not in {"admin","superadmin"}:
        raise PermissionError("admin required for active scan authorization")
    if user_id==principal.user_id:
        raise PermissionError("grant creator cannot be the beneficiary")
    ref=str(authorization_ref or "").strip()
    if not ref or len(ref)>200:
        raise ValueError("invalid authorization_ref")
    pattern=validate_active_scope_pattern(pattern)
    requested_ttl=int(ttl_seconds)
    if requested_ttl>24*3600 and principal.role!="superadmin":
        raise PermissionError("grants longer than 24 hours require superadmin approval")
    ttl=max(60,min(requested_ttl,30*24*3600))
    ensure_authorization_schema()
    ensure_scope_schema()
    conn=_db()
    user=conn.execute("SELECT id,tenant_id,active,role FROM users WHERE id=?",(user_id,)).fetchone()
    if not user or user["tenant_id"]!=principal.tenant_id or not user["active"]:
        conn.close()
        raise ValueError("user outside tenant or inactive")
    if user["role"] in {"admin","superadmin"} and principal.role!="superadmin":
        conn.close()
        raise PermissionError("authorization grants for administrative users require superadmin approval")
    assigned=conn.execute("""SELECT s.pattern FROM scan_scopes s
        JOIN user_scan_scopes us ON us.scope_id=s.id
        WHERE us.user_id=? AND s.tenant_id=? AND s.active=1""",
        (user_id,principal.tenant_id)).fetchall()
    requested_base=pattern[2:] if pattern.startswith("*.") else pattern
    if not assigned or not any(_scope_pattern_matches(requested_base,row["pattern"]) for row in assigned):
        conn.close()
        raise PermissionError("grant pattern must be within beneficiary active scan scope")
    now=int(time.time())
    grant_id=secrets.token_hex(12)
    conn.execute(
        """INSERT INTO active_scan_grants(
            grant_id,tenant_id,user_id,authorization_ref,pattern,created_at,expires_at,created_by
        ) VALUES(?,?,?,?,?,?,?,?)""",
        (grant_id,principal.tenant_id,user_id,ref,pattern,now,now+ttl,principal.user_id),
    )
    conn.commit(); conn.close()
    return {
        "grant_id":grant_id,"tenant_id":principal.tenant_id,"user_id":user_id,
        "authorization_ref":ref,"pattern":pattern,"created_at":now,"expires_at":now+ttl,
        "revoked":False,
    }


def list_authorization_grants(principal: Principal) -> list[dict]:
    if not can(principal,"users:read"):
        raise PermissionError("users:read required")
    ensure_authorization_schema()
    conn=_db()
    rows=conn.execute(
        """SELECT grant_id,user_id,authorization_ref,pattern,created_at,expires_at,revoked_at,created_by
           FROM active_scan_grants WHERE tenant_id=? ORDER BY created_at DESC""",
        (principal.tenant_id,),
    ).fetchall()
    conn.close()
    return [{**dict(r),"revoked":r["revoked_at"] is not None} for r in rows]


def revoke_authorization_grant(principal: Principal, grant_id: str) -> dict:
    if not can(principal,"users:write"):
        raise PermissionError("users:write required")
    ensure_authorization_schema()
    conn=_db()
    now=int(time.time())
    updated=conn.execute(
        """UPDATE active_scan_grants SET revoked_at=?
           WHERE grant_id=? AND tenant_id=? AND revoked_at IS NULL""",
        (now,grant_id,principal.tenant_id),
    ).rowcount
    row=conn.execute(
        "SELECT grant_id,authorization_ref,user_id,pattern,expires_at,revoked_at FROM active_scan_grants WHERE grant_id=? AND tenant_id=?",
        (grant_id,principal.tenant_id),
    ).fetchone()
    conn.commit(); conn.close()
    if not row:
        raise ValueError("authorization grant not found")
    return {**dict(row),"revoked":row["revoked_at"] is not None,"changed":bool(updated)}


def authorization_grant_valid(principal: Principal, authorization_ref: str, target: str,
                              now: int | None = None) -> bool:
    ref=str(authorization_ref or "").strip()
    if not ref:
        return False
    ensure_authorization_schema()
    now=int(now or time.time())
    conn=_db()
    rows=conn.execute(
        """SELECT pattern FROM active_scan_grants
           WHERE tenant_id=? AND user_id=? AND authorization_ref=?
             AND revoked_at IS NULL AND expires_at>?""",
        (principal.tenant_id,principal.user_id,ref,now),
    ).fetchall()
    conn.close()
    try:
        hostname=_scope_hostname_from_value(target)
    except ValueError:
        return False
    return any(_scope_pattern_matches(hostname,r["pattern"]) for r in rows)
