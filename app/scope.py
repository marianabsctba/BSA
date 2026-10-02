from dataclasses import dataclass
from urllib.parse import urlparse
import ipaddress
import unicodedata


@dataclass(frozen=True)
class Scope:
    domains: tuple[str, ...]

    def allows_hostname(self, hostname: str) -> bool:
        candidate = hostname.rstrip(".").lower()
        for root in self.domains:
            root = root.rstrip(".").lower()
            if candidate == root or candidate.endswith("." + root):
                return True
        return False

    def allows_url(self, url: str) -> bool:
        host = urlparse(url).hostname
        return bool(host and self.allows_hostname(host))

import fnmatch
import os
import secrets
import time
from .auth import _db, Principal

def ensure_scope_schema():
    conn=_db()
    conn.execute("""CREATE TABLE IF NOT EXISTS scopes(
        id TEXT PRIMARY KEY, tenant_id TEXT NOT NULL, name TEXT NOT NULL,
        pattern TEXT NOT NULL, active INTEGER NOT NULL DEFAULT 1, created_at INTEGER NOT NULL)""")
    cols={r["name"] for r in conn.execute("PRAGMA table_info(user_scopes)").fetchall()}
    if cols and "scope_id" not in cols:
        legacy="user_scopes_legacy_"+str(int(time.time()))
        conn.execute(f"ALTER TABLE user_scopes RENAME TO {legacy}")
    conn.execute("""CREATE TABLE IF NOT EXISTS user_scopes(
        user_id TEXT NOT NULL, scope_id TEXT NOT NULL, PRIMARY KEY(user_id,scope_id))""")
    conn.execute("""CREATE TABLE IF NOT EXISTS asset_groups(
        id TEXT PRIMARY KEY, tenant_id TEXT NOT NULL, name TEXT NOT NULL,
        pattern TEXT NOT NULL, created_at INTEGER NOT NULL)""")
    conn.execute("""CREATE TABLE IF NOT EXISTS scan_scopes(
        id TEXT PRIMARY KEY, tenant_id TEXT NOT NULL, name TEXT NOT NULL,
        pattern TEXT NOT NULL, active INTEGER NOT NULL DEFAULT 1, created_at INTEGER NOT NULL)""")
    conn.execute("""CREATE TABLE IF NOT EXISTS user_scan_scopes(
        user_id TEXT NOT NULL, scope_id TEXT NOT NULL, PRIMARY KEY(user_id,scope_id))""")
    conn.commit(); conn.close()

def bootstrap_scope(tenant_id="tenant-demo"):
    ensure_scope_schema()
    conn=_db()
    row=conn.execute("SELECT id FROM scopes WHERE tenant_id=? LIMIT 1",(tenant_id,)).fetchone()
    if not row and os.getenv("BSA_ENV","development").lower() not in {"production","prod"}:
        sid=secrets.token_hex(10)
        conn.execute("INSERT INTO scopes(id,tenant_id,name,pattern,created_at) VALUES(?,?,?,?,?)",
                     (sid,tenant_id,"Tenant Full Scope","*",int(time.time())))
        users=conn.execute("SELECT id FROM users WHERE tenant_id=?",(tenant_id,)).fetchall()
        conn.executemany("INSERT OR IGNORE INTO user_scopes(user_id,scope_id) VALUES(?,?)",[(u["id"],sid) for u in users])
        conn.commit()
    conn.close()

def create_scope(principal: Principal,name:str,pattern:str):
    if not __import__("app.auth",fromlist=["can"]).can(principal,"users:write"): raise PermissionError("users:write required")
    ensure_scope_schema(); conn=_db(); sid=secrets.token_hex(10)
    conn.execute("INSERT INTO scopes(id,tenant_id,name,pattern,created_at) VALUES(?,?,?,?,?)",(sid,principal.tenant_id,name,pattern,int(time.time())))
    conn.commit(); conn.close()
    return {"id":sid,"tenant_id":principal.tenant_id,"name":name,"pattern":pattern,"active":True}

def list_scopes(principal: Principal):
    ensure_scope_schema(); conn=_db()
    rows=conn.execute("SELECT id,name,pattern,active,created_at FROM scopes WHERE tenant_id=? ORDER BY name",(principal.tenant_id,)).fetchall()
    conn.close(); return [dict(r) for r in rows]

def assign_scope(principal: Principal,user_id:str,scope_id:str):
    if not __import__("app.auth",fromlist=["can"]).can(principal,"users:write"): raise PermissionError("users:write required")
    ensure_scope_schema(); conn=_db()
    user=conn.execute("SELECT id,tenant_id FROM users WHERE id=?",(user_id,)).fetchone()
    scope=conn.execute("SELECT id,tenant_id FROM scopes WHERE id=?",(scope_id,)).fetchone()
    if not user or not scope or user["tenant_id"]!=principal.tenant_id or scope["tenant_id"]!=principal.tenant_id:
        conn.close(); raise ValueError("user or scope outside tenant")
    conn.execute("INSERT OR IGNORE INTO user_scopes(user_id,scope_id) VALUES(?,?)",(user_id,scope_id))
    conn.commit(); conn.close()

def scoped_patterns(principal: Principal):
    ensure_scope_schema(); conn=_db()
    rows=conn.execute("""SELECT s.pattern FROM scopes s JOIN user_scopes us ON us.scope_id=s.id
        WHERE us.user_id=? AND s.tenant_id=? AND s.active=1""",(principal.user_id,principal.tenant_id)).fetchall()
    conn.close(); return {r["pattern"] for r in rows}

def _normalize_scope_hostname(value: str) -> str:
    raw=str(value or "").strip()
    if not raw or any(ch in raw for ch in "/?#@"):
        raise ValueError("target must be a hostname")
    candidate=raw.rstrip(".").lower()
    try:
        ipaddress.ip_address(candidate)
        return candidate
    except ValueError:
        pass
    try:
        candidate=candidate.encode("idna").decode("ascii")
    except UnicodeError as exc:
        raise ValueError("invalid hostname") from exc
    labels=candidate.split(".")
    if any(not label or len(label)>63 or label.startswith("-") or label.endswith("-") for label in labels):
        raise ValueError("invalid hostname")
    return candidate

def _scope_pattern_matches(hostname: str, pattern: str) -> bool:
    try:
        normalized=_normalize_scope_hostname(hostname)
    except ValueError:
        return False
    pattern=pattern.strip().rstrip(".").lower()
    if pattern=="*":
        return True
    if pattern.startswith("*."):
        pattern=pattern[2:]
    try:
        pattern=_normalize_scope_hostname(pattern)
    except ValueError:
        return False
    return normalized==pattern or normalized.endswith("." + pattern)

def _scope_hostname_from_value(value: str) -> str:
    raw=str(value or "").strip()
    if not raw:
        raise ValueError("empty target")
    if "://" in raw:
        host=urlparse(raw).hostname
        if not host:
            raise ValueError("invalid URL target")
        return _normalize_scope_hostname(host)
    if raw.count(":")==1 and "/" not in raw:
        host,port=raw.rsplit(":",1)
        if port.isdigit():
            return _normalize_scope_hostname(host)
    return _normalize_scope_hostname(raw)

def asset_in_scope(principal: Principal,value:str):
    try:
        hostname=_scope_hostname_from_value(value)
    except ValueError:
        return False
    patterns=scoped_patterns(principal)
    if patterns:
        return any(_scope_pattern_matches(hostname,p) for p in patterns)
    if os.getenv("BSA_ENV","development").lower() not in {"production","prod"} and principal.role=="superadmin":
        return True
    return False


def create_scan_scope(principal: Principal,name:str,pattern:str):
    if not __import__("app.auth",fromlist=["can"]).can(principal,"users:write"):
        raise PermissionError("users:write required")
    ensure_scope_schema(); conn=_db(); sid=secrets.token_hex(10)
    conn.execute(
        "INSERT INTO scan_scopes(id,tenant_id,name,pattern,created_at) VALUES(?,?,?,?,?)",
        (sid,principal.tenant_id,name,pattern,int(time.time())),
    )
    conn.commit(); conn.close()
    return {"id":sid,"tenant_id":principal.tenant_id,"name":name,"pattern":pattern,"active":True}

def list_scan_scopes(principal: Principal):
    ensure_scope_schema(); conn=_db()
    rows=conn.execute(
        "SELECT id,name,pattern,active,created_at FROM scan_scopes WHERE tenant_id=? ORDER BY name",
        (principal.tenant_id,),
    ).fetchall()
    conn.close(); return [dict(r) for r in rows]

def assign_scan_scope(principal: Principal,user_id:str,scope_id:str):
    if not __import__("app.auth",fromlist=["can"]).can(principal,"users:write"):
        raise PermissionError("users:write required")
    ensure_scope_schema(); conn=_db()
    user=conn.execute("SELECT id,tenant_id FROM users WHERE id=?",(user_id,)).fetchone()
    scope=conn.execute("SELECT id,tenant_id FROM scan_scopes WHERE id=?",(scope_id,)).fetchone()
    if not user or not scope or user["tenant_id"]!=principal.tenant_id or scope["tenant_id"]!=principal.tenant_id:
        conn.close(); raise ValueError("user or scan scope outside tenant")
    conn.execute("INSERT OR IGNORE INTO user_scan_scopes(user_id,scope_id) VALUES(?,?)",(user_id,scope_id))
    conn.commit(); conn.close()

def list_user_scan_scopes(principal: Principal,user_id:str):
    if not (principal.role in {"superadmin","admin"} or user_id==principal.user_id):
        raise PermissionError("scan scope read denied")
    ensure_scope_schema(); conn=_db()
    rows=conn.execute("""SELECT s.id,s.name,s.pattern,s.active,s.created_at
        FROM scan_scopes s JOIN user_scan_scopes us ON us.scope_id=s.id
        JOIN users u ON u.id=us.user_id
        WHERE us.user_id=? AND u.tenant_id=? AND s.tenant_id=? ORDER BY s.name""",
        (user_id,principal.tenant_id,principal.tenant_id)).fetchall()
    conn.close(); return [dict(r) for r in rows]

def scan_scoped_patterns(principal: Principal):
    ensure_scope_schema(); conn=_db()
    rows=conn.execute("""SELECT s.pattern FROM scan_scopes s
        JOIN user_scan_scopes us ON us.scope_id=s.id
        WHERE us.user_id=? AND s.tenant_id=? AND s.active=1""",
        (principal.user_id,principal.tenant_id)).fetchall()
    conn.close(); return {r["pattern"] for r in rows}

def active_scan_in_scope(principal: Principal,value:str):
    try:
        hostname=_scope_hostname_from_value(value)
    except ValueError:
        return False
    patterns=scan_scoped_patterns(principal)
    if patterns:
        return any(_scope_pattern_matches(hostname,p) for p in patterns)
    if os.getenv("BSA_ENV","development").lower() not in {"production","prod"}:
        return asset_in_scope(principal,value)
    return False

def assign_scan_scope_to_user(principal: Principal,user_id:str,scope_id:str):
    assign_scan_scope(principal,user_id,scope_id)
    return {"user_id":user_id,"scope_id":scope_id,"active":True,"kind":"active_scan"}

def create_group(principal: Principal,name:str,pattern:str):
    if principal.role not in {"admin","superadmin"}: raise PermissionError("admin required")
    ensure_scope_schema(); conn=_db(); gid=secrets.token_hex(10)
    conn.execute("INSERT INTO asset_groups(id,tenant_id,name,pattern,created_at) VALUES(?,?,?,?,?)",(gid,principal.tenant_id,name,pattern,int(time.time())))
    conn.commit(); conn.close()
    return {"id":gid,"tenant_id":principal.tenant_id,"name":name,"pattern":pattern}

def list_groups(principal: Principal):
    ensure_scope_schema(); conn=_db()
    rows=conn.execute("SELECT id,name,pattern,created_at FROM asset_groups WHERE tenant_id=? ORDER BY name",(principal.tenant_id,)).fetchall()
    conn.close(); return [dict(r) for r in rows]

def list_user_scopes(principal: Principal, user_id: str):
    if not (principal.role in {"superadmin","admin"} or user_id == principal.user_id):
        raise PermissionError("scope read denied")
    ensure_scope_schema(); conn=_db()
    rows=conn.execute("""SELECT s.id,s.name,s.pattern,s.active,s.created_at
        FROM scopes s JOIN user_scopes us ON us.scope_id=s.id
        JOIN users u ON u.id=us.user_id
        WHERE us.user_id=? AND u.tenant_id=? AND s.tenant_id=? ORDER BY s.name""",
        (user_id,principal.tenant_id,principal.tenant_id)).fetchall()
    conn.close(); return [dict(r) for r in rows]

def assign_scope_to_user(principal: Principal, user_id: str, scope_id: str):
    if principal.role not in {"superadmin","admin"}: raise PermissionError("users:write required")
    assign_scope(principal,user_id,scope_id)
    return {"user_id":user_id,"scope_id":scope_id,"active":True}
