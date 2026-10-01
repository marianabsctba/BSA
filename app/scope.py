from dataclasses import dataclass
from urllib.parse import urlparse


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
    conn.execute("""CREATE TABLE IF NOT EXISTS user_scopes(
        user_id TEXT NOT NULL, scope_id TEXT NOT NULL, PRIMARY KEY(user_id,scope_id))""")
    conn.execute("""CREATE TABLE IF NOT EXISTS asset_groups(
        id TEXT PRIMARY KEY, tenant_id TEXT NOT NULL, name TEXT NOT NULL,
        pattern TEXT NOT NULL, created_at INTEGER NOT NULL)""")
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
    if principal.role not in {"admin","superadmin"}: raise PermissionError("admin required")
    ensure_scope_schema(); conn=_db(); sid=secrets.token_hex(10)
    conn.execute("INSERT INTO scopes(id,tenant_id,name,pattern,created_at) VALUES(?,?,?,?,?)",(sid,principal.tenant_id,name,pattern,int(time.time())))
    conn.commit(); conn.close()
    return {"id":sid,"tenant_id":principal.tenant_id,"name":name,"pattern":pattern,"active":True}

def list_scopes(principal: Principal):
    ensure_scope_schema(); conn=_db()
    rows=conn.execute("SELECT id,name,pattern,active,created_at FROM scopes WHERE tenant_id=? ORDER BY name",(principal.tenant_id,)).fetchall()
    conn.close(); return [dict(r) for r in rows]

def assign_scope(principal: Principal,user_id:str,scope_id:str):
    if principal.role not in {"admin","superadmin"}: raise PermissionError("admin required")
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

def asset_in_scope(principal: Principal,value:str):
    patterns=scoped_patterns(principal)
    if patterns:
        return any(fnmatch.fnmatch(value.lower(),p.lower()) for p in patterns)
    if os.getenv("BSA_ENV","development").lower() not in {"production","prod"} and principal.role=="superadmin":
        return True
    return False

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
