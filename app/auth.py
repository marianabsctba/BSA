import base64
import hashlib
import hmac
import json
import os
import secrets
import sqlite3
import time
from dataclasses import dataclass
from pathlib import Path

DB_PATH = os.getenv("BSA_AUTH_DB", str(Path("/tmp") / "bsa_auth.db"))
JWT_SECRET = os.getenv("BSA_JWT_SECRET", "")
ENVIRONMENT = os.getenv("BSA_ENV", "development").lower()
MIN_PASSWORD_LENGTH = int(os.getenv("BSA_MIN_PASSWORD_LENGTH", "14" if ENVIRONMENT in {"production","prod"} else "12"))
_LOGIN_ATTEMPTS = {}
TOKEN_TTL = int(os.getenv("BSA_TOKEN_TTL", "28800"))

ROLES = {"superadmin", "admin", "manager", "analyst", "viewer"}
CUSTOM_ROLE_PREFIX = "custom:"
PERMISSION_CATALOG = ["assets:read","assets:write","findings:read","findings:write","discovery:run","remediation:write","users:read","users:write","audit:read","tenant:manage"]
PERMISSIONS = {
    "superadmin": {"*"},
    "admin": {"assets:read","assets:write","findings:read","findings:write","discovery:run","remediation:write","users:read","users:write"},
    "manager": {"assets:read","assets:write","findings:read","findings:write","discovery:run","remediation:write","users:read"},
    "analyst": {"assets:read","findings:read","findings:write","discovery:run","remediation:write"},
    "viewer": {"assets:read","findings:read"},
}

@dataclass(frozen=True)
class Principal:
    user_id: str
    tenant_id: str
    email: str
    role: str
    name: str

def _require_security_config():
    if ENVIRONMENT in {"production","prod"} and (not JWT_SECRET or len(JWT_SECRET) < 32):
        raise RuntimeError("BSA_JWT_SECRET must be set to a random secret of at least 32 characters in production")


def _validate_password(password: str):
    if len(password) < MIN_PASSWORD_LENGTH:
        raise ValueError(f"password must contain at least {MIN_PASSWORD_LENGTH} characters")
    if password.lower() in {"changeme!123","password","password123"}:
        raise ValueError("password is not allowed")


def _db():
    conn = sqlite3.connect(DB_PATH, timeout=15)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA busy_timeout=15000")
    conn.execute("PRAGMA journal_mode=WAL")
    conn.execute("""CREATE TABLE IF NOT EXISTS tenants(
        id TEXT PRIMARY KEY, name TEXT NOT NULL, active INTEGER NOT NULL DEFAULT 1)""")
    conn.execute("""CREATE TABLE IF NOT EXISTS users(
        id TEXT PRIMARY KEY, tenant_id TEXT NOT NULL, email TEXT NOT NULL UNIQUE,
        name TEXT NOT NULL, password_hash TEXT NOT NULL, role TEXT NOT NULL,
        active INTEGER NOT NULL DEFAULT 1, created_at INTEGER NOT NULL)""")
    conn.execute("""CREATE TABLE IF NOT EXISTS custom_roles(
        name TEXT PRIMARY KEY, tenant_id TEXT NOT NULL, permissions TEXT NOT NULL, created_at INTEGER NOT NULL)
    """)
    conn.execute("""CREATE TABLE IF NOT EXISTS sessions(
        jti TEXT PRIMARY KEY, user_id TEXT NOT NULL, tenant_id TEXT NOT NULL,
        created_at INTEGER NOT NULL, expires_at INTEGER NOT NULL,
        revoked_at INTEGER)""")
    conn.commit()
    return conn

def _hash(password: str, salt: bytes | None = None) -> str:
    salt = salt or secrets.token_bytes(16)
    digest = hashlib.pbkdf2_hmac("sha256", password.encode(), salt, 310000)
    return base64.urlsafe_b64encode(salt + digest).decode()

def _verify(password: str, encoded: str) -> bool:
    raw = base64.urlsafe_b64decode(encoded.encode())
    salt, expected = raw[:16], raw[16:]
    actual = hashlib.pbkdf2_hmac("sha256", password.encode(), salt, 310000)
    return hmac.compare_digest(actual, expected)

def _b64(value: bytes) -> str:
    return base64.urlsafe_b64encode(value).rstrip(b"=").decode()

def _token(payload: dict) -> str:
    _require_security_config()
    body = _b64(json.dumps(payload, separators=(",", ":")).encode())
    sig = _b64(hmac.new(JWT_SECRET.encode(), body.encode(), hashlib.sha256).digest())
    return body + "." + sig

def _decode(token: str) -> dict:
    body, sig = token.split(".", 1)
    expected = _b64(hmac.new(JWT_SECRET.encode(), body.encode(), hashlib.sha256).digest())
    if not hmac.compare_digest(sig, expected):
        raise ValueError("invalid token")
    payload = json.loads(base64.urlsafe_b64decode(body + "==="))
    if int(payload.get("exp", 0)) < int(time.time()):
        raise ValueError("expired token")
    return payload

def bootstrap():
    _require_security_config()
    conn = _db()
    conn.execute("INSERT OR IGNORE INTO tenants(id,name) VALUES(?,?)", ("tenant-demo", "Be Safe Demo"))
    email = os.getenv("BSA_ADMIN_EMAIL", "admin@besafe.local").lower()
    password = os.getenv("BSA_ADMIN_PASSWORD", "")
    if not password:
        raise RuntimeError("BSA_ADMIN_PASSWORD must be set before bootstrap creates the administrator")
    _validate_password(password)
    exists = conn.execute("SELECT id FROM users WHERE email=?", (email,)).fetchone()
    if not exists:
        conn.execute(
            "INSERT INTO users(id,tenant_id,email,name,password_hash,role,created_at) VALUES(?,?,?,?,?,?,?)",
            (secrets.token_hex(12), "tenant-demo", email, "BSA Administrator", _hash(password), os.getenv("BSA_BOOTSTRAP_ROLE", "admin"), int(time.time()))
        )
    conn.commit()
    conn.close()

def authenticate(email: str, password: str) -> str | None:
    now=time.time()
    key=email.strip().lower()
    attempts=_LOGIN_ATTEMPTS.get(key, {"count":0,"until":0})
    if attempts["until"] > now: return None
    conn = _db()
    row = conn.execute("SELECT * FROM users WHERE lower(email)=lower(?) AND active=1", (email,)).fetchone()
    conn.close()
    if not row or not _verify(password, row["password_hash"]):
        attempts["count"]+=1
        if attempts["count"]>=5:
            attempts={"count":attempts["count"],"until":now+300}
        _LOGIN_ATTEMPTS[key]=attempts
        return None
    _LOGIN_ATTEMPTS.pop(key,None)
    now = int(time.time())
    jti=secrets.token_urlsafe(24)
    exp=now + TOKEN_TTL
    conn = _db()
    conn.execute("INSERT INTO sessions(jti,user_id,tenant_id,created_at,expires_at) VALUES(?,?,?,?,?)",
                 (jti,row["id"],row["tenant_id"],now,exp))
    conn.commit(); conn.close()
    return _token({"sub": row["id"], "tenant": row["tenant_id"], "email": row["email"], "name": row["name"], "role": row["role"], "iat": now, "exp": exp, "jti": jti})

def principal_from_token(token: str) -> Principal:
    p = _decode(token)
    if p.get("role") not in ROLES or not p.get("jti"):
        raise ValueError("invalid token claims")
    conn = _db()
    session = conn.execute(
        "SELECT revoked_at,expires_at FROM sessions WHERE jti=? AND user_id=? AND tenant_id=?",
        (p["jti"],p["sub"],p["tenant"])
    ).fetchone()
    user = conn.execute("SELECT active,role,tenant_id FROM users WHERE id=?", (p["sub"],)).fetchone()
    tenant = conn.execute("SELECT active FROM tenants WHERE id=?", (p["tenant"],)).fetchone()
    conn.close()
    if not session or session["revoked_at"] is not None or int(session["expires_at"]) < int(time.time()):
        raise ValueError("session revoked or expired")
    if not user or not user["active"] or user["tenant_id"] != p["tenant"]:
        raise ValueError("user inactive or tenant mismatch")
    if not tenant or not tenant["active"]:
        raise ValueError("tenant inactive")
    if user["role"] != p["role"]:
        raise ValueError("role changed; re-authentication required")
    return Principal(p["sub"], p["tenant"], p["email"], user["role"], p["name"])

def revoke_session(principal: Principal, jti: str | None = None) -> None:
    conn = _db()
    if jti:
        conn.execute("UPDATE sessions SET revoked_at=? WHERE jti=? AND user_id=? AND tenant_id=?",
                     (int(time.time()),jti,principal.user_id,principal.tenant_id))
    else:
        conn.execute("UPDATE sessions SET revoked_at=? WHERE user_id=? AND tenant_id=? AND revoked_at IS NULL",
                     (int(time.time()),principal.user_id,principal.tenant_id))
    conn.commit()
    conn.close()

def create_user(principal: Principal, email: str, name: str, password: str, role: str) -> dict:
    if not can(principal, "users:write"):
        raise PermissionError("users:write required")
    if role not in ROLES:
        raise ValueError("invalid role")
    if role == "superadmin" and principal.role != "superadmin":
        raise PermissionError("superadmin role requires superadmin")
    _validate_password(password)
    conn = _db()
    uid = secrets.token_hex(12)
    conn.execute("INSERT INTO users(id,tenant_id,email,name,password_hash,role,created_at) VALUES(?,?,?,?,?,?,?)",
                 (uid, principal.tenant_id, email.lower(), name, _hash(password), role, int(time.time())))
    conn.commit()
    conn.close()
    return {"id": uid, "tenant_id": principal.tenant_id, "email": email.lower(), "name": name, "role": role, "active": True}

def list_users(principal: Principal) -> list[dict]:
    if not can(principal, "users:read"):
        raise PermissionError("users:read required")
    conn = _db()
    rows = conn.execute("SELECT id,email,name,role,active,created_at FROM users WHERE tenant_id=? ORDER BY name", (principal.tenant_id,)).fetchall()
    conn.close()
    return [dict(r) for r in rows]

def update_user(principal: Principal, user_id: str, name: str, role: str | None = None) -> dict:
    if not can(principal, "users:write"): raise PermissionError("users:write required")
    if role is not None and role not in ROLES: raise ValueError("invalid role")
    if role == "superadmin" and principal.role != "superadmin": raise PermissionError("superadmin role requires superadmin")
    conn=_db()
    row=conn.execute("SELECT id FROM users WHERE id=? AND tenant_id=?", (user_id,principal.tenant_id)).fetchone()
    if not row: conn.close(); raise ValueError("user not found")
    if user_id == principal.user_id and role and role != principal.role: conn.close(); raise ValueError("cannot change your own role")
    conn.execute("UPDATE users SET name=?, role=COALESCE(?,role) WHERE id=? AND tenant_id=?", (name,role,user_id,principal.tenant_id))
    conn.commit()
    out=dict(conn.execute("SELECT id,tenant_id,email,name,role,active,created_at FROM users WHERE id=?", (user_id,)).fetchone())
    conn.close()
    return out

def set_user_active(principal: Principal, user_id: str, active: bool) -> dict:
    if principal.role not in {"admin", "superadmin"}: raise PermissionError("admin required")
    conn=_db()
    row=conn.execute("SELECT id FROM users WHERE id=? AND tenant_id=?", (user_id,principal.tenant_id)).fetchone()
    if not row: conn.close(); raise ValueError("user not found")
    if user_id == principal.user_id and not active: conn.close(); raise ValueError("cannot deactivate current user")
    conn.execute("UPDATE users SET active=? WHERE id=? AND tenant_id=?", (1 if active else 0,user_id,principal.tenant_id))
    if not active: conn.execute("UPDATE sessions SET revoked_at=? WHERE user_id=? AND tenant_id=? AND revoked_at IS NULL",(int(time.time()),user_id,principal.tenant_id))
    conn.commit()
    out=dict(conn.execute("SELECT id,tenant_id,email,name,role,active,created_at FROM users WHERE id=?", (user_id,)).fetchone())
    conn.close()
    return out

def reset_user_password(principal: Principal, user_id: str, password: str) -> dict:
    if principal.role not in {"admin", "superadmin"}: raise PermissionError("admin required")
    _validate_password(password)
    conn=_db()
    row=conn.execute("SELECT id FROM users WHERE id=? AND tenant_id=?", (user_id,principal.tenant_id)).fetchone()
    if not row: conn.close(); raise ValueError("user not found")
    conn.execute("UPDATE users SET password_hash=? WHERE id=? AND tenant_id=?", (_hash(password),user_id,principal.tenant_id))
    conn.execute("UPDATE sessions SET revoked_at=? WHERE user_id=? AND tenant_id=? AND revoked_at IS NULL",(int(time.time()),user_id,principal.tenant_id))
    conn.commit(); conn.close()
    return {"ok":True,"user_id":user_id,"sessions_revoked":True}

def can(principal: Principal, permission: str) -> bool:
    perms = PERMISSIONS[principal.role]
    return "*" in perms or permission in perms

def validate_permissions(permissions: list[str]) -> list[str]:
    normalized=sorted(set(permissions))
    invalid=[p for p in normalized if p not in PERMISSION_CATALOG]
    if invalid: raise ValueError("invalid permission: "+invalid[0])
    return normalized

def role_permissions(role: str) -> list[str]:

    if role in PERMISSIONS:
        return sorted(PERMISSIONS[role])
    if role.startswith(CUSTOM_ROLE_PREFIX):
        conn=_db(); row=conn.execute("SELECT permissions FROM custom_roles WHERE name=?",(role,)).fetchone(); conn.close()
        if not row: raise ValueError("invalid role")
        return json.loads(row["permissions"])
    raise ValueError("invalid role")


def create_tenant(principal: Principal, tenant_id: str, name: str) -> dict:
    if principal.role != "superadmin":
        raise PermissionError("superadmin required")
    conn = _db()
    conn.execute("INSERT INTO tenants(id,name) VALUES(?,?)", (tenant_id, name))
    conn.commit()
    conn.close()
    return {"id": tenant_id, "name": name, "active": True}


def list_tenants(principal: Principal) -> list[dict]:
    if principal.role != "superadmin":
        raise PermissionError("superadmin required")
    conn = _db()
    rows = conn.execute("SELECT id,name,active FROM tenants ORDER BY name").fetchall()
    conn.close()
    return [dict(r) for r in rows]


def audit(principal: Principal, action: str, resource: str, resource_id: str | None = None, metadata: dict | None = None) -> None:
    conn = _db()
    conn.execute("""CREATE TABLE IF NOT EXISTS audit_log(
        id INTEGER PRIMARY KEY AUTOINCREMENT, tenant_id TEXT NOT NULL, user_id TEXT NOT NULL,
        action TEXT NOT NULL, resource TEXT NOT NULL, resource_id TEXT, metadata TEXT,
        created_at INTEGER NOT NULL)""")
    conn.execute("INSERT INTO audit_log(tenant_id,user_id,action,resource,resource_id,metadata,created_at) VALUES(?,?,?,?,?,?,?)",
                 (principal.tenant_id, principal.user_id, action, resource, resource_id, json.dumps(metadata or {}, separators=(",", ":")), int(time.time())))
    conn.commit(); conn.close()


def list_audit(principal: Principal, limit: int = 100) -> list[dict]:
    if not can(principal, "users:write"):
        raise PermissionError("users:write required")
    conn = _db()
    if principal.role == "superadmin":
        rows = conn.execute("SELECT * FROM audit_log ORDER BY id DESC LIMIT ?", (min(limit, 500),)).fetchall()
    else:
        rows = conn.execute("SELECT * FROM audit_log WHERE tenant_id=? ORDER BY id DESC LIMIT ?", (principal.tenant_id, min(limit, 500))).fetchall()
    conn.close()
    return [dict(r) for r in rows]
