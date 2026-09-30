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
JWT_SECRET = os.getenv("BSA_JWT_SECRET", "CHANGE-ME-IN-PRODUCTION")
TOKEN_TTL = int(os.getenv("BSA_TOKEN_TTL", "28800"))

ROLES = {"superadmin", "admin", "manager", "analyst", "viewer"}
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

def _db():
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    conn.execute("""CREATE TABLE IF NOT EXISTS tenants(
        id TEXT PRIMARY KEY, name TEXT NOT NULL, active INTEGER NOT NULL DEFAULT 1)""")
    conn.execute("""CREATE TABLE IF NOT EXISTS users(
        id TEXT PRIMARY KEY, tenant_id TEXT NOT NULL, email TEXT NOT NULL UNIQUE,
        name TEXT NOT NULL, password_hash TEXT NOT NULL, role TEXT NOT NULL,
        active INTEGER NOT NULL DEFAULT 1, created_at INTEGER NOT NULL)""")
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
    conn = _db()
    conn.execute("INSERT OR IGNORE INTO tenants(id,name) VALUES(?,?)", ("tenant-demo", "Be Safe Demo"))
    email = os.getenv("BSA_ADMIN_EMAIL", "admin@besafe.local").lower()
    password = os.getenv("BSA_ADMIN_PASSWORD", "ChangeMe!123")
    exists = conn.execute("SELECT id FROM users WHERE email=?", (email,)).fetchone()
    if not exists:
        conn.execute(
            "INSERT INTO users(id,tenant_id,email,name,password_hash,role,created_at) VALUES(?,?,?,?,?,?,?)",
            (secrets.token_hex(12), "tenant-demo", email, "BSA Administrator", _hash(password), os.getenv("BSA_BOOTSTRAP_ROLE", "superadmin"), int(time.time()))
        )
    conn.commit()
    conn.close()

def authenticate(email: str, password: str) -> str | None:
    conn = _db()
    row = conn.execute("SELECT * FROM users WHERE lower(email)=lower(?) AND active=1", (email,)).fetchone()
    conn.close()
    if not row or not _verify(password, row["password_hash"]):
        return None
    now = int(time.time())
    return _token({"sub": row["id"], "tenant": row["tenant_id"], "email": row["email"], "name": row["name"], "role": row["role"], "iat": now, "exp": now + TOKEN_TTL})

def principal_from_token(token: str) -> Principal:
    p = _decode(token)
    if p.get("role") not in ROLES:
        raise ValueError("invalid role")
    return Principal(p["sub"], p["tenant"], p["email"], p["role"], p["name"])

def create_user(principal: Principal, email: str, name: str, password: str, role: str) -> dict:
    if principal.role not in {"admin", "superadmin"}:
        raise PermissionError("admin required")
    if role not in ROLES:
        raise ValueError("invalid role")
    conn = _db()
    uid = secrets.token_hex(12)
    conn.execute("INSERT INTO users(id,tenant_id,email,name,password_hash,role,created_at) VALUES(?,?,?,?,?,?,?)",
                 (uid, principal.tenant_id, email.lower(), name, _hash(password), role, int(time.time())))
    conn.commit()
    conn.close()
    return {"id": uid, "tenant_id": principal.tenant_id, "email": email.lower(), "name": name, "role": role, "active": True}

def list_users(principal: Principal) -> list[dict]:
    if principal.role != "admin":
        raise PermissionError("admin required")
    conn = _db()
    rows = conn.execute("SELECT id,email,name,role,active,created_at FROM users WHERE tenant_id=? ORDER BY name", (principal.tenant_id,)).fetchall()
    conn.close()
    return [dict(r) for r in rows]

def can(principal: Principal, permission: str) -> bool:
    perms = PERMISSIONS[principal.role]
    return "*" in perms or permission in perms


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
