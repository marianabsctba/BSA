import base64
import hashlib
import hmac
import json
import os
import secrets
import sqlite3
import time
import struct
import urllib.parse
from dataclasses import dataclass
from pathlib import Path
from cryptography.fernet import Fernet, InvalidToken

ENVIRONMENT = os.getenv("BSA_ENV", "development").lower()
DB_PATH = os.getenv("BSA_AUTH_DB", "/data/bsa_auth.db" if ENVIRONMENT in {"production","prod"} else str(Path("/tmp") / "bsa_auth.db"))
JWT_SECRET = os.getenv("BSA_JWT_SECRET", "")
MFA_SECRET_KEY = os.getenv("BSA_MFA_KEY", "")
MFA_KEY = MFA_SECRET_KEY
MIN_PASSWORD_LENGTH = int(os.getenv("BSA_MIN_PASSWORD_LENGTH", "14" if ENVIRONMENT in {"production","prod"} else "12"))
TOKEN_TTL = int(os.getenv("BSA_TOKEN_TTL", "28800"))
SESSION_IDLE_TIMEOUT = int(os.getenv("BSA_SESSION_IDLE_TIMEOUT", "1800"))

def _mfa_key_material() -> str:
    material=MFA_KEY or MFA_SECRET_KEY or (JWT_SECRET if ENVIRONMENT not in {"production","prod"} else "")
    if not material:
        raise RuntimeError("BSA_MFA_KEY is required for MFA secret encryption in production")
    return material

def _mfa_cipher() -> Fernet:
    key=base64.urlsafe_b64encode(hashlib.sha256((_mfa_key_material() + ":mfa").encode()).digest())
    return Fernet(key)

def _encrypt_mfa_secret(secret: str) -> str:
    return "fernet:" + _mfa_cipher().encrypt(secret.encode()).decode()

def _decrypt_mfa_secret(value: str) -> str:
    if value.startswith("fernet:"):
        try:
            return _mfa_cipher().decrypt(value[7:].encode()).decode()
        except InvalidToken as exc:
            raise ValueError("invalid encrypted MFA secret") from exc
    return value


ROLES = {"superadmin", "admin", "manager", "analyst", "viewer"}
CUSTOM_ROLE_PREFIX = "custom:"
PERMISSION_CATALOG = ["assets:read","assets:write","findings:read","findings:write","discovery:run","remediation:write","users:read","users:write","audit:read","tenant:manage"]
PERMISSIONS = {
    "superadmin": {"*"},
    "admin": {"assets:read","assets:write","findings:read","findings:write","discovery:run","remediation:write","users:read","users:write","audit:read"},
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
    configured_mfa_key=MFA_KEY or MFA_SECRET_KEY
    if ENVIRONMENT in {"production","prod"} and (not configured_mfa_key or len(configured_mfa_key) < 32):
        raise RuntimeError("BSA_MFA_KEY must be set to a random secret of at least 32 characters in production")


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
        id TEXT PRIMARY KEY, name TEXT NOT NULL, active INTEGER NOT NULL DEFAULT 1,
        locale TEXT NOT NULL DEFAULT 'pt-BR', mfa_required INTEGER NOT NULL DEFAULT 0)""")
    tenant_cols={r["name"] for r in conn.execute("PRAGMA table_info(tenants)").fetchall()}
    if "locale" not in tenant_cols:
        conn.execute("ALTER TABLE tenants ADD COLUMN locale TEXT NOT NULL DEFAULT 'pt-BR'")
    if "mfa_required" not in tenant_cols:
        conn.execute("ALTER TABLE tenants ADD COLUMN mfa_required INTEGER NOT NULL DEFAULT 0")
    conn.execute("""CREATE TABLE IF NOT EXISTS users(
        id TEXT PRIMARY KEY, tenant_id TEXT NOT NULL, email TEXT NOT NULL UNIQUE,
        name TEXT NOT NULL, password_hash TEXT NOT NULL, role TEXT NOT NULL,
        active INTEGER NOT NULL DEFAULT 1, created_at INTEGER NOT NULL)""")
    conn.execute("""CREATE TABLE IF NOT EXISTS custom_roles(
        name TEXT NOT NULL, tenant_id TEXT NOT NULL, permissions TEXT NOT NULL, created_at INTEGER NOT NULL,
        PRIMARY KEY(tenant_id,name))
    """)
    role_info=conn.execute("PRAGMA table_info(custom_roles)").fetchall()
    role_pk=[r["name"] for r in role_info if r["pk"]]
    if role_pk==["name"]:
        conn.execute("""CREATE TABLE custom_roles_v2(
            name TEXT NOT NULL, tenant_id TEXT NOT NULL, permissions TEXT NOT NULL, created_at INTEGER NOT NULL,
            PRIMARY KEY(tenant_id,name))""")
        conn.execute("""INSERT INTO custom_roles_v2(name,tenant_id,permissions,created_at)
            SELECT name,tenant_id,permissions,created_at FROM custom_roles""")
        conn.execute("DROP TABLE custom_roles")
        conn.execute("ALTER TABLE custom_roles_v2 RENAME TO custom_roles")
    conn.execute("""CREATE TABLE IF NOT EXISTS users_mfa(
        user_id TEXT PRIMARY KEY, secret TEXT NOT NULL, enabled INTEGER NOT NULL DEFAULT 0,
        created_at INTEGER NOT NULL, last_counter INTEGER)
    """)
    mfa_cols={r["name"] for r in conn.execute("PRAGMA table_info(users_mfa)").fetchall()}
    if "last_counter" not in mfa_cols:
        conn.execute("ALTER TABLE users_mfa ADD COLUMN last_counter INTEGER")
    conn.execute("""CREATE TABLE IF NOT EXISTS mfa_recovery_codes(
        user_id TEXT NOT NULL,
        code_hash TEXT NOT NULL,
        created_at INTEGER NOT NULL,
        used_at INTEGER,
        PRIMARY KEY(user_id,code_hash)
    )""")
    conn.execute("""CREATE TABLE IF NOT EXISTS sessions(
        jti TEXT PRIMARY KEY, user_id TEXT NOT NULL, tenant_id TEXT NOT NULL,
        created_at INTEGER NOT NULL, expires_at INTEGER NOT NULL,
        last_seen_at INTEGER,
        revoked_at INTEGER)""")
    session_cols={r["name"] for r in conn.execute("PRAGMA table_info(sessions)").fetchall()}
    if "last_seen_at" not in session_cols:
        conn.execute("ALTER TABLE sessions ADD COLUMN last_seen_at INTEGER")
        conn.execute("UPDATE sessions SET last_seen_at=created_at WHERE last_seen_at IS NULL")
    conn.execute("""CREATE TABLE IF NOT EXISTS auth_rate_limits(
        bucket TEXT NOT NULL,
        identity TEXT NOT NULL,
        count INTEGER NOT NULL DEFAULT 0,
        window_started_at INTEGER NOT NULL,
        blocked_until INTEGER NOT NULL DEFAULT 0,
        PRIMARY KEY(bucket,identity)
    )""")
    conn.execute("""CREATE TABLE IF NOT EXISTS mfa_recovery_codes(
        user_id TEXT NOT NULL,
        code_hash TEXT NOT NULL,
        created_at INTEGER NOT NULL,
        used_at INTEGER,
        PRIMARY KEY(user_id,code_hash)
    )""")
    conn.execute("""CREATE TABLE IF NOT EXISTS tenant_security_policy(
        tenant_id TEXT PRIMARY KEY,
        mfa_required_roles TEXT NOT NULL DEFAULT '[]',
        updated_at INTEGER NOT NULL
    )""")
    conn.execute("""CREATE TABLE IF NOT EXISTS audit_log(
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        tenant_id TEXT NOT NULL,
        user_id TEXT NOT NULL,
        action TEXT NOT NULL,
        resource TEXT NOT NULL,
        resource_id TEXT,
        metadata TEXT,
        created_at INTEGER NOT NULL,
        prev_hash TEXT,
        entry_hash TEXT
    )""")
    audit_cols={r["name"] for r in conn.execute("PRAGMA table_info(audit_log)").fetchall()}
    if "prev_hash" not in audit_cols:
        conn.execute("ALTER TABLE audit_log ADD COLUMN prev_hash TEXT")
    if "entry_hash" not in audit_cols:
        conn.execute("ALTER TABLE audit_log ADD COLUMN entry_hash TEXT")
    _backfill_audit_chain(conn)
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

_DUMMY_PASSWORD_HASH = _hash("bsa-auth-dummy-password", b"\0"*16)

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

def _totp(secret: str, counter: int) -> str:
    key=base64.b32decode(secret.upper()+"="*((8-len(secret)%8)%8))
    msg=struct.pack(">Q",counter)
    digest=hmac.new(key,msg,hashlib.sha1).digest()
    offset=digest[-1]&15
    code=(struct.unpack(">I",digest[offset:offset+4])[0]&0x7fffffff)%1000000
    return f"{code:06d}"

def generate_mfa_secret() -> str:
    return base64.b32encode(secrets.token_bytes(20)).decode().rstrip("=")

def verify_totp_counter(secret: str, code: str, window: int=1) -> int | None:
    if not code or not code.isdigit() or len(code)!=6:
        return None
    counter=int(time.time())//30
    for candidate in range(counter-window,counter+window+1):
        if hmac.compare_digest(_totp(secret,candidate),code):
            return candidate
    return None

def verify_totp(secret: str, code: str, window: int=1) -> bool:
    return verify_totp_counter(secret,code,window) is not None

def mfa_status(principal: Principal) -> dict:
    conn=_db()
    row=conn.execute("SELECT enabled FROM users_mfa WHERE user_id=?",(principal.user_id,)).fetchone()
    conn.close()
    return {"enabled":bool(row and row["enabled"])}

def mfa_enroll(principal: Principal, current_password: str, current_mfa_code: str | None = None) -> dict:
    conn=_db()
    user=conn.execute(
        "SELECT password_hash FROM users WHERE id=? AND tenant_id=? AND active=1",
        (principal.user_id,principal.tenant_id),
    ).fetchone()
    existing=conn.execute(
        "SELECT enabled FROM users_mfa WHERE user_id=?",
        (principal.user_id,),
    ).fetchone()
    conn.close()
    if not user:
        raise ValueError("user not found")
    if not _verify(current_password,user["password_hash"]):
        raise PermissionError("current password verification failed")
    if existing and existing["enabled"]:
        if not current_mfa_code or not verify_user_mfa_once(principal.user_id,current_mfa_code):
            raise PermissionError("current MFA verification failed")

    secret=generate_mfa_secret()
    now=int(time.time())
    conn=_db()
    conn.execute(
        """INSERT INTO users_mfa(user_id,secret,enabled,created_at,last_counter)
           VALUES(?,?,0,?,NULL)
           ON CONFLICT(user_id) DO UPDATE SET
             secret=excluded.secret,enabled=0,created_at=excluded.created_at,last_counter=NULL""",
        (principal.user_id,_encrypt_mfa_secret(secret),now),
    )
    conn.execute("DELETE FROM mfa_recovery_codes WHERE user_id=?",(principal.user_id,))
    conn.commit(); conn.close()

    label=urllib.parse.quote(f"Be Safe ASM:{principal.email}")
    uri=f"otpauth://totp/{label}?secret={secret}&issuer=Be%20Safe%20ASM"
    return {"secret":secret,"otpauth_uri":uri}

def mfa_enable(principal: Principal, code: str) -> bool:
    conn=_db()
    row=conn.execute(
        "SELECT secret,last_counter FROM users_mfa WHERE user_id=?",
        (principal.user_id,),
    ).fetchone()
    if not row:
        conn.close()
        raise ValueError("MFA enrollment required")
    counter=verify_totp_counter(_decrypt_mfa_secret(row["secret"]),code)
    if counter is None or (row["last_counter"] is not None and counter<=int(row["last_counter"])):
        conn.close()
        return False
    conn.execute(
        "UPDATE users_mfa SET enabled=1,last_counter=? WHERE user_id=?",
        (counter,principal.user_id),
    )
    conn.commit(); conn.close()
    return True

def mfa_secret_for_user(user_id: str) -> str | None:
    conn=_db()
    row=conn.execute(
        "SELECT secret FROM users_mfa WHERE user_id=? AND enabled=1",
        (user_id,),
    ).fetchone()
    conn.close()
    if not row:
        return None
    secret=_decrypt_mfa_secret(row["secret"])
    if not str(row["secret"]).startswith("fernet:"):
        conn=_db()
        conn.execute(
            "UPDATE users_mfa SET secret=? WHERE user_id=?",
            (_encrypt_mfa_secret(secret),user_id),
        )
        conn.commit(); conn.close()
    return secret

def verify_user_mfa_once(user_id: str, code: str) -> bool:
    conn=_db()
    row=conn.execute(
        "SELECT secret,last_counter FROM users_mfa WHERE user_id=? AND enabled=1",
        (user_id,),
    ).fetchone()
    if not row:
        conn.close()
        return False
    counter=verify_totp_counter(_decrypt_mfa_secret(row["secret"]),code)
    if counter is None or (row["last_counter"] is not None and counter<=int(row["last_counter"])):
        conn.close()
        return False
    updated=conn.execute(
        """UPDATE users_mfa SET last_counter=?
           WHERE user_id=? AND enabled=1 AND (last_counter IS NULL OR last_counter<?)""",
        (counter,user_id,counter),
    ).rowcount
    conn.commit(); conn.close()
    return bool(updated)

def _recovery_code_hash(code: str) -> str:
    key=hashlib.sha256((_mfa_key_material()+":recovery").encode()).digest()
    return hmac.new(key,str(code or "").strip().encode(),hashlib.sha256).hexdigest()

def issue_mfa_recovery_codes(principal: Principal) -> list[str]:
    conn=_db()
    row=conn.execute(
        "SELECT enabled FROM users_mfa WHERE user_id=?",
        (principal.user_id,),
    ).fetchone()
    if not row or not row["enabled"]:
        conn.close()
        raise ValueError("MFA must be enabled before recovery codes are issued")
    codes=[secrets.token_urlsafe(9) for _ in range(10)]
    now=int(time.time())
    conn.execute("DELETE FROM mfa_recovery_codes WHERE user_id=?",(principal.user_id,))
    conn.executemany(
        "INSERT INTO mfa_recovery_codes(user_id,code_hash,created_at,used_at) VALUES(?,?,?,NULL)",
        [(principal.user_id,_recovery_code_hash(code),now) for code in codes],
    )
    conn.commit(); conn.close()
    return codes

def generate_mfa_recovery_codes(principal: Principal, current_password: str, current_mfa_code: str) -> list[str]:
    conn=_db()
    user=conn.execute(
        "SELECT password_hash FROM users WHERE id=? AND tenant_id=? AND active=1",
        (principal.user_id,principal.tenant_id),
    ).fetchone()
    conn.close()
    if not user or not _verify(current_password,user["password_hash"]):
        raise PermissionError("current password verification failed")
    if not verify_user_mfa_once(principal.user_id,current_mfa_code):
        raise PermissionError("current MFA verification failed")
    return issue_mfa_recovery_codes(principal)

def verify_mfa_recovery_code(user_id: str, code: str) -> bool:
    code_hash=_recovery_code_hash(code)
    now=int(time.time())
    conn=_db()
    updated=conn.execute(
        """UPDATE mfa_recovery_codes SET used_at=?
           WHERE user_id=? AND code_hash=? AND used_at IS NULL""",
        (now,user_id,code_hash),
    ).rowcount
    conn.commit(); conn.close()
    return bool(updated)

def mfa_disable(principal: Principal, current_password: str, verification_code: str) -> bool:
    conn=_db()
    user=conn.execute(
        "SELECT password_hash FROM users WHERE id=? AND tenant_id=? AND active=1",
        (principal.user_id,principal.tenant_id),
    ).fetchone()
    enabled=conn.execute(
        "SELECT enabled FROM users_mfa WHERE user_id=?",
        (principal.user_id,),
    ).fetchone()
    conn.close()
    if not user:
        raise ValueError("user not found")
    if not _verify(current_password,user["password_hash"]):
        raise PermissionError("current password verification failed")
    if not enabled or not enabled["enabled"]:
        return True

    verified=False
    if verification_code.isdigit() and len(verification_code)==6:
        verified=verify_user_mfa_once(principal.user_id,verification_code)
    if not verified:
        verified=verify_mfa_recovery_code(principal.user_id,verification_code)
    if not verified:
        raise PermissionError("current MFA verification failed")

    now=int(time.time())
    conn=_db()
    conn.execute(
        "UPDATE users_mfa SET enabled=0,last_counter=NULL WHERE user_id=?",
        (principal.user_id,),
    )
    conn.execute("DELETE FROM mfa_recovery_codes WHERE user_id=?",(principal.user_id,))
    conn.execute(
        "UPDATE sessions SET revoked_at=? WHERE user_id=? AND tenant_id=? AND revoked_at IS NULL",
        (now,principal.user_id,principal.tenant_id),
    )
    conn.commit(); conn.close()
    return True

def tenant_mfa_policy(tenant_id: str) -> dict:
    conn=_db()
    row=conn.execute(
        "SELECT mfa_required_roles,updated_at FROM tenant_security_policy WHERE tenant_id=?",
        (tenant_id,),
    ).fetchone()
    conn.close()
    roles=json.loads(row["mfa_required_roles"]) if row else []
    return {
        "tenant_id":tenant_id,
        "mfa_required_roles":roles,
        "updated_at":row["updated_at"] if row else None,
    }

def set_tenant_mfa_policy(principal: Principal, roles: list[str]) -> dict:
    if principal.role not in {"admin","superadmin"} and not can(principal,"tenant:manage"):
        raise PermissionError("admin required")
    normalized=sorted(set(str(role).strip() for role in roles if str(role).strip()))
    for role in normalized:
        if role not in ROLES and not role.startswith(CUSTOM_ROLE_PREFIX):
            raise ValueError("invalid role in MFA policy")
        if role.startswith(CUSTOM_ROLE_PREFIX):
            role_permissions(role,principal.tenant_id)

    conn=_db()
    if normalized:
        placeholders=",".join("?" for _ in normalized)
        rows=conn.execute(
            f"""SELECT u.id,u.email,u.role FROM users u
                LEFT JOIN users_mfa m ON m.user_id=u.id AND m.enabled=1
                WHERE u.tenant_id=? AND u.active=1
                  AND u.role IN ({placeholders}) AND m.user_id IS NULL""",
            (principal.tenant_id,*normalized),
        ).fetchall()
        if rows:
            conn.close()
            raise ValueError("all active users in required roles must enable MFA before policy enforcement")

    now=int(time.time())
    conn.execute(
        """INSERT INTO tenant_security_policy(tenant_id,mfa_required_roles,updated_at)
           VALUES(?,?,?)
           ON CONFLICT(tenant_id) DO UPDATE SET
             mfa_required_roles=excluded.mfa_required_roles,
             updated_at=excluded.updated_at""",
        (principal.tenant_id,json.dumps(normalized,separators=(",",":")),now),
    )
    conn.commit(); conn.close()
    return {
        "tenant_id":principal.tenant_id,
        "mfa_required_roles":normalized,
        "updated_at":now,
    }

def _tenant_role_requires_mfa(tenant_id: str, role: str) -> bool:
    return role in set(tenant_mfa_policy(tenant_id)["mfa_required_roles"])

def mfa_enabled_for_user(user_id: str) -> bool:
    conn=_db()
    row=conn.execute(
        "SELECT enabled FROM users_mfa WHERE user_id=?",
        (user_id,),
    ).fetchone()
    conn.close()
    return bool(row and row["enabled"])

def rate_limit_action(bucket: str, identity: str, limit: int = 5, window_seconds: int = 300) -> bool:
    now=int(time.time())
    key=str(identity or "unknown").strip().lower()[:512] or "unknown"
    conn=_db()
    row=conn.execute(
        "SELECT count,window_started_at,blocked_until FROM auth_rate_limits WHERE bucket=? AND identity=?",
        (bucket,key),
    ).fetchone()
    if row and int(row["blocked_until"] or 0)>now:
        conn.close()
        return False
    if not row or now-int(row["window_started_at"] or 0)>=window_seconds:
        count=1
        started=now
    else:
        count=int(row["count"] or 0)+1
        started=int(row["window_started_at"])
    blocked_until=now+window_seconds if count>limit else 0
    conn.execute(
        """INSERT INTO auth_rate_limits(bucket,identity,count,window_started_at,blocked_until)
           VALUES(?,?,?,?,?)
           ON CONFLICT(bucket,identity) DO UPDATE SET
             count=excluded.count,window_started_at=excluded.window_started_at,blocked_until=excluded.blocked_until""",
        (bucket,key,count,started,blocked_until),
    )
    conn.commit(); conn.close()
    return blocked_until==0

def _rate_limit_blocked(bucket: str, identity: str) -> bool:
    now=int(time.time())
    key=str(identity or "unknown").strip().lower()[:512] or "unknown"
    conn=_db()
    row=conn.execute(
        "SELECT blocked_until FROM auth_rate_limits WHERE bucket=? AND identity=?",
        (bucket,key),
    ).fetchone()
    conn.close()
    return bool(row and int(row["blocked_until"] or 0)>now)

def _clear_rate_limit(bucket: str, identity: str) -> None:
    conn=_db()
    conn.execute("DELETE FROM auth_rate_limits WHERE bucket=? AND identity=?",(bucket,str(identity or "unknown").strip().lower()[:512] or "unknown"))
    conn.commit(); conn.close()


def authenticate(email: str, password: str, client_ip: str = "", mfa_code: str | None = None) -> str | None:
    key=email.strip().lower()
    ipkey=client_ip.strip() or "unknown"
    account_client=f"{key}:{ipkey}"
    if _rate_limit_blocked("login-account-client",account_client) or _rate_limit_blocked("login-ip",ipkey):
        return None

    conn=_db()
    row=conn.execute("SELECT * FROM users WHERE lower(email)=lower(?) AND active=1",(email,)).fetchone()
    conn.close()

    encoded=row["password_hash"] if row else _DUMMY_PASSWORD_HASH
    password_ok=_verify(password,encoded)
    if not row or not password_ok:
        rate_limit_action("login-account-client",account_client,limit=5,window_seconds=300)
        rate_limit_action("login-ip",ipkey,limit=20,window_seconds=900)
        return None

    # Password is valid: clear primary credential throttles before entering
    # the independent MFA challenge so MFA failures cannot poison the
    # password/IP bucket or prevent the MFA limiter from taking effect.
    _clear_rate_limit("login-account-client",account_client)
    _clear_rate_limit("login-ip",ipkey)

    mfa_secret=mfa_secret_for_user(row["id"])
    if _tenant_role_requires_mfa(row["tenant_id"],row["role"]) and not mfa_secret:
        return None
    if mfa_secret:
        mfa_identity=f"{row['id']}:{ipkey}"
        if _rate_limit_blocked("mfa-login",mfa_identity):
            return None
        supplied=mfa_code or ""
        verified=verify_user_mfa_once(row["id"],supplied) if supplied.isdigit() and len(supplied)==6 else verify_mfa_recovery_code(row["id"],supplied)
        if not verified:
            rate_limit_action("mfa-login",mfa_identity,limit=5,window_seconds=300)
            return None
        _clear_rate_limit("mfa-login",mfa_identity)

    now=int(time.time())
    jti=secrets.token_urlsafe(24)
    exp=now+TOKEN_TTL
    conn=_db()
    conn.execute(
        "INSERT INTO sessions(jti,user_id,tenant_id,created_at,expires_at,last_seen_at) VALUES(?,?,?,?,?,?)",
        (jti,row["id"],row["tenant_id"],now,exp,now),
    )
    conn.commit(); conn.close()
    return _token({"sub":row["id"],"tenant":row["tenant_id"],"email":row["email"],"name":row["name"],"role":row["role"],"iat":now,"exp":exp,"jti":jti})

def principal_from_token(token: str) -> Principal:
    p = _decode(token)
    if (p.get("role") not in ROLES and not p.get("role","").startswith(CUSTOM_ROLE_PREFIX)) or not p.get("jti"):
        raise ValueError("invalid token claims")
    conn = _db()
    session = conn.execute(
        "SELECT revoked_at,expires_at,last_seen_at,created_at FROM sessions WHERE jti=? AND user_id=? AND tenant_id=?",
        (p["jti"],p["sub"],p["tenant"])
    ).fetchone()
    user = conn.execute("SELECT active,role,tenant_id FROM users WHERE id=?", (p["sub"],)).fetchone()
    tenant = conn.execute("SELECT active FROM tenants WHERE id=?", (p["tenant"],)).fetchone()
    conn.close()
    now=int(time.time())
    if not session or session["revoked_at"] is not None or int(session["expires_at"]) < now:
        raise ValueError("session revoked or expired")
    last_seen=int(session["last_seen_at"] or session["created_at"] or 0)
    if SESSION_IDLE_TIMEOUT > 0 and now-last_seen >= SESSION_IDLE_TIMEOUT:
        conn=_db()
        conn.execute("UPDATE sessions SET revoked_at=? WHERE jti=?",(now,p["jti"]))
        conn.commit(); conn.close()
        raise ValueError("session idle timeout exceeded")
    conn=_db()
    conn.execute("UPDATE sessions SET last_seen_at=? WHERE jti=?",(now,p["jti"]))
    conn.commit(); conn.close()
    if not user or not user["active"] or user["tenant_id"] != p["tenant"]:
        raise ValueError("user inactive or tenant mismatch")
    if not tenant or not tenant["active"]:
        raise ValueError("tenant inactive")
    if user["role"] != p["role"]:
        raise ValueError("role changed; re-authentication required")
    return Principal(p["sub"], p["tenant"], p["email"], user["role"], p["name"])

def current_principal_for_user(user_id: str, tenant_id: str) -> Principal:
    conn=_db()
    user=conn.execute(
        "SELECT id,tenant_id,email,name,role,active FROM users WHERE id=? AND tenant_id=?",
        (user_id,tenant_id),
    ).fetchone()
    tenant=conn.execute("SELECT active FROM tenants WHERE id=?",(tenant_id,)).fetchone()
    conn.close()
    if not user or not user["active"]:
        raise ValueError("user inactive or missing")
    if not tenant or not tenant["active"]:
        raise ValueError("tenant inactive or missing")
    role=str(user["role"])
    if role not in ROLES and not role.startswith(CUSTOM_ROLE_PREFIX):
        raise ValueError("invalid current role")
    role_permissions(role,tenant_id)
    return Principal(user["id"],user["tenant_id"],user["email"],role,user["name"])


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
    if role not in ROLES and not role.startswith(CUSTOM_ROLE_PREFIX):
        raise ValueError("invalid role")
    if role.startswith(CUSTOM_ROLE_PREFIX):
        role_permissions(role, principal.tenant_id)
    if role == "superadmin" and principal.role != "superadmin":
        raise PermissionError("superadmin role requires superadmin")
    if role == "admin" and principal.role not in {"admin","superadmin"}:
        raise PermissionError("admin role requires admin")
    if not _can_manage_target(principal, role, principal.tenant_id, allow_equal=True):
        raise PermissionError("cannot grant a role above caller authority")
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

def _role_power(role: str, tenant_id: str) -> tuple[int,set[str]]:
    if role=="superadmin": return (100,set(PERMISSION_CATALOG))
    perms=set(role_permissions(role,tenant_id))
    return (len(perms),perms)

def _can_manage_target(principal: Principal, target_role: str, target_tenant: str, allow_equal: bool = False) -> bool:
    if principal.role=="superadmin":
        return True
    if target_role=="superadmin":
        return False
    principal_power,principal_perms=_role_power(principal.role,principal.tenant_id)
    target_power,target_perms=_role_power(target_role,target_tenant)
    if target_power > principal_power or (target_power == principal_power and not allow_equal):
        return False
    return target_perms.issubset(principal_perms)

def update_user(principal: Principal, user_id: str, name: str, role: str | None = None) -> dict:
    if not can(principal, "users:write"): raise PermissionError("users:write required")
    if role is not None and role not in ROLES and not role.startswith(CUSTOM_ROLE_PREFIX): raise ValueError("invalid role")
    if role and role.startswith(CUSTOM_ROLE_PREFIX): role_permissions(role, principal.tenant_id)
    if role == "superadmin" and principal.role != "superadmin": raise PermissionError("superadmin role requires superadmin")
    if role == "admin" and principal.role not in {"admin","superadmin"}: raise PermissionError("admin role requires admin")
    if role and not _can_manage_target(principal,role,principal.tenant_id,allow_equal=True):
        raise PermissionError("cannot grant a role above caller authority")
    conn=_db()
    row=conn.execute("SELECT id,role,tenant_id FROM users WHERE id=? AND tenant_id=?", (user_id,principal.tenant_id)).fetchone()
    if not row: conn.close(); raise ValueError("user not found")
    if not _can_manage_target(principal,row["role"],row["tenant_id"]): conn.close(); raise PermissionError("target user role is equal or higher than caller")
    if user_id == principal.user_id and role and role != principal.role: conn.close(); raise ValueError("cannot change your own role")
    conn.execute("UPDATE users SET name=?, role=COALESCE(?,role) WHERE id=? AND tenant_id=?", (name,role,user_id,principal.tenant_id))
    conn.commit()
    out=dict(conn.execute("SELECT id,tenant_id,email,name,role,active,created_at FROM users WHERE id=?", (user_id,)).fetchone())
    conn.close()
    return out

def set_user_active(principal: Principal, user_id: str, active: bool) -> dict:
    if principal.role not in {"admin", "superadmin"}: raise PermissionError("admin required")
    conn=_db()
    row=conn.execute("SELECT id,role,tenant_id FROM users WHERE id=? AND tenant_id=?", (user_id,principal.tenant_id)).fetchone()
    if not row: conn.close(); raise ValueError("user not found")
    if not _can_manage_target(principal,row["role"],row["tenant_id"],allow_equal=True): conn.close(); raise PermissionError("target user role is higher than caller")
    if user_id == principal.user_id and not active: conn.close(); raise ValueError("cannot deactivate current user")
    conn.execute("UPDATE users SET active=? WHERE id=? AND tenant_id=?", (1 if active else 0,user_id,principal.tenant_id))
    if not active:
        conn.execute("UPDATE sessions SET revoked_at=? WHERE user_id=? AND tenant_id=? AND revoked_at IS NULL",(int(time.time()),user_id,principal.tenant_id))
    conn.commit()
    out=dict(conn.execute("SELECT id,tenant_id,email,name,role,active,created_at FROM users WHERE id=?", (user_id,)).fetchone())
    conn.close()
    return out

def change_own_password(principal: Principal, current_password: str, new_password: str) -> dict:
    _validate_password(new_password)
    conn=_db()
    row=conn.execute(
        "SELECT password_hash FROM users WHERE id=? AND tenant_id=? AND active=1",
        (principal.user_id,principal.tenant_id),
    ).fetchone()
    if not row:
        conn.close()
        raise ValueError("user not found")
    if not _verify(current_password,row["password_hash"]):
        conn.close()
        raise PermissionError("current password verification failed")
    conn.execute(
        "UPDATE users SET password_hash=? WHERE id=? AND tenant_id=?",
        (_hash(new_password),principal.user_id,principal.tenant_id),
    )
    conn.execute(
        "UPDATE sessions SET revoked_at=? WHERE user_id=? AND tenant_id=? AND revoked_at IS NULL",
        (int(time.time()),principal.user_id,principal.tenant_id),
    )
    conn.commit(); conn.close()
    return {"ok":True,"sessions_revoked":True}

def reset_user_password(principal: Principal, user_id: str, password: str) -> dict:
    if principal.role not in {"admin", "superadmin"}: raise PermissionError("admin required")
    _validate_password(password)
    conn=_db()
    row=conn.execute("SELECT id,role,tenant_id FROM users WHERE id=? AND tenant_id=?", (user_id,principal.tenant_id)).fetchone()
    if not row: conn.close(); raise ValueError("user not found")
    if not _can_manage_target(principal,row["role"],row["tenant_id"]): conn.close(); raise PermissionError("target user role is equal or higher than caller")
    conn.execute("UPDATE users SET password_hash=? WHERE id=? AND tenant_id=?", (_hash(password),user_id,principal.tenant_id))
    conn.execute("UPDATE sessions SET revoked_at=? WHERE user_id=? AND tenant_id=? AND revoked_at IS NULL",(int(time.time()),user_id,principal.tenant_id))
    conn.commit(); conn.close()
    return {"ok":True,"user_id":user_id,"sessions_revoked":True}

def can(principal: Principal, permission: str) -> bool:
    perms = role_permissions(principal.role, principal.tenant_id)
    return "*" in perms or permission in perms

def validate_permissions(permissions: list[str]) -> list[str]:
    normalized=sorted(set(permissions))
    invalid=[p for p in normalized if p not in PERMISSION_CATALOG]
    if invalid: raise ValueError("invalid permission: "+invalid[0])
    return normalized

def role_permissions(role: str, tenant_id: str | None = None) -> list[str]:
    if role in PERMISSIONS:
        return sorted(PERMISSIONS[role])
    if role.startswith(CUSTOM_ROLE_PREFIX):
        if not tenant_id: raise ValueError("tenant required for custom role")
        conn=_db(); row=conn.execute("SELECT permissions FROM custom_roles WHERE name=? AND tenant_id=?",(role,tenant_id)).fetchone(); conn.close()
        if not row: raise ValueError("invalid role")
        return json.loads(row["permissions"])
    raise ValueError("invalid role")


def scope_allowed(principal: Principal, scope_type: str, scope_value: str) -> bool:
    """Compatibility helper backed by the canonical scope subsystem."""
    if principal.role == "superadmin":
        return True
    if scope_type not in {"hostname","domain","target"}:
        return False
    try:
        from .scope import asset_in_scope
        return asset_in_scope(principal, scope_value)
    except Exception:
        return False

def list_custom_roles(principal: Principal) -> list[dict]:
    if not can(principal, "users:read"):
        raise PermissionError("users:read required")
    conn=_db()
    rows=conn.execute("SELECT name,permissions,created_at FROM custom_roles WHERE tenant_id=? ORDER BY name",(principal.tenant_id,)).fetchall()
    conn.close()
    return [{"name":r["name"],"permissions":json.loads(r["permissions"]),"created_at":r["created_at"]} for r in rows]

def create_custom_role(principal: Principal, name: str, permissions: list[str]) -> dict:
    if not can(principal, "users:write"):
        raise PermissionError("users:write required")
    if not name.strip() or len(name)>80: raise ValueError("invalid role name")
    role_name=CUSTOM_ROLE_PREFIX+name.strip().lower().replace(" ","-")
    perms=validate_permissions(permissions)
    caller_perms=set(role_permissions(principal.role, principal.tenant_id))
    if "*" not in caller_perms and not set(perms).issubset(caller_perms):
        raise PermissionError("custom role cannot grant permissions beyond caller scope")
    conn=_db()
    conn.execute("INSERT INTO custom_roles(name,tenant_id,permissions,created_at) VALUES(?,?,?,?)",(role_name,principal.tenant_id,json.dumps(perms),int(time.time())))
    conn.commit(); conn.close()
    return {"name":role_name,"permissions":perms}

SUPPORTED_LOCALES={"pt-BR","en","es"}

def tenant_settings(principal: Principal) -> dict:
    conn=_db()
    row=conn.execute("SELECT id,name,active,locale FROM tenants WHERE id=?",(principal.tenant_id,)).fetchone()
    conn.close()
    if not row: raise ValueError("tenant not found")
    return dict(row)

def update_tenant_locale(principal: Principal, locale: str) -> dict:
    if principal.role not in {"admin","superadmin"} and not can(principal,"tenant:manage"):
        raise PermissionError("admin required")
    if locale not in SUPPORTED_LOCALES:
        raise ValueError("unsupported locale")
    conn=_db()
    conn.execute("UPDATE tenants SET locale=? WHERE id=?",(locale,principal.tenant_id))
    conn.commit()
    row=conn.execute("SELECT id,name,active,locale FROM tenants WHERE id=?",(principal.tenant_id,)).fetchone()
    conn.close()
    return dict(row)

def create_tenant(principal: Principal, tenant_id: str, name: str, locale: str = "pt-BR") -> dict:
    if principal.role != "superadmin":
        raise PermissionError("superadmin required")
    conn = _db()
    if locale not in SUPPORTED_LOCALES: raise ValueError("unsupported locale")
    conn.execute("INSERT INTO tenants(id,name,locale) VALUES(?,?,?)", (tenant_id, name, locale))
    conn.commit()
    conn.close()
    return {"id": tenant_id, "name": name, "active": True, "locale": locale}


def list_tenants(principal: Principal) -> list[dict]:
    if principal.role != "superadmin":
        raise PermissionError("superadmin required")
    conn = _db()
    rows = conn.execute("SELECT id,name,active,locale FROM tenants ORDER BY name").fetchall()
    conn.close()
    return [dict(r) for r in rows]


def _audit_entry_hash(tenant_id: str, user_id: str, action: str, resource: str, resource_id: str | None,
                      metadata_text: str, created_at: int, prev_hash: str) -> str:
    body=json.dumps({
        "tenant_id":tenant_id,
        "user_id":user_id,
        "action":action,
        "resource":resource,
        "resource_id":resource_id,
        "metadata":metadata_text,
        "created_at":int(created_at),
        "prev_hash":prev_hash,
    },sort_keys=True,separators=(",",":"),ensure_ascii=False)
    return hashlib.sha256(body.encode()).hexdigest()

def _backfill_audit_chain(conn) -> None:
    tenants=conn.execute("SELECT DISTINCT tenant_id FROM audit_log ORDER BY tenant_id").fetchall()
    for tenant in tenants:
        tenant_id=tenant["tenant_id"]
        prev=""
        rows=conn.execute(
            "SELECT id,user_id,action,resource,resource_id,metadata,created_at,prev_hash,entry_hash FROM audit_log WHERE tenant_id=? ORDER BY id",
            (tenant_id,),
        ).fetchall()
        for row in rows:
            metadata_text=row["metadata"] or "{}"
            expected=_audit_entry_hash(
                tenant_id,row["user_id"],row["action"],row["resource"],row["resource_id"],
                metadata_text,int(row["created_at"]),prev,
            )
            if not row["entry_hash"]:
                conn.execute(
                    "UPDATE audit_log SET prev_hash=?,entry_hash=? WHERE id=?",
                    (prev,expected,row["id"]),
                )
                current=expected
            else:
                current=row["entry_hash"]
            prev=current

def verify_audit_chain(principal: Principal) -> dict:
    if not can(principal,"audit:read"):
        raise PermissionError("audit:read required")
    conn=_db()
    if principal.role=="superadmin":
        tenant_ids=[r["tenant_id"] for r in conn.execute("SELECT DISTINCT tenant_id FROM audit_log ORDER BY tenant_id").fetchall()]
    else:
        tenant_ids=[principal.tenant_id]
    checked=0
    for tenant_id in tenant_ids:
        prev=""
        rows=conn.execute(
            "SELECT id,user_id,action,resource,resource_id,metadata,created_at,prev_hash,entry_hash FROM audit_log WHERE tenant_id=? ORDER BY id",
            (tenant_id,),
        ).fetchall()
        for row in rows:
            expected=_audit_entry_hash(
                tenant_id,row["user_id"],row["action"],row["resource"],row["resource_id"],
                row["metadata"] or "{}",int(row["created_at"]),prev,
            )
            if (row["prev_hash"] or "")!=prev or not hmac.compare_digest(str(row["entry_hash"] or ""),expected):
                conn.close()
                return {"valid":False,"checked":checked,"tenant_id":tenant_id,"broken_id":row["id"]}
            prev=row["entry_hash"]
            checked+=1
    conn.close()
    return {"valid":True,"checked":checked,"tenant_count":len(tenant_ids)}

def audit(principal: Principal, action: str, resource: str, resource_id: str | None = None, metadata: dict | None = None) -> None:
    conn=_db()
    metadata_text=json.dumps(metadata or {},sort_keys=True,separators=(",",":"),ensure_ascii=False)
    created_at=int(time.time())
    row=conn.execute(
        "SELECT entry_hash FROM audit_log WHERE tenant_id=? ORDER BY id DESC LIMIT 1",
        (principal.tenant_id,),
    ).fetchone()
    prev_hash=str(row["entry_hash"] or "") if row else ""
    entry_hash=_audit_entry_hash(
        principal.tenant_id,principal.user_id,action,resource,resource_id,
        metadata_text,created_at,prev_hash,
    )
    conn.execute(
        """INSERT INTO audit_log(
           tenant_id,user_id,action,resource,resource_id,metadata,created_at,prev_hash,entry_hash
           ) VALUES(?,?,?,?,?,?,?,?,?)""",
        (principal.tenant_id,principal.user_id,action,resource,resource_id,metadata_text,created_at,prev_hash,entry_hash),
    )
    conn.commit(); conn.close()


def list_audit(principal: Principal, limit: int = 100) -> list[dict]:
    if not can(principal, "audit:read"):
        raise PermissionError("audit:read required")
    conn = _db()
    if principal.role == "superadmin":
        rows = conn.execute("SELECT * FROM audit_log ORDER BY id DESC LIMIT ?", (min(limit, 500),)).fetchall()
    else:
        rows = conn.execute("SELECT * FROM audit_log WHERE tenant_id=? ORDER BY id DESC LIMIT ?", (principal.tenant_id, min(limit, 500))).fetchall()
    conn.close()
    return [dict(r) for r in rows]
