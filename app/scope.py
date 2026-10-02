from dataclasses import dataclass
from urllib.parse import urlparse
import urllib.request
import urllib.error
import ipaddress
import unicodedata
import tldextract
import dns.resolver


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

_TLD_EXTRACT=tldextract.TLDExtract(suffix_list_urls=())

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
    conn.execute("""CREATE TABLE IF NOT EXISTS domain_ownership_proofs(
        proof_id TEXT PRIMARY KEY,
        tenant_id TEXT NOT NULL,
        domain TEXT NOT NULL,
        method TEXT NOT NULL,
        challenge TEXT NOT NULL,
        created_at INTEGER NOT NULL,
        expires_at INTEGER NOT NULL,
        verified_at INTEGER,
        verified_by TEXT
    )""")
    conn.execute("""CREATE INDEX IF NOT EXISTS idx_domain_ownership_lookup
        ON domain_ownership_proofs(tenant_id,domain,verified_at,expires_at)""")
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

def validate_active_scope_pattern(pattern: str) -> str:
    raw=str(pattern or "").strip().rstrip(".").lower()
    if not raw or raw=="*":
        raise ValueError("active scan scope cannot be global wildcard")
    if "*" in raw and not raw.startswith("*."):
        raise ValueError("wildcard is only allowed as a leading subdomain wildcard")
    base=raw[2:] if raw.startswith("*.") else raw
    normalized=_normalize_scope_hostname(base)
    try:
        ip=ipaddress.ip_address(normalized)
        if not ip.is_global:
            raise ValueError("active scan scope must use a public IP")
        if raw.startswith("*."):
            raise ValueError("wildcard cannot be used with IP address")
        return normalized
    except ValueError as exc:
        if "public IP" in str(exc) or "wildcard cannot" in str(exc):
            raise
    extracted=_TLD_EXTRACT(normalized)
    if not extracted.suffix or not extracted.domain:
        raise ValueError("active scan scope requires a registrable public domain")
    registrable=f"{extracted.domain}.{extracted.suffix}"
    if normalized==extracted.suffix or registrable==extracted.suffix:
        raise ValueError("public suffix cannot be used as active scan scope")
    return ("*." if raw.startswith("*.") else "")+normalized


def _validate_active_pattern(pattern: str) -> str:
    raw=str(pattern or "").strip().rstrip(".").lower()
    if not raw or raw=="*" or ("*" in raw and not raw.startswith("*.")):
        raise ValueError("invalid active scan pattern")
    wildcard=raw.startswith("*.")
    candidate=raw[2:] if wildcard else raw
    normalized=_normalize_scope_hostname(candidate)
    try:
        ip=ipaddress.ip_address(normalized)
        if wildcard or not ip.is_global:
            raise ValueError("active scan IP must be public and exact")
        return normalized
    except ValueError as exc:
        if "active scan IP" in str(exc):
            raise
    extracted=_TLD_EXTRACT(normalized)
    if not extracted.domain or not extracted.suffix:
        raise ValueError("active scan pattern must contain a registrable domain")
    return "*."+normalized if wildcard else normalized


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



def _registrable_domain(pattern: str) -> str | None:
    raw=str(pattern or "").strip().rstrip(".").lower()
    base=raw[2:] if raw.startswith("*.") else raw
    try:
        ipaddress.ip_address(base)
        return None
    except ValueError:
        pass
    normalized=_normalize_scope_hostname(base)
    extracted=_TLD_EXTRACT(normalized)
    if not extracted.domain or not extracted.suffix:
        raise ValueError("domain must be registrable")
    return f"{extracted.domain}.{extracted.suffix}"


def create_domain_ownership_proof(principal: Principal, domain: str, method: str="dns_txt") -> dict:
    if principal.role not in {"admin","superadmin"}:
        raise PermissionError("admin required for domain ownership proof")
    normalized=validate_active_scope_pattern(domain)
    if normalized.startswith("*."):
        normalized=normalized[2:]
    registrable=_registrable_domain(normalized)
    if not registrable:
        raise ValueError("domain ownership proof requires a domain")
    method=str(method or "").strip().lower()
    if method not in {"dns_txt","well_known"}:
        raise ValueError("ownership proof method must be dns_txt or well_known")
    ensure_scope_schema()
    proof_id=secrets.token_hex(12)
    token=secrets.token_urlsafe(24)
    challenge=f"bsa-asm-verification={token}"
    now=int(time.time())
    expires_at=now+24*3600
    conn=_db()
    conn.execute(
        """INSERT INTO domain_ownership_proofs(
           proof_id,tenant_id,domain,method,challenge,created_at,expires_at
           ) VALUES(?,?,?,?,?,?,?)""",
        (proof_id,principal.tenant_id,registrable,method,challenge,now,expires_at),
    )
    conn.commit(); conn.close()
    result={
        "proof_id":proof_id,
        "tenant_id":principal.tenant_id,
        "domain":registrable,
        "method":method,
        "challenge":challenge,
        "expires_at":expires_at,
        "verified":False,
    }
    if method=="dns_txt":
        result["record_name"]=f"_bsa-verify.{registrable}"
        result["record_type"]="TXT"
    else:
        result["url"]=f"https://{registrable}/.well-known/be-safe-asm-verification"
    return result


class _NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        return None


def _verify_dns_txt(domain: str, challenge: str) -> bool:
    resolver=dns.resolver.Resolver()
    resolver.timeout=3
    resolver.lifetime=5
    try:
        answers=resolver.resolve(f"_bsa-verify.{domain}","TXT")
    except Exception:
        return False
    for answer in answers:
        parts=getattr(answer,"strings",None)
        if parts:
            value="".join(x.decode("utf-8","ignore") if isinstance(x,bytes) else str(x) for x in parts)
        else:
            value=str(answer).strip('"')
        if value.strip()==challenge:
            return True
    return False


def _verify_well_known(domain: str, challenge: str) -> bool:
    from .security import validate_external_target
    validate_external_target(domain)
    url=f"https://{domain}/.well-known/be-safe-asm-verification"
    opener=urllib.request.build_opener(_NoRedirect)
    request=urllib.request.Request(url,headers={"User-Agent":"Be-Safe-ASM-Ownership/1.0"},method="GET")
    try:
        with opener.open(request,timeout=5) as response:
            if int(getattr(response,"status",200))!=200:
                return False
            body=response.read(4096).decode("utf-8","ignore").strip()
    except (urllib.error.URLError,urllib.error.HTTPError,TimeoutError,OSError,ValueError):
        return False
    return body==challenge


def verify_domain_ownership_proof(principal: Principal, proof_id: str) -> dict:
    if principal.role not in {"admin","superadmin"}:
        raise PermissionError("admin required for domain ownership proof")
    ensure_scope_schema()
    conn=_db()
    row=conn.execute(
        """SELECT proof_id,tenant_id,domain,method,challenge,created_at,expires_at,verified_at
           FROM domain_ownership_proofs WHERE proof_id=? AND tenant_id=?""",
        (proof_id,principal.tenant_id),
    ).fetchone()
    if not row:
        conn.close()
        raise ValueError("ownership proof not found")
    now=int(time.time())
    if int(row["expires_at"])<=now:
        conn.close()
        raise ValueError("ownership proof expired")
    if row["verified_at"] is not None:
        result=dict(row); conn.close()
        return {**result,"verified":True}
    conn.close()
    verified=_verify_dns_txt(row["domain"],row["challenge"]) if row["method"]=="dns_txt" else _verify_well_known(row["domain"],row["challenge"])
    if not verified:
        return {
            "proof_id":row["proof_id"],"tenant_id":row["tenant_id"],"domain":row["domain"],
            "method":row["method"],"expires_at":row["expires_at"],"verified":False,
        }
    conn=_db()
    conn.execute(
        "UPDATE domain_ownership_proofs SET verified_at=?,verified_by=? WHERE proof_id=? AND tenant_id=?",
        (now,principal.user_id,proof_id,principal.tenant_id),
    )
    conn.commit(); conn.close()
    return {
        "proof_id":row["proof_id"],"tenant_id":row["tenant_id"],"domain":row["domain"],
        "method":row["method"],"expires_at":row["expires_at"],"verified_at":now,"verified":True,
    }


def domain_ownership_verified(tenant_id: str, domain: str) -> bool:
    registrable=_registrable_domain(domain)
    if not registrable:
        return False
    ensure_scope_schema()
    conn=_db()
    now=int(time.time())
    row=conn.execute(
        """SELECT 1 FROM domain_ownership_proofs
           WHERE tenant_id=? AND domain=? AND verified_at IS NOT NULL AND expires_at>?
           ORDER BY verified_at DESC LIMIT 1""",
        (tenant_id,registrable,now),
    ).fetchone()
    conn.close()
    return bool(row)


def _domain_overlap_tenants(tenant_id: str, domain: str) -> list[str]:
    registrable=_registrable_domain(domain)
    if not registrable:
        return []
    ensure_scope_schema()
    conn=_db()
    rows=conn.execute(
        "SELECT tenant_id,pattern FROM scan_scopes WHERE active=1 AND tenant_id<>?",
        (tenant_id,),
    ).fetchall()
    conn.close()
    overlaps=set()
    for row in rows:
        try:
            other=_registrable_domain(row["pattern"])
        except ValueError:
            continue
        if other==registrable:
            overlaps.add(str(row["tenant_id"]))
    return sorted(overlaps)


def create_scan_scope(principal: Principal,name:str,pattern:str):
    if principal.role not in {"admin","superadmin"}:
        raise PermissionError("admin required for active scan scope")
    pattern=validate_active_scope_pattern(pattern)
    registrable=_registrable_domain(pattern)
    production=os.getenv("BSA_ENV","development").lower() in {"production","prod"}
    overlap_tenants=[]
    if production and registrable:
        if not domain_ownership_verified(principal.tenant_id,registrable):
            raise PermissionError("verified domain ownership proof required for active scan scope")
        overlap_tenants=_domain_overlap_tenants(principal.tenant_id,registrable)
        if overlap_tenants and principal.role!="superadmin":
            raise PermissionError("domain already assigned to another tenant; superadmin approval required")
    ensure_scope_schema(); conn=_db(); sid=secrets.token_hex(10)
    conn.execute(
        "INSERT INTO scan_scopes(id,tenant_id,name,pattern,created_at) VALUES(?,?,?,?,?)",
        (sid,principal.tenant_id,name,pattern,int(time.time())),
    )
    conn.commit(); conn.close()
    return {
        "id":sid,"tenant_id":principal.tenant_id,"name":name,"pattern":pattern,"active":True,
        "ownership_verified":bool(registrable and (not production or domain_ownership_verified(principal.tenant_id,registrable))),
        "overlap_approved_by_superadmin":bool(overlap_tenants and principal.role=="superadmin"),
    }

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
    user=conn.execute(
        "SELECT id FROM users WHERE id=? AND tenant_id=?",
        (user_id,principal.tenant_id),
    ).fetchone()
    if not user:
        conn.close()
        raise ValueError("user not found")
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
    user=conn.execute(
        "SELECT id FROM users WHERE id=? AND tenant_id=?",
        (user_id,principal.tenant_id),
    ).fetchone()
    if not user:
        conn.close()
        raise ValueError("user not found")
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
