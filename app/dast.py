from dataclasses import dataclass, asdict
from datetime import datetime, timezone
from urllib.parse import urlparse
import uuid
from .collectors.http import _pinned_fetch, security_header_evidence
from .security import validate_external_target, resolve_public

@dataclass(frozen=True)
class DASTFinding:
    check: str
    severity: str
    title: str
    evidence: str
    confidence: int

def run_safe_web_assessment(target: str) -> dict:
    """Bounded non-destructive web assessment for an explicitly authorized target."""
    validate_external_target(target)
    parsed = urlparse(target if "://" in target else f"https://{target}")
    if parsed.scheme not in {"http", "https"} or not parsed.hostname:
        raise ValueError("invalid web target")
    url = f"{parsed.scheme}://{parsed.hostname}{parsed.path or '/'}"
    approved_ips = resolve_public(parsed.hostname)
    status, headers, body, final_url = _pinned_fetch(url, timeout=4.0, max_bytes=262144, approved_ips=approved_ips)
    findings=[]
    lower_headers={str(k).lower():str(v) for k,v in headers.items()}
    required={"strict-transport-security":"missing HSTS","content-security-policy":"missing Content-Security-Policy","x-content-type-options":"missing X-Content-Type-Options","referrer-policy":"missing Referrer-Policy"}
    for header,title in required.items():
        if header not in lower_headers: findings.append(DASTFinding("security_headers","low",title,header,90))
    cookie=lower_headers.get("set-cookie","")
    if "bsa_session" in cookie.lower():
        for flag,severity in (("secure","medium"),("httponly","medium"),("samesite","low")):
            if flag not in cookie.lower(): findings.append(DASTFinding("session_cookie",severity,f"session cookie without {flag.title()}","bsa_session",92))
    if 500 <= status <= 599: findings.append(DASTFinding("http_status","medium","server returned 5xx",str(status),85))
    return {"job_id":str(uuid.uuid4()),"target":url,"final_url":final_url,"profile":"safe-web","destructive_tests":False,"started_at":datetime.now(timezone.utc).isoformat(),"http_status":status,"findings":[asdict(x) for x in findings],"finding_count":len(findings),"evidence":[asdict(x) for x in security_header_evidence(url,headers)],"body_bytes_observed":len(body)}
