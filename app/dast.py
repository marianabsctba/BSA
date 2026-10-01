from dataclasses import dataclass, asdict
from datetime import datetime, timezone
from urllib.parse import urlparse, urljoin
import uuid
import re
import json
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
    if body:
        html=body.decode("utf-8","ignore")[:262144]
        forms=len(re.findall(r"<form\\b",html,re.I))
        scripts=len(re.findall(r"<script\\b",html,re.I))
        if forms:
            findings.append(DASTFinding("surface_inventory","info",f"forms observed: {forms}",f"forms={forms}",95))
        if scripts:
            findings.append(DASTFinding("surface_inventory","info",f"scripts observed: {scripts}",f"scripts={scripts}",95))
    api_inventory=[]
    content_type=lower_headers.get("content-type","").lower()
    if "json" in content_type and body:
        try:
            spec=json.loads(body.decode("utf-8","ignore"))
            if isinstance(spec,dict) and (spec.get("openapi") or spec.get("swagger")):
                for path,item in list(spec.get("paths",{}).items())[:500]:
                    if isinstance(path,str) and isinstance(item,dict):
                        for method,op in item.items():
                            if method.lower() in {"get","post","put","patch","delete","head","options","trace"}:
                                api_inventory.append({"path":path,"method":method.upper(),"operation_id":op.get("operationId") if isinstance(op,dict) else None,"auth_declared":bool(op.get("security",spec.get("security"))) if isinstance(op,dict) else bool(spec.get("security"))})
        except (ValueError,TypeError):
            pass

    api_validation=[]
    for item in api_inventory[:500]:
        path=item["path"]
        if "{" in path:
            api_validation.append({"path":path,"method":item["method"],"status":"template","reason":"path parameter requires an explicit test value"})
            continue
        candidate=urljoin(url,path)
        cp=urlparse(candidate)
        if cp.hostname != parsed.hostname:
            continue
        try:
            vstatus, vheaders, _, vfinal=_pinned_fetch(candidate,timeout=3.0,max_bytes=65536,approved_ips=approved_ips)
            api_validation.append({"path":path,"method":item["method"],"status":vstatus,"final_url":vfinal,"auth_declared":item["auth_declared"]})
            if item["method"]=="GET" and vstatus>=500:
                findings.append(DASTFinding("api_validation","medium","documented GET endpoint returned 5xx",f"{item['method']} {path} -> {vstatus}",86))
        except Exception:
            api_validation.append({"path":path,"method":item["method"],"status":"unreachable","auth_declared":item["auth_declared"]})

    # Bounded same-origin crawl: GET only, no payload mutation and no external hosts.
    discovered = []
    if body:
        html = body.decode("utf-8","ignore")[:262144]
        for ref in re.findall(r"(?:href|src|action)=['\"]([^'\"]+)['\"]", html, re.I)[:150]:
            absolute = urljoin(url, ref)
            rp = urlparse(absolute)
            if rp.hostname == parsed.hostname and rp.scheme in {"http","https"}:
                discovered.append(absolute)
        if parsed.scheme == "https" and re.search(r"(?:src|href)=['\"]http://", html, re.I):
            findings.append(DASTFinding("mixed_content","medium","HTTPS page references HTTP resources","http:// resource",90))
        for action in re.findall(r"<form[^>]+action=['\"]([^'\"]+)['\"]", html, re.I)[:50]:
            ap = urlparse(urljoin(url, action))
            if parsed.scheme == "https" and ap.scheme == "http" and ap.hostname == parsed.hostname:
                findings.append(DASTFinding("form_transport","medium","HTTPS page posts a form to HTTP","form action",94))
    seen={url}
    queue=list(dict.fromkeys(discovered))[:30]
    while queue and len(seen)<31:
        candidate=queue.pop(0)
        if candidate in seen: continue
        cp=urlparse(candidate)
        if cp.hostname != parsed.hostname or cp.scheme not in {"http","https"}: continue
        seen.add(candidate)
        try:
            cstatus, cheaders, cbody, _ = _pinned_fetch(candidate, timeout=3.0, max_bytes=131072, approved_ips=approved_ips)
        except Exception:
            continue
        if cstatus >= 500:
            findings.append(DASTFinding("http_status","medium","same-origin resource returned 5xx",f"{cstatus} {candidate}",85))
        if cbody:
            ctext=cbody.decode("utf-8","ignore")[:131072]
            for ref in re.findall(r"(?:href|src|action)=[\"']([^\"']+)[\"']", ctext, re.I)[:50]:
                nxt=urljoin(candidate,ref)
                if urlparse(nxt).hostname == parsed.hostname and nxt not in seen and len(queue)<30:
                    queue.append(nxt)
    return {"job_id":str(uuid.uuid4()),"target":url,"final_url":final_url,"profile":"safe-web","destructive_tests":False,"started_at":datetime.now(timezone.utc).isoformat(),"http_status":status,"findings":[asdict(x) for x in findings],"finding_count":len(findings),"api_inventory":api_inventory,"api_validation":api_validation,"evidence":[asdict(x) for x in security_header_evidence(url,headers)],"body_bytes_observed":len(body)}
