from urllib.request import Request, urlopen, HTTPRedirectHandler, build_opener
from urllib.error import URLError, HTTPError
from urllib.parse import urljoin, urlparse
import re
import hashlib
import json
from hashlib import sha256

from .base import Evidence
from ..security import validate_external_target, validate_redirect




class _NoRedirect(HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        return None



ARTIFACT_CONTENT_TYPES = {
    "application/json": "json",
    "application/manifest+json": "json",
    "application/xml": "xml",
    "text/xml": "xml",
    "text/yaml": "yaml",
    "application/yaml": "yaml",
    "text/plain": "text",
}

ARTIFACT_PATHS = (
    "/robots.txt",
    "/sitemap.xml",
    "/.well-known/security.txt",
    "/.well-known/assetlinks.json",
    "/.well-known/apple-app-site-association",
    "/swagger.json",
    "/openapi.json",
    "/api/openapi.json",
    "/swagger/v1/swagger.json",
    "/package.json",
    "/composer.json",
    "/manifest.json",
)


COMMON_SURFACE_PATHS = (
    "/.git/HEAD","/.env","/.env.example","/.well-known/security.txt",
    "/robots.txt","/sitemap.xml","/swagger.json","/openapi.json",
    "/api/openapi.json","/api/docs","/docs","/redoc","/graphql",
    "/health","/healthz","/status","/metrics","/actuator/health",
    "/server-status","/phpinfo.php","/debug","/admin","/login",
    "/signin","/dashboard","/config.json","/manifest.json",
    "/asset-manifest.json","/service-worker.js","/favicon.ico",
    "/crossdomain.xml","/clientaccesspolicy.xml","/backup.zip",
    "/backup.tar.gz","/site-backup.zip","/.DS_Store","/package.json",
)

def _safe_surface_fetch(base_url: str, path: str, timeout: float = 2.5):
    candidate=urljoin(base_url,path)
    validate_external_target(candidate)
    req=Request(candidate,method="GET",headers={"User-Agent":"BSA-ASM/0.3 defensive-surface"})
    try:
        opener=build_opener(_NoRedirect())
        with opener.open(req,timeout=timeout) as resp:
            return resp.status, resp.headers, resp.read(262144), resp.geturl()
    except HTTPError as exc:
        return exc.code, exc.headers, b"", candidate
    except (URLError,OSError,ValueError):
        return None, {}, b"", candidate


JS_CHUNK_PATHS = ("/_next/static/","/static/js/","/assets/","/js/")

def extract_js_surface_references(js: str, source_url: str) -> list[Evidence]:
    out=[]; seen=set()
    patterns=[
        (r"""['"]([^'"]+\.map(?:\?[^'"]*)?)['"]""","js_sourcemap_reference"),
        (r"""['"]([^'"]+(?:\.chunk|\.bundle|\.min)\.js(?:\?[^'"]*)?)['"]""","js_chunk_reference"),
        (r"""['"]((?:/api/|/graphql|/v\d+/)[A-Za-z0-9._~:/?#[\]-]{1,240})['"]""","js_endpoint_reference"),
        (r"""['"]((?:/|\./|\.\./)[A-Za-z0-9._~:/?#[\]-]{2,180}(?:json|yaml|xml|config|env|map))['"]""","js_artifact_reference"),
    ]
    for pattern,kind in patterns:
        for m in re.finditer(pattern,js,re.I):
            value=urljoin(source_url,m.group(1))
            if value in seen: continue
            seen.add(value)
            out.append(Evidence("http",source_url,kind,value,84,{"source":"javascript"}))
            if len(out)>=200: return out
    return out


def analyze_public_artifact_references(url: str, body: bytes, content_type: str = "") -> list[Evidence]:
    """Parse public structured artifacts without executing their contents."""
    if not body: return []
    text_body=body[:1048576].decode("utf-8","ignore")
    kind="text"
    low=content_type.lower()
    if "json" in low or url.lower().endswith(".json"): kind="json"
    elif "yaml" in low or url.lower().endswith((".yaml",".yml")): kind="yaml"
    elif "xml" in low or url.lower().endswith(".xml"): kind="xml"
    out=artifact_discovery_candidates(url,kind,body)
    if kind=="json":
        try:
            obj=json.loads(text_body)
            if isinstance(obj,dict) and (obj.get("openapi") or obj.get("swagger")):
                out.extend(extract_openapi_inventory(url,body))
        except Exception:
            pass
    # Source maps: record source paths as evidence; do not fetch arbitrary sources here.
    if url.lower().endswith(".map"):
        try:
            obj=json.loads(text_body)
            for src in obj.get("sources",[])[:500] if isinstance(obj,dict) else []:
                if isinstance(src,str) and src:
                    out.append(Evidence("http",url,"sourcemap_source",src,82,{"source_map":url}))
        except Exception:
            pass
    return out[:1000]


def contextual_surface_paths(evidence: list[dict], max_paths: int = 80) -> list[str]:
    """Build bounded, evidence-derived paths; no arbitrary wordlist expansion."""
    paths=set()
    for e in evidence[-1000:]:
        kind=str(e.get("kind",""))
        value=str(e.get("value",""))
        if kind in {"js_endpoint_reference","js_artifact_reference","openapi_endpoint","sourcemap_source"}:
            parsed=urlparse(value)
            p=parsed.path if parsed.scheme else value
            if p.startswith("/"):
                paths.add(p)
                base=p.rsplit("/",1)[0] or "/"
                if base != "/": paths.add(base)
        if kind=="technology_version":
            product=str(e.get("metadata",{}).get("product","")).lower()
            if product in {"wordpress","drupal","joomla"}:
                paths.update({"/wp-admin/","/wp-json/"} if product=="wordpress" else {"/admin/","/core/"} if product=="drupal" else {"/administrator/"})
    return sorted(paths)[:max(1,min(max_paths,200))]


def classify_surface_response(status: int | None, headers: dict, body: bytes) -> dict:
    ctype=(headers.get("content-type") or "").lower()
    digest=hashlib.sha256(body[:1048576]).hexdigest() if body else None
    length=len(body)
    return {
        "status":status,
        "content_type":ctype.split(";")[0],
        "length":length,
        "sha256":digest,
        "redirect": status in {301,302,303,307,308} if status else False,
        "likely_empty": length == 0,
    }

def discover_web_surface(url: str, max_paths: int = 40, max_js: int = 20) -> list[Evidence]:
    """Bounded same-origin web surface discovery: common files/directories + public JS references."""
    validate_external_target(url)
    evidence=[]
    origin=url.rstrip("/")
    paths=list(COMMON_SURFACE_PATHS[:max(1,min(max_paths,len(COMMON_SURFACE_PATHS)))])
    script_urls=[]
    for path in paths:
        status,headers,body,final_url=_safe_surface_fetch(origin,path)
        if status is None: continue
        kind="surface_path"
        evidence.append(Evidence("http",origin,kind,path,90,{"surface":classify_surface_response(status,headers,body)}))
        if 200 <= status < 300 and body:
            ctype=(headers.get("content-type") or "").lower()
            if "javascript" in ctype or path.endswith(".js"):
                script_urls.append(final_url)
            elif "html" in ctype or path == "/":
                try:
                    html=body.decode("utf-8","ignore")[:1048576]
                    for m in re.finditer(r"""<script[^>]+src=['"]([^'"]+\.js(?:\?[^'"]*)?)['"]""",html,re.I):
                        src=urljoin(origin,m.group(1))
                        if urlparse(src).hostname == urlparse(origin).hostname:
                            script_urls.append(src)
                except UnicodeDecodeError:
                    pass
    status,headers,body,final_url=_safe_surface_fetch(origin,"/")
    if status and body:
        html=body.decode("utf-8","ignore")[:1048576]
        for m in re.finditer(r"""<script[^>]+src=['"]([^'"]+\.js(?:\?[^'"]*)?)['"]""",html,re.I):
            src=urljoin(origin,m.group(1))
            parsed=urlparse(src)
            base=urlparse(origin)
            if parsed.scheme in {"http","https"} and parsed.hostname==base.hostname:
                script_urls.append(src)
        for m in re.finditer(r"""(?:fetch|axios\.(?:get|post|put|patch|delete)|XMLHttpRequest)[^\n]{0,300}?['"](/[^'"]{2,200})['"]""",html,re.I):
            evidence.append(Evidence("http",origin,"js_endpoint_reference",m.group(1),82,{"source":"inline-js"}))
    seen=set()
    for js_url in script_urls[:max_js]:
        if js_url in seen: continue
        seen.add(js_url)
        try:
            validate_external_target(js_url)
            parsed_js=urlparse(js_url)
            base=urlparse(origin)
            js_path=parsed_js.path or "/"
            if parsed_js.query:
                js_path += "?" + parsed_js.query
            status_js,headers_js,body_js,final_js=_safe_surface_fetch(origin,js_path,timeout=3.0)
            if not (status_js and 200 <= status_js < 300 and body_js):
                continue
            js=body_js[:524288].decode("utf-8","ignore")
            evidence.append(Evidence("http",js_url,"javascript_asset",js_url,90,{"bytes":len(js)}))
            for m in re.finditer(r"""(?:fetch|axios\.(?:get|post|put|patch|delete)|XMLHttpRequest)[^\n]{0,300}?['"]((?:/api/|/graphql|/v\d+/)[A-Za-z0-9._~:/?#[\]-]{1,240})['"]""",js,re.I):
                evidence.append(Evidence("http",js_url,"js_endpoint_reference",m.group(1),84,{"source":"javascript"}))
            for m in re.finditer(r"""['"]((?:/|\./|\.\./)[A-Za-z0-9._~:/?#[\]-]{2,180}(?:json|yaml|xml|config|map))['"]""",js,re.I):
                evidence.append(Evidence("http",js_url,"js_artifact_reference",m.group(1),80,{"source":"javascript"}))
        except (URLError,OSError,ValueError):
            continue
            evidence.extend(extract_js_surface_references(js,js_url))
    return evidence

def _artifact_evidence(url, headers, body):
    evidence=[]
    content_type=(headers.get("content-type") or "").split(";",1)[0].strip().lower()
    kind=ARTIFACT_CONTENT_TYPES.get(content_type)
    if kind and body:
        digest=sha256(body).hexdigest()
        evidence.append(Evidence("http",url,f"web_artifact:{kind}",f"content-type:{content_type}",91,{"sha256":digest,"bytes":len(body)}))
        text_body=body.decode("utf-8","ignore")[:65536]
        # Extract only public references; no execution and no recursive fetching here.
        pattern = r"""https?://[^\s<>'"\\]+|(?:^|[\s"'(/])/[A-Za-z0-9._~:/?#[\]-]{2,}"""
        for match in re.finditer(pattern, text_body):
            ref=match.group(0).strip()
            if ref:
                evidence.append(Evidence("http",url,"artifact_reference",ref[:500],78,{"artifact_kind":kind}))
    return evidence



def artifact_discovery_candidates(url: str, kind: str, body: bytes) -> list[Evidence]:
    """Turn references from an already fetched public artifact into bounded candidates.
    This never performs the follow-up request; discovery orchestration decides scope."""
    if not body or kind not in {"json","xml","yaml","text"}:
        return []
    text_body=body.decode("utf-8","ignore")[:65536]
    refs=[]
    seen=set()
    for match in re.finditer(r"""https?://[^\s<>'"\\]+|(?:^|[\s"'(/])/[A-Za-z0-9._~:/?#[\]-]{2,}""",text_body):
        ref=match.group(0).strip().strip('"\'').rstrip(".,;")
        if not ref or ref in seen: continue
        seen.add(ref)
        if ref.startswith("http"):
            candidate=ref
        else:
            candidate=urljoin(url,ref)
        refs.append(Evidence("http",url,"discovery_candidate",candidate,72,{"artifact_kind":kind,"derived_from":url}))
        if len(refs)>=100: break
    return refs


def extract_openapi_inventory(url: str, body: bytes) -> list[Evidence]:
    try:
        data=json.loads(body.decode("utf-8","ignore"))
    except Exception:
        return []
    if not isinstance(data,dict) or not (data.get("openapi") or data.get("swagger")):
        return []
    out=[]
    paths=data.get("paths")
    if not isinstance(paths,dict):
        return out
    for path,item in paths.items():
        if not isinstance(path,str) or not path.startswith("/") or not isinstance(item,dict):
            continue
        for method,operation in item.items():
            if method.lower() not in {"get","post","put","patch","delete","head","options","trace"}:
                continue
            if not isinstance(operation,dict): operation={}
            auth=operation.get("security", data.get("security"))
            out.append(Evidence("http",url,"openapi_endpoint",path,88,{
                "method":method.upper(),
                "operation_id":operation.get("operationId"),
                "auth_declared":bool(auth),
                "tags":operation.get("tags",[]) if isinstance(operation.get("tags",[]),list) else [],
                "parameters":len(operation.get("parameters",[])) if isinstance(operation.get("parameters",[]),list) else 0,
            }))
            if len(out)>=1000: return out
    return out

def _structured_artifact_evidence(url: str, kind: str, body: bytes) -> list[Evidence]:
    if kind != "json" or not body:
        return []
    try:
        data=json.loads(body.decode("utf-8","ignore"))
    except Exception:
        return []
    evidence=[]
    if isinstance(data,dict):
        for key in ("openapi","swagger","version","name","title","description"):
            value=data.get(key)
            if isinstance(value,(str,int,float)) and str(value).strip():
                evidence.append(Evidence("http",url,f"json_field:{key}",str(value)[:500],86,{"artifact_kind":kind}))
        for key in ("servers","paths","components","security","dependencies","scripts"):
            value=data.get(key)
            if isinstance(value,dict):
                evidence.append(Evidence("http",url,f"json_section:{key}",str(len(value)),82,{"artifact_kind":kind,"count":len(value)}))
            elif isinstance(value,list):
                evidence.append(Evidence("http",url,f"json_section:{key}",str(len(value)),82,{"artifact_kind":kind,"count":len(value)}))
    return evidence

SECURITY_HEADERS = (
    "strict-transport-security",
    "content-security-policy",
    "x-content-type-options",
    "referrer-policy",
    "permissions-policy",
)



def _versioned_technology_evidence(url: str, source: str, value: str) -> list[Evidence]:
    value=value.strip()[:240]
    if not value: return []
    out=[Evidence("http",url,"technology:fingerprint",value,84,{"source":source})]
    patterns=[
        (r"(?i)([a-z][a-z0-9._-]{1,40})[ /-](v?\d+(?:\.\d+){0,3})","technology_version"),
        (r"(?i)(php|nginx|apache|iis|tomcat|gunicorn|uvicorn|express|wordpress|drupal|joomla|next\.js|react)[ /_-](v?\d+(?:\.\d+){0,3})","technology_version"),
    ]
    for pattern,kind in patterns:
        for m in re.finditer(pattern,value):
            product=m.group(1).strip()
            version=m.group(2).lstrip("v")
            out.append(Evidence("http",url,kind,f"{product}:{version}",90,{"source":source,"product":product,"version":version}))
    return out

def security_header_evidence(url: str, headers) -> list[Evidence]:
    evidence = []
    for header in SECURITY_HEADERS:
        value = headers.get(header)
        evidence.append(
            Evidence(
                source="http",
                subject=url,
                kind=f"security_header:{header}",
                value=value or "missing",
                confidence=97,
                metadata={"present": bool(value)},
            )
        )
    return evidence


class HTTPCollector:
    name = "http"

    def collect(self, url: str, timeout: float = 4.0) -> list[Evidence]:
        validate_external_target(url)
        req = Request(
            url,
            method="GET",
            headers={"User-Agent": "BSA-ASM/0.3 defensive-discovery"},
        )
        body=b""
        redirect_chain=[]
        try:
            opener = build_opener(_NoRedirect())
            with opener.open(req, timeout=timeout) as resp:
                headers=resp.headers
                status=resp.status
                final_url=resp.geturl()
                validate_redirect(final_url)
                body=resp.read(131072)
        except HTTPError as exc:
            headers = exc.headers
            status = exc.code
            if 300 <= status < 400:
                location = headers.get("Location")
                if location:
                    redirect_url = urljoin(url, location)
                    validate_redirect(redirect_url)
                    redirect_chain.append(redirect_url)
        except URLError:
            return []

        evidence=[Evidence(self.name,url,"http_status",str(status),98)]
        if redirect_chain:
            evidence.append(Evidence(self.name,url,"redirect_chain"," -> ".join(redirect_chain),96,{"chain":redirect_chain}))
        try:
            import re
            m=re.search(rb"<title[^>]*>(.*?)</title>",body,re.I|re.S)
            title=m.group(1).decode("utf-8","ignore").strip()[:300] if m else ""
            if title:
                evidence.append(Evidence(self.name,url,"page_title",title,88))
        except Exception:
            pass
        if body:
            evidence.append(Evidence(self.name,url,"body_sha256",sha256(body).hexdigest(),92))
            text=body.decode("utf-8","ignore")
            for kind, pattern in ((
                ("technology:generator", r"<meta[^>]+name=[\'\"]generator[\'\"][^>]+content=[\'\"]([^\'\"]+)"),
                ("technology:powered-by", r"<meta[^>]+name=[\'\"]powered-by[\'\"][^>]+content=[\'\"]([^\'\"]+)"),
            )):
                for match in re.finditer(pattern, text, re.I):
                    value=match.group(1).strip()[:180]
                    if value:
                        evidence.append(Evidence(self.name,url,kind,value,82))
        if headers.get("server"):
            evidence.append(Evidence(self.name,url,"technology:server",headers.get("server"),78))
            evidence.extend(_versioned_technology_evidence(url,"server_header",headers.get("server","")))
        if headers.get("x-powered-by"):
            evidence.append(Evidence(self.name,url,"technology:x-powered-by",headers.get("x-powered-by"),78))
            evidence.extend(_versioned_technology_evidence(url,"x_powered_by",headers.get("x-powered-by","")))

        for header in ("server", "content-type", "strict-transport-security", "x-powered-by"):
            value = headers.get(header)
            if value:
                evidence.append(Evidence(self.name, url, f"http_header:{header}", value, 85))

        evidence.extend(_artifact_evidence(url, headers, body))
        if body:
            ctype=(headers.get("content-type") or "").split(";",1)[0].strip().lower()
            kind=ARTIFACT_CONTENT_TYPES.get(ctype)
            if kind:
                evidence.extend(_structured_artifact_evidence(url,kind,body))
                evidence.extend(artifact_discovery_candidates(url,kind,body))
                evidence.extend(extract_openapi_inventory(url,body))
        evidence.extend(security_header_evidence(url, headers))
        return evidence
