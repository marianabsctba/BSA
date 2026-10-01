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




def classify_source_reference(value: str) -> str:
    v=value.lower()
    if any(x in v for x in ("config","secret","credential","token","admin","internal")): return "sensitive-pattern"
    if any(x in v for x in ("admin","internal","debug","staging","test")): return "high-interest-pattern"
    if any(x in v for x in ("auth","login","session","identity")): return "identity-surface"
    if any(x in v for x in ("api","graphql","client","service")): return "api-surface"
    return "general"

def source_map_context_evidence(source_map_url: str, sources: list[str]) -> list[Evidence]:
    out=[]
    for src in sources[:500]:
        if not isinstance(src,str) or not src: continue
        out.append(Evidence("http",source_map_url,"sourcemap_source_classification",
                            src,82,{"classification":classify_source_reference(src)}))
    return out

def extract_source_map_metadata(body: bytes, source_map_url: str) -> list[Evidence]:
    try:
        obj=json.loads(body[:2097152].decode("utf-8","ignore"))
    except Exception:
        return []
    if not isinstance(obj,dict) or obj.get("version") != 3: return []
    out=[]
    sources=obj.get("sources") if isinstance(obj.get("sources"),list) else []
    names=obj.get("names") if isinstance(obj.get("names"),list) else []
    out.append(Evidence("http",source_map_url,"sourcemap_metadata",source_map_url,90,{
        "source_count":len(sources),"name_count":len(names),
        "has_sources_content":isinstance(obj.get("sourcesContent"),list),
    }))
    for src in sources[:500]:
        if isinstance(src,str) and src:
            out.append(Evidence("http",source_map_url,"sourcemap_source",src,82,{"source_map":source_map_url}))
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


def build_response_baseline(samples: list[dict]) -> dict:
    """Build a deterministic baseline from observed negative/redirect responses."""
    usable=[s for s in samples if s.get("status") in {403,404}]
    hashes={}
    for s in usable:
        h=s.get("sha256")
        if h: hashes[h]=hashes.get(h,0)+1
    dominant=max(hashes,key=hashes.get) if hashes else None
    return {"sample_count":len(usable),"dominant_hash":dominant,
            "dominant_count":hashes.get(dominant,0) if dominant else 0,
            "known_hashes":hashes}

def compare_response_to_baseline(response: dict, baseline: dict) -> dict:
    h=response.get("sha256")
    known=set((baseline or {}).get("known_hashes",{}))
    return {"is_known_negative": bool(h and h in known),
            "same_as_dominant": bool(h and h==(baseline or {}).get("dominant_hash")),
            "status":response.get("status"),
            "length":response.get("length")}


def classify_surface_candidate(response: dict, baseline: dict) -> str:
    if not response or response.get("status") is None: return "unknown"
    cmp=compare_response_to_baseline(response,baseline)
    if cmp["is_known_negative"]:
        return "negative-known"
    if response.get("redirect"):
        return "redirect"
    status=response.get("status")
    if 200 <= status < 300:
        return "interesting"
    if status in {401,403}:
        return "protected"
    return "unknown"


def extract_js_literals(js: str, source_url: str, max_items: int = 500) -> list[Evidence]:
    """Extract non-executed literals from public JS bundles."""
    out=[]; seen=set()
    patterns=[
        (r"""['"]((?:https?://|//)[A-Za-z0-9._~:/?#\[\]@!$&'()*+,;=%-]{3,400})['"]""","js_url_literal"),
        (r"""['"]((?:/api/|/graphql|/oauth|/auth|/login|/admin|/internal|/health|/metrics)[A-Za-z0-9._~:/?#\[\]-]{0,300})['"]""","js_route_literal"),
        (r"""['"]((?:/|\./|\.\./)[A-Za-z0-9._~:/?#\[\]-]{2,240}\.(?:json|yaml|yml|xml|txt|config|map|wasm))['"]""","js_file_reference"),
    ]
    base=urlparse(source_url)
    for pattern,kind in patterns:
        for m in re.finditer(pattern,js,re.I):
            value=m.group(1)
            if value in seen: continue
            seen.add(value)
            try:
                parsed=urlparse(value if not value.startswith("//") else base.scheme+":"+value)
                if parsed.scheme and parsed.hostname and parsed.hostname != base.hostname:
                    kind="js_external_url_literal"
            except ValueError:
                pass
            out.append(Evidence("http",source_url,kind,value,78,{"source":"javascript"}))
            if len(out)>=max_items: return out
    return out

def detect_frontend_build_markers(body: bytes, url: str) -> list[Evidence]:
    text_body=body[:1048576].decode("utf-8","ignore")
    low=text_body.lower()
    markers=[]
    signatures=[
        ("nextjs",("__next_data__","/_next/")),
        ("vite",("/@vite/client","vite/")),
        ("webpack",("webpackjsonp","webpack-runtime")),
        ("angular",("ng-version",)),
        ("react",("react-dom",)),
        ("nuxt",("__nuxt__","/_nuxt/")),
        ("svelte",("__svelte",)),
    ]
    for framework,needles in signatures:
        hits=[n for n in needles if n in low]
        if hits:
            markers.append(Evidence("http",url,"frontend_framework_marker",framework,82,{"markers":hits}))
    pattern=r"""<script[^>]+src=['"]([^'"]+\.js(?:\?[^'"]*)?)['"]"""
    for m in re.finditer(pattern,text_body,re.I):
        src=m.group(1)
        if any(x in src.lower() for x in ("/_next/","/_nuxt/","runtime","main","polyfills","vendor")):
            markers.append(Evidence("http",url,"frontend_build_asset",src,84,{"source":"html"}))
    return markers[:200]



def extract_frontend_manifest_candidates(body: bytes, url: str) -> list[Evidence]:
    text_body=body[:1048576].decode("utf-8","ignore")
    patterns=[
        r"""['"]([^'"]+(?:build-manifest|asset-manifest|manifest|webpack-manifest)[^'"]*\.json(?:\?[^'"]*)?)['"]""",
        r"""['"]([^'"]+(?:_buildManifest|_ssgManifest)[^'"]*\.js(?:\?[^'"]*)?)['"]""",
        r"""['"]([^'"]+/_next/static/[^'"]+\.js(?:\?[^'"]*)?)['"]""",
        r"""['"]([^'"]+/_nuxt/[^'"]+\.(?:js|json)(?:\?[^'"]*)?)['"]""",
    ]
    out=[]; seen=set()
    for pattern in patterns:
        for m in re.finditer(pattern,text_body,re.I):
            value=m.group(1)
            if value in seen: continue
            seen.add(value)
            out.append(Evidence("http",url,"frontend_manifest_candidate",value,84,{"source":"html"}))
            if len(out)>=200: return out
    return out


def extract_manifest_asset_references(body: bytes, manifest_url: str) -> list[Evidence]:
    """Parse common frontend manifests without executing JavaScript."""
    raw=body[:2097152].decode("utf-8","ignore")
    out=[]; seen=set()
    def add(value,kind="manifest_asset"):
        if not isinstance(value,str) or not value or value in seen: return
        if not (value.endswith((".js",".map",".json",".css")) or "/_next/" in value or "/_nuxt/" in value):
            return
        seen.add(value)
        out.append(Evidence("http",manifest_url,kind,value,84,{"source":"frontend_manifest"}))
    try:
        obj=json.loads(raw)
        def walk(v):
            if len(out)>=500:return
            if isinstance(v,str): add(v)
            elif isinstance(v,dict):
                for x in v.values(): walk(x)
            elif isinstance(v,list):
                for x in v: walk(x)
        walk(obj)
    except Exception:
        for m in re.finditer(r"""["']([^"']+\.(?:js|map|json|css)(?:\?[^"']*)?)["']""",raw,re.I):
            add(m.group(1))
            if len(out)>=500: break
    return out

def discover_web_surface(url: str, max_paths: int = 40, max_js: int = 20) -> list[Evidence]:
    """Bounded same-origin web surface discovery."""
    validate_external_target(url)
    evidence=[]
    origin=url.rstrip("/")
    paths=list(COMMON_SURFACE_PATHS[:max(1,min(max_paths,len(COMMON_SURFACE_PATHS)))])
    script_urls=[]
    manifest_urls=[]
    for path in paths:
        status,headers,body,final_url=_safe_surface_fetch(origin,path)
        if status is None:
            continue
        evidence.append(Evidence("http",origin,"surface_path",path,90,{"surface":classify_surface_response(status,headers,body)}))
        ctype=(headers.get("content-type") or "").lower()
        if 200 <= status < 300 and body:
            if "javascript" in ctype or path.endswith(".js"):
                script_urls.append(final_url)
            if "html" in ctype or path=="/":
                html=body.decode("utf-8","ignore")
                evidence.extend(detect_frontend_build_markers(body,origin))
                evidence.extend(extract_frontend_manifest_candidates(body,origin))
                for m in re.finditer(r"""<script[^>]+src=[\'"]([^\'"]+(?:manifest|build-manifest|asset-manifest)[^\'"]*)[\'"]""",html,re.I):
                    manifest_urls.append(urljoin(origin,m.group(1)))
                for m in re.finditer(r'''<script[^>]+src=['"]([^'"]+\.js(?:\?[^'"]*)?)['"]''',html,re.I):
                    src=urljoin(origin,m.group(1))
                    if urlparse(src).hostname == urlparse(origin).hostname:
                        script_urls.append(src)
    # Always inspect root independently: bounded discovery must not depend on '/' being in the first N paths.
    if "/" not in paths:
        status,headers,body,final_url=_safe_surface_fetch(origin,"/")
        if status and 200 <= status < 300 and body:
            html=body.decode("utf-8","ignore")
            evidence.extend(detect_frontend_build_markers(body,origin))
            evidence.extend(extract_frontend_manifest_candidates(body,origin))
            for m in re.finditer(r"""<script[^>]+src=[\'"]([^\'"]+(?:manifest|build-manifest|asset-manifest)[^\'"]*)[\'"]""",html,re.I):
                manifest_urls.append(urljoin(origin,m.group(1)))
            for m in re.finditer(r'''<script[^>]+src=['"]([^'"]+\.js(?:\?[^'"]*)?)['"]''',html,re.I):
                src=urljoin(origin,m.group(1))
                if urlparse(src).hostname == urlparse(origin).hostname:
                    script_urls.append(src)
    # Fetch explicitly referenced frontend manifests with the same bounded transport.
    manifest_assets=[]
    for manifest_url in list(dict.fromkeys(manifest_urls))[:max_js]:
        parsed=urlparse(manifest_url)
        if parsed.hostname != urlparse(origin).hostname: continue
        manifest_path=parsed.path or "/"
        if parsed.query: manifest_path += "?" + parsed.query
        status,headers,body,final_url=_safe_surface_fetch(origin,manifest_path,timeout=3.0)
        if not (status and 200 <= status < 300 and body): continue
        evidence.append(Evidence("http",manifest_url,"frontend_manifest_analyzed",manifest_url,88,{"bytes":len(body)}))
        for asset in extract_manifest_asset_references(body,manifest_url)[:100]:
            asset_url=urljoin(origin,asset.value)
            if urlparse(asset_url).hostname == urlparse(origin).hostname:
                manifest_assets.append(asset_url)
                evidence.append(Evidence("http",manifest_url,"manifest_discovered_asset",asset_url,86,{"source":manifest_url}))

    seen=set()
    for js_url in script_urls[:max_js]:
        if js_url in seen: continue
        seen.add(js_url)
        parsed=urlparse(js_url)
        js_path=parsed.path or "/"
        if parsed.query: js_path += "?" + parsed.query
        status,headers,body,final_url=_safe_surface_fetch(origin,js_path,timeout=3.0)
        if not (status and 200 <= status < 300 and body):
            continue
        js=body[:524288].decode("utf-8","ignore")
        evidence.append(Evidence("http",js_url,"javascript_asset",js_url,90,{"bytes":len(js)}))
        evidence.extend(extract_js_surface_references(js,js_url))
        evidence.extend(extract_js_literals(js,js_url))
        if any(x in js_url.lower() for x in ("manifest", "build-manifest", "asset-manifest", "_buildmanifest", "_ssgmanifest")):
            for asset in extract_manifest_asset_references(body,js_url)[:100]:
                asset_url=urljoin(origin,asset.value)
                if urlparse(asset_url).hostname == urlparse(origin).hostname:
                    manifest_assets.append(asset_url)
                    evidence.append(Evidence("http",js_url,"manifest_discovered_asset",asset_url,86,{"source":js_url}))

    # Analyze bounded manifest-discovered JS chunks in a second pass.
    for asset_url in list(dict.fromkeys(manifest_assets))[:max_js]:
        if asset_url in seen: continue
        seen.add(asset_url)
        parsed=urlparse(asset_url); asset_path=parsed.path or "/"
        if parsed.query: asset_path += "?" + parsed.query
        status,headers,body,final_url=_safe_surface_fetch(origin,asset_path,timeout=3.0)
        if not (status and 200 <= status < 300 and body): continue
        ctype=(headers.get("content-type") or "").lower()
        if "javascript" not in ctype and not asset_path.endswith((".js",".mjs")): continue
        js=body[:524288].decode("utf-8","ignore")
        evidence.append(Evidence("http",asset_url,"manifest_asset_analyzed",asset_url,88,{"bytes":len(js)}))
        evidence.extend(extract_js_surface_references(js,asset_url))
        evidence.extend(extract_js_literals(js,asset_url))
        # Discover source maps from the standard sourceMappingURL trailer.
        map_match=re.search(r"""sourceMappingURL\s*=\s*([^\s"'<>]+)""",js[-32768:],re.I)
        if map_match:
            map_url=urljoin(asset_url,map_match.group(1).strip())
            if urlparse(map_url).hostname == urlparse(origin).hostname:
                evidence.append(Evidence("http",asset_url,"source_map_candidate",map_url,84,{"source":"javascript_chunk"}))
        # Also support quoted .js.map references used by some build loaders.
        for sm in re.finditer(r"""["']([^"']+\.js\.map(?:\?[^"']*)?)["']""",js,re.I):
            map_url=urljoin(asset_url,sm.group(1))
            if urlparse(map_url).hostname == urlparse(origin).hostname:
                evidence.append(Evidence("http",asset_url,"source_map_candidate",map_url,84,{"source":"javascript_chunk"}))
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
