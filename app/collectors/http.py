from urllib.request import Request, urlopen, HTTPRedirectHandler, build_opener
from urllib.error import URLError, HTTPError
from urllib.parse import urljoin
import re
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
        if headers.get("x-powered-by"):
            evidence.append(Evidence(self.name,url,"technology:x-powered-by",headers.get("x-powered-by"),78))

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
        evidence.extend(security_header_evidence(url, headers))
        return evidence
