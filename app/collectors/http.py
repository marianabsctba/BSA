from urllib.request import Request, urlopen
from urllib.error import URLError, HTTPError
from hashlib import sha256

from .base import Evidence


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
        req = Request(
            url,
            method="GET",
            headers={"User-Agent": "BSA-ASM/0.3 defensive-discovery"},
        )
        body=b""
        redirect_chain=[]
        try:
            with urlopen(req, timeout=timeout) as resp:
                headers=resp.headers
                status=resp.status
                final_url=resp.geturl()
                body=resp.read(131072)
                if final_url != url:
                    redirect_chain.append(final_url)
        except HTTPError as exc:
            headers = exc.headers
            status = exc.code
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
        if headers.get("server"):
            evidence.append(Evidence(self.name,url,"technology:server",headers.get("server"),78))
        if headers.get("x-powered-by"):
            evidence.append(Evidence(self.name,url,"technology:x-powered-by",headers.get("x-powered-by"),78))

        for header in ("server", "content-type", "strict-transport-security", "x-powered-by"):
            value = headers.get(header)
            if value:
                evidence.append(Evidence(self.name, url, f"http_header:{header}", value, 85))

        evidence.extend(security_header_evidence(url, headers))
        return evidence
