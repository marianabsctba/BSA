from urllib.request import Request, urlopen
from urllib.error import URLError, HTTPError

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
            method="HEAD",
            headers={"User-Agent": "BSA-ASM/0.3 defensive-discovery"},
        )
        try:
            with urlopen(req, timeout=timeout) as resp:
                headers = resp.headers
                status = resp.status
        except HTTPError as exc:
            headers = exc.headers
            status = exc.code
        except URLError:
            return []

        evidence = [Evidence(self.name, url, "http_status", str(status), 98)]

        for header in ("server", "content-type", "strict-transport-security", "x-powered-by"):
            value = headers.get(header)
            if value:
                evidence.append(Evidence(self.name, url, f"http_header:{header}", value, 85))

        evidence.extend(security_header_evidence(url, headers))
        return evidence
