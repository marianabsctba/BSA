from urllib.request import Request, urlopen
from urllib.error import URLError, HTTPError

from .base import Evidence


class HTTPCollector:
    name = "http"

    def collect(self, url: str, timeout: float = 3.0) -> list[Evidence]:
        req = Request(url, method="HEAD", headers={"User-Agent": "BSA-ASM/0.2 defensive-discovery"})
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

        return evidence
