import json
from urllib.parse import quote
from urllib.request import Request, urlopen
from urllib.error import URLError, HTTPError

from .base import Evidence


class CertificateTransparencyCollector:
    name = "certificate-transparency"

    def collect(self, domain: str, timeout: float = 5.0) -> list[Evidence]:
        """Passive certificate discovery for an explicitly supplied domain."""
        domain = domain.lower().strip().lstrip("*.")
        if "." not in domain:
            return []
        url = "https://crt.sh/?q=%25." + quote(domain) + "&output=json"
        req = Request(url, headers={"User-Agent": "BSA-ASM/0.3 defensive-passive-discovery"})
        try:
            with urlopen(req, timeout=timeout) as resp:
                payload = json.loads(resp.read().decode("utf-8", errors="replace"))
        except (URLError, HTTPError, ValueError, TimeoutError):
            return []

        names: set[str] = set()
        for row in payload:
            for name in str(row.get("name_value", "")).splitlines():
                candidate = name.strip().lower().lstrip("*.")
                if candidate == domain or candidate.endswith("." + domain):
                    names.add(candidate)

        return [
            Evidence(
                source=self.name,
                subject=domain,
                kind="certificate_name",
                value=name,
                confidence=88,
                metadata={"passive": True},
            )
            for name in sorted(names)
        ]
