from dataclasses import dataclass
from urllib.parse import urlparse


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
