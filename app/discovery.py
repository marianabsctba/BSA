from dataclasses import asdict
from urllib.parse import urlparse

from .collectors.dns import DNSCollector
from .collectors.http import HTTPCollector
from .collectors.tls import TLSCollector


COLLECTORS = {
    "dns": DNSCollector(),
    "http": HTTPCollector(),
    "tls": TLSCollector(),
}


def normalize_target(target: str) -> tuple[str, str]:
    raw = target.strip()
    if not raw:
        raise ValueError("target vazio")
    candidate = raw if "://" in raw else f"https://{raw}"
    parsed = urlparse(candidate)
    hostname = parsed.hostname
    if not hostname:
        raise ValueError("target inválido")
    scheme = parsed.scheme if parsed.scheme in {"http", "https"} else "https"
    return hostname, f"{scheme}://{hostname}"


def collect_target(target: str, checks: list[str] | None = None) -> dict:
    """Run bounded, explicit-target discovery only. No recursive scanning."""
    hostname, url = normalize_target(target)
    selected = checks or ["dns", "http", "tls"]
    evidence = []

    if "dns" in selected:
        evidence.extend(COLLECTORS["dns"].collect(hostname))

    if "http" in selected:
        evidence.extend(COLLECTORS["http"].collect(url))

    if "tls" in selected:
        try:
            evidence.extend(COLLECTORS["tls"].collect(hostname))
        except (OSError, ValueError):
            pass

    return {
        "target": hostname,
        "url": url,
        "checks": selected,
        "evidence": [asdict(item) for item in evidence],
        "evidence_count": len(evidence),
        "confidence": round(sum(e.confidence for e in evidence) / len(evidence)) if evidence else 0,
    }
