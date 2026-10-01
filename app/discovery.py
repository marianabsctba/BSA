from dataclasses import asdict
from urllib.parse import urlparse
from collections import deque

from .collectors.dns import DNSCollector
from .collectors.http import HTTPCollector
from .collectors.tls import TLSCollector
from .collectors.certificate_transparency import CertificateTransparencyCollector
from .collectors.ports import PortCollector
from .correlation import correlate_evidence


COLLECTORS = {
    "dns": DNSCollector(),
    "http": HTTPCollector(),
    "tls": TLSCollector(),
    "ct": CertificateTransparencyCollector(),
    "ports": PortCollector(),
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
    selected = checks or ["dns", "http", "tls", "ct"]
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

    if "ct" in selected:
        evidence.extend(COLLECTORS["ct"].collect(hostname))

    if "ports" in selected:
        evidence.extend(COLLECTORS["ports"].collect(hostname))

    return {
        "target": hostname,
        "url": url,
        "checks": selected,
        "evidence": [asdict(item) for item in evidence],
        "evidence_count": len(evidence),
        "confidence": round(sum(e.confidence for e in evidence) / len(evidence)) if evidence else 0,
    }


def discover_surface(seed: str, max_depth: int = 2, max_assets: int = 40) -> dict:
    """Bounded passive EASM expansion from an explicit in-scope seed.

    Only certificate-derived names inside the seed's registrable domain are
    eligible for expansion. External redirect/related names are reported but
    never recursively scanned.
    """
    hostname, _ = normalize_target(seed)
    base = hostname.split(".")[-2:] if hostname.count(".") >= 1 else [hostname]
    registrable = ".".join(base)
    queue = deque([(hostname, 0, "seed")])
    visited = set()
    nodes = []
    edges = []
    all_evidence = []

    while queue and len(nodes) < max_assets:
        current, depth, reason = queue.popleft()
        if current in visited or depth > max_depth:
            continue
        visited.add(current)
        data = collect_target(current, ["dns", "http", "tls", "ct"])
        all_evidence.extend(data["evidence"])
        assets = correlate_evidence(data["target"], data["evidence"])
        nodes.append({
            "target": current, "depth": depth, "reason": reason,
            "confidence": data["confidence"], "evidence_count": data["evidence_count"],
            "assets": [asdict(a) for a in assets],
        })

        candidates = set()
        for e in data["evidence"]:
            if e.get("kind") != "certificate_name":
                continue
            name = str(e.get("value", "")).lower().strip().lstrip("*.")
            if name == registrable or name.endswith("." + registrable):
                candidates.add(name)

        for candidate in sorted(candidates):
            if candidate == current or candidate in visited:
                continue
            if len(visited) + len(queue) >= max_assets:
                break
            edges.append({
                "source": current, "target": candidate,
                "relationship": "certificate-derived",
                "confidence": 88, "depth": depth + 1,
                "evidence": "certificate-transparency",
            })
            queue.append((candidate, depth + 1, "certificate-derived"))

    correlated = correlate_evidence(hostname, all_evidence)
    return {
        "seed": hostname,
        "max_depth": max_depth,
        "max_assets": max_assets,
        "nodes": nodes,
        "edges": edges,
        "assets": [asdict(a) for a in correlated],
        "summary": {
            "discovered_targets": len(nodes),
            "candidate_relationships": len(edges),
            "evidence_count": len(all_evidence),
            "max_depth_reached": max([n["depth"] for n in nodes], default=0),
        },
    }
