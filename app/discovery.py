from dataclasses import asdict
from urllib.parse import urlparse
from collections import deque
import os
import threading
import tldextract

from .collectors.dns import DNSCollector
from .collectors.http import HTTPCollector
from .collectors.tls import TLSCollector
from .collectors.certificate_transparency import CertificateTransparencyCollector
from .collectors.ports import PortCollector
from .collectors.rdap import RDAPCollector
from .collectors.ip_intel import IPIntelCollector
from .correlation import correlate_evidence
from .security import validate_external_target, resolve_public
from .local_ai import prioritize_collection
from .collectors.http import discover_web_surface, contextual_surface_paths

_PSL_EXTRACTOR=tldextract.TLDExtract(suffix_list_urls=())

def registrable_domain(hostname: str) -> str:
    ext=_PSL_EXTRACTOR(hostname.rstrip(".").lower())
    if not ext.domain or not ext.suffix:
        return hostname.rstrip(".").lower()
    return ext.top_domain_under_public_suffix.lower()


MAX_DISCOVERY_CONCURRENCY = max(1, min(int(os.getenv("BSA_MAX_DISCOVERY_CONCURRENCY", "4")), 32))
_DISCOVERY_GATE = threading.BoundedSemaphore(MAX_DISCOVERY_CONCURRENCY)


COLLECTORS = {
    "dns": DNSCollector(),
    "http": HTTPCollector(),
    "tls": TLSCollector(),
    "ct": CertificateTransparencyCollector(),
    "ports": PortCollector(),
    "rdap": RDAPCollector(),
    "ip_intel": IPIntelCollector(),
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
    validate_external_target(target)
    approved_ips=resolve_public(hostname)
    if not _DISCOVERY_GATE.acquire(timeout=10):
        raise RuntimeError("discovery capacity temporarily exhausted")
    try:
        selected = checks or ["dns", "http", "tls", "ct", "ports", "rdap", "ip_intel"]
        evidence = []

        if "dns" in selected:
            evidence.extend(COLLECTORS["dns"].collect(hostname))

        if "http" in selected:
            evidence.extend(COLLECTORS["http"].collect(url,approved_ips=approved_ips))

        if "tls" in selected:
            try:
                evidence.extend(COLLECTORS["tls"].collect(hostname))
            except (OSError, ValueError):
                pass

        if "ct" in selected:
            evidence.extend(COLLECTORS["ct"].collect(hostname))

        if "ports" in selected:
            evidence.extend(COLLECTORS["ports"].collect(hostname,approved_ips=approved_ips))

        if "rdap" in selected:
            evidence.extend(COLLECTORS["rdap"].collect(hostname))

        if "ip_intel" in selected:
            for e in list(evidence):
                if e.get("kind") in {"a_record","aaaa"}:
                    evidence.extend(COLLECTORS["ip_intel"].collect(str(e.get("value"))))

        return {
            "target": hostname,
        "url": url,
        "checks": selected,
        "evidence": [asdict(item) for item in evidence],
        "evidence_count": len(evidence),
            "confidence": round(sum(e.confidence for e in evidence) / len(evidence)) if evidence else 0,
        }
    finally:
        _DISCOVERY_GATE.release()


def discover_surface(seed: str, max_depth: int = 2, max_assets: int = 40, scope_validator=None) -> dict:
    """Bounded passive EASM expansion from an explicit in-scope seed.

    Only certificate-derived names inside the seed's registrable domain are
    eligible for expansion. External redirect/related names are reported but
    never recursively scanned.
    """
    hostname, _ = normalize_target(seed)
    validate_external_target(seed)
    registrable = registrable_domain(hostname)
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
        try:
            data["evidence"].extend(asdict(e) for e in discover_web_surface(data["url"], max_paths=40, max_js=20))
            contextual=contextual_surface_paths(data["evidence"])
            for path in contextual[:80]:
                try:
                    extra=discover_web_surface(data["url"].rstrip("/")+path,max_paths=1,max_js=5)
                    data["evidence"].extend(asdict(e) for e in extra)
                except (OSError, ValueError):
                    continue
            data["evidence_count"]=len(data["evidence"])
            data["confidence"]=round(sum(int(e.get("confidence",0)) for e in data["evidence"])/len(data["evidence"])) if data["evidence"] else 0
        except (OSError, ValueError):
            pass
        all_evidence.extend(data["evidence"])
        artifact_candidates = set()
        for e in data["evidence"]:
            if e.get("kind") != "discovery_candidate":
                continue
            try:
                candidate_host, _ = normalize_target(str(e.get("value", "")))
            except ValueError:
                continue
            if candidate_host == registrable or candidate_host.endswith("." + registrable):
                artifact_candidates.add(candidate_host)
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

        candidates.update(artifact_candidates)
        for candidate in sorted(candidates):
            if scope_validator is not None and not scope_validator(candidate):
                continue
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

def adaptive_discovery(seed: str, max_rounds: int = 3, max_assets: int = 40) -> dict:
    """Evidence-driven bounded discovery with explicit candidate provenance.

    The adaptive loop may change collector selection, but it never expands scope
    blindly. Candidate hosts are emitted from observed evidence and remain
    bounded by max_assets; callers can decide whether to validate/collect them.
    """
    hostname, _ = normalize_target(seed)
    validate_external_target(seed)
    registrable = registrable_domain(hostname)
    rounds=[]
    accumulated=[]
    candidates: dict[str, dict] = {}
    selected=["dns","http","tls","ct"]
    limit=max(1, min(int(max_assets), 500))

    for round_no in range(1, max(1, min(int(max_rounds), 5)) + 1):
        data=collect_target(hostname, selected)
        accumulated.extend(data["evidence"])

        for e in data["evidence"]:
            kind=str(e.get("kind",""))
            value=str(e.get("value","")).strip()
            if kind not in {"certificate_name", "discovery_candidate"} or not value:
                continue
            try:
                candidate,_=normalize_target(value)
            except ValueError:
                continue
            if candidate == hostname or not (candidate == registrable or candidate.endswith("." + registrable)):
                continue
            ref=evidence_reference(e, str(e.get("source","unknown")), kind, value)
            item=candidates.setdefault(candidate, {"value":candidate, "reasons":set(), "evidence_refs":set(), "confidence":[]})
            item["reasons"].add(kind)
            item["evidence_refs"].add(ref)
            item["confidence"].append(int(e.get("confidence",0) or 0))
            if len(candidates) >= limit:
                break

        signals=[{"kind":e.get("kind"),"value":e.get("value"),"confidence":e.get("confidence")}
                 for e in data["evidence"]
                 if e.get("kind") in {"http_status","certificate_name","a_record","aaaa","openapi_endpoint"}]
        ai=prioritize_collection(hostname,data["evidence"],signals,
                                 ["dns","http","tls","ct","ports","rdap","ip_intel"])
        rounds.append({
            "round":round_no,
            "checks":selected,
            "evidence_count":len(data["evidence"]),
            "candidate_count":len(candidates),
            "ai_prioritization":ai,
        })
        if len(candidates) >= limit or not ai or not ai.get("priorities"):
            break

        proposed=[]
        for item in ai.get("priorities",[]):
            check=item.get("check") if isinstance(item,dict) else None
            if check in {"dns","http","tls","ct","ports","rdap","ip_intel"} and check not in proposed:
                proposed.append(check)
        if not proposed or proposed==selected:
            break
        selected=proposed

    candidate_list=[]
    for item in candidates.values():
        scores=item["confidence"]
        candidate_list.append({
            "value":item["value"],
            "reasons":sorted(item["reasons"]),
            "evidence_refs":sorted(item["evidence_refs"]),
            "confidence":provenance_confidence(scores, len(item["reasons"]), len(item["evidence_refs"])),
        })
    candidate_list.sort(key=lambda x:(x["confidence"], x["value"]), reverse=True)

    return {
        "seed":hostname,
        "rounds":rounds,
        "evidence_count":len(accumulated),
        "candidates":candidate_list[:limit],
        "max_rounds":max_rounds,
        "max_assets":max_assets,
    }
