from dataclasses import dataclass
from hashlib import sha256
from urllib.parse import urlparse

from .models import AssetType


@dataclass(frozen=True)
class CorrelatedAsset:
    fingerprint: str
    value: str
    asset_type: str
    confidence: int
    sources: tuple[str, ...]
    evidence_count: int
    tags: tuple[str, ...]


def _fingerprint(asset_type: str, value: str) -> str:
    return sha256(f"{asset_type}:{value.lower()}".encode()).hexdigest()[:16]


def correlate_evidence(target: str, evidence: list[dict]) -> list[CorrelatedAsset]:
    """Collapse duplicate observations into stable asset identities."""
    grouped: dict[tuple[str, str], dict] = {}

    def add(asset_type: str, value: str, source: str, confidence: int, tags=()):
        if not value:
            return
        key = (asset_type, value.lower().strip())
        item = grouped.setdefault(key, {"sources": set(), "confidence": [], "count": 0, "tags": set()})
        item["sources"].add(source)
        item["confidence"].append(confidence)
        item["count"] += 1
        item["tags"].update(tags)

    add(AssetType.DOMAIN.value, target, "target", 100, ("seed",))
    for item in evidence:
        source = str(item.get("source", "unknown"))
        value = str(item.get("value", "")).strip()
        kind = str(item.get("kind", ""))
        confidence = int(item.get("confidence", 0) or 0)

        if kind == "certificate_name":
            add(AssetType.SUBDOMAIN.value, value, source, confidence, ("certificate-derived",))
        elif kind == "http_status" or kind.startswith("http_header:") or kind.startswith("security_header:") or kind in {"page_title","body_sha256","redirect_chain"} or kind.startswith("technology:"):
            host = urlparse(str(item.get("subject", ""))).hostname or value
            add(AssetType.APPLICATION.value, host, source, confidence, ("web-exposed",))
            if kind == "redirect_chain":
                for hop in str(value).split(" -> "):
                    host2=urlparse(hop).hostname
                    if host2:
                        add(AssetType.DOMAIN.value, host2, source, confidence, ("redirect-derived",))
        elif kind in {"a", "aaaa", "a_record", "aaaa_record"}:
            add(AssetType.IP.value, value, source, confidence, ("dns-resolved",))
        elif kind in {"cname", "mx", "ns", "srv", "txt", "caa"}:
            add(AssetType.SERVICE.value, value, source, confidence, ("dns-related",))

    # Merge the same hostname observed through different collectors.
    # A web observation upgrades a certificate-only hostname to an application asset
    # while retaining every supporting source and tag.
    merged: dict[str, dict] = {}
    type_priority = {
        AssetType.APPLICATION.value: 3,
        AssetType.SUBDOMAIN.value: 2,
        AssetType.DOMAIN.value: 1,
        AssetType.IP.value: 1,
        AssetType.SERVICE.value: 1,
    }
    for (asset_type, value), item in grouped.items():
        key = value.lower().strip()
        current = merged.setdefault(
            key,
            {
                "types": [],
                "sources": set(),
                "confidence": [],
                "count": 0,
                "tags": set(),
            },
        )
        current["types"].append(asset_type)
        current["sources"].update(item["sources"])
        current["confidence"].extend(item["confidence"])
        current["count"] += item["count"]
        current["tags"].update(item["tags"])

    result = []
    for value, item in sorted(merged.items()):
        asset_type = max(item["types"], key=lambda t: type_priority.get(t, 0))
        avg = round(sum(item["confidence"]) / len(item["confidence"]))
        if len(item["sources"]) >= 3:
            avg = min(100, avg + 5)
        result.append(
            CorrelatedAsset(
                fingerprint=_fingerprint(asset_type, value),
                value=value,
                asset_type=asset_type,
                confidence=avg,
                sources=tuple(sorted(item["sources"])),
                evidence_count=item["count"],
                tags=tuple(sorted(item["tags"])),
            )
        )
    return result
