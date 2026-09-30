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
        elif kind == "http_status" or kind.startswith("http_header:") or kind.startswith("security_header:"):
            host = urlparse(str(item.get("subject", ""))).hostname or value
            add(AssetType.APPLICATION.value, host, source, confidence, ("web-exposed",))
        elif kind in {"a", "aaaa"}:
            add(AssetType.IP.value, value, source, confidence, ("dns-resolved",))
        elif kind in {"cname", "mx", "ns"}:
            add(AssetType.SERVICE.value, value, source, confidence, ("dns-related",))

    result = []
    for (asset_type, value), item in sorted(grouped.items()):
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
