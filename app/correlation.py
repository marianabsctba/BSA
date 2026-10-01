from dataclasses import dataclass
from hashlib import sha256
from urllib.parse import urlparse

from .models import AssetType
from .asset_identity import evidence_reference, normalize_asset_value, provenance_confidence


@dataclass(frozen=True)
class CorrelatedAsset:
    fingerprint: str
    value: str
    asset_type: str
    confidence: int
    sources: tuple[str, ...]
    evidence_count: int
    tags: tuple[str, ...]
    evidence_refs: tuple[str, ...] = ()


def _fingerprint(asset_type: str, value: str) -> str:
    return sha256(f"{asset_type}:{value.lower()}".encode()).hexdigest()[:16]


def correlate_evidence(target: str, evidence: list[dict]) -> list[CorrelatedAsset]:
    """Collapse duplicate observations into stable asset identities."""
    grouped: dict[tuple[str, str], dict] = {}

    def add(asset_type: str, value: str, source: str, confidence: int, tags=(), evidence_ref: str | None = None):
        normalized = normalize_asset_value(asset_type, value)
        if not normalized:
            return
        key = (asset_type, normalized)
        item = grouped.setdefault(
            key,
            {"sources": set(), "confidence": [], "count": 0, "tags": set(), "evidence_refs": set()},
        )
        item["sources"].add(source)
        item["confidence"].append(confidence)
        item["count"] += 1
        item["tags"].update(tags)
        if evidence_ref:
            item["evidence_refs"].add(evidence_ref)

    add(
        AssetType.DOMAIN.value,
        target,
        "target",
        100,
        ("seed",),
        f"target:domain:{normalize_asset_value(AssetType.DOMAIN.value, target)}",
    )
    for item in evidence:
        source = str(item.get("source", "unknown"))
        value = str(item.get("value", "")).strip()
        kind = str(item.get("kind", ""))
        confidence = int(item.get("confidence", 0) or 0)
        evidence_ref = evidence_reference(item, source, kind, value)

        if kind == "certificate_name":
            add(
                AssetType.SUBDOMAIN.value,
                value,
                source,
                confidence,
                ("certificate-derived",),
                evidence_ref,
            )
        elif kind == "http_status" or kind.startswith("http_header:") or kind.startswith("security_header:") or kind in {"page_title","body_sha256","redirect_chain"} or kind.startswith("technology:"):
            host = urlparse(str(item.get("subject", ""))).hostname or value
            add(AssetType.APPLICATION.value, host, source, confidence, ("web-exposed",), evidence_ref)
            if kind == "redirect_chain":
                for hop in str(value).split(" -> "):
                    host2=urlparse(hop).hostname
                    if host2:
                        add(AssetType.DOMAIN.value, host2, source, confidence, ("redirect-derived",), evidence_ref)
        elif kind in {"a", "aaaa", "a_record", "aaaa_record"}:
            add(AssetType.IP.value, value, source, confidence, ("dns-resolved",), evidence_ref)
        elif kind in {"cname", "mx", "ns", "srv", "txt", "caa"}:
            add(AssetType.SERVICE.value, value, source, confidence, ("dns-related",), evidence_ref)
        elif kind == "openapi_endpoint":
            host = urlparse(str(item.get("subject", ""))).hostname
            if host:
                add(AssetType.APPLICATION.value, host, source, confidence, ("api-surface", "openapi-observed"), evidence_ref)
        elif kind in {"potential_secret_exposure", "source_map_analyzed", "web_artifact:json", "web_artifact:xml", "web_artifact:yaml", "web_artifact:text"}:
            host = urlparse(str(item.get("subject", ""))).hostname
            if host:
                add(AssetType.APPLICATION.value, host, source, confidence, ("web-artifact",), evidence_ref)

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
                "evidence_refs": set(),
            },
        )
        current["types"].append(asset_type)
        current["sources"].update(item["sources"])
        current["confidence"].extend(item["confidence"])
        current["count"] += item["count"]
        current["tags"].update(item["tags"])
        current["evidence_refs"].update(item["evidence_refs"])

    result = []
    for value, item in sorted(merged.items()):
        asset_type = max(item["types"], key=lambda t: type_priority.get(t, 0))
        avg = provenance_confidence(item["confidence"], len(item["sources"]), item["count"])
        result.append(
            CorrelatedAsset(
                fingerprint=_fingerprint(asset_type, value),
                value=value,
                asset_type=asset_type,
                confidence=avg,
                sources=tuple(sorted(item["sources"])),
                evidence_count=item["count"],
                tags=tuple(sorted(item["tags"])),
                evidence_refs=tuple(sorted(item["evidence_refs"])),
            )
        )
    return result
