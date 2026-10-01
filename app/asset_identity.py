"""Stable asset identity and provenance helpers for the Be Safe ASM correlation layer.

The discovery engine can observe the same asset in several representations
(wildcard certificate names, FQDNs with a trailing dot, URLs, compressed
IPv6, etc.). These helpers normalize those representations without changing
what was actually observed, so correlation can keep a stable identity while
retaining evidence lineage.
"""

from __future__ import annotations

import ipaddress
from urllib.parse import urlparse

from .models import AssetType


def normalize_asset_value(asset_type: str, value: str) -> str:
    """Return the canonical value used for asset identity/correlation."""
    raw = str(value or "").strip()
    if not raw:
        return ""

    if asset_type in {
        AssetType.DOMAIN.value,
        AssetType.SUBDOMAIN.value,
        AssetType.SERVICE.value,
    }:
        # Certificate SANs commonly arrive as *.example.com and DNS FQDNs
        # may carry a terminal dot. Neither should create a second asset.
        raw = raw.lower().strip().lstrip("*.")
        return raw.rstrip(".")

    if asset_type == AssetType.APPLICATION.value:
        parsed = urlparse(raw if "://" in raw else f"https://{raw}")
        hostname = parsed.hostname
        if hostname:
            return hostname.rstrip(".").lower()
        return raw.lower().rstrip(".")

    if asset_type == AssetType.IP.value:
        try:
            return ipaddress.ip_address(raw).compressed
        except ValueError:
            return raw.lower()

    return raw.lower()


def evidence_reference(item: dict, source: str, kind: str, value: str) -> str:
    """Return an explicit evidence reference or a deterministic fallback."""
    metadata = item.get("metadata")
    if isinstance(metadata, dict):
        ref = metadata.get("evidence_ref")
        if ref:
            return str(ref)

    subject = str(item.get("subject", "")).strip()
    if subject:
        return f"{source}:{kind}:{subject}:{value}"

    return f"{source}:{kind}:{value}"


def provenance_confidence(
    confidences: list[int],
    source_count: int,
    evidence_count: int,
) -> int:
    """Calculate bounded confidence while rewarding independent corroboration."""
    if not confidences:
        return 0

    base = round(sum(max(0, min(100, int(x))) for x in confidences) / len(confidences))

    # Independent sources are stronger evidence than repeated observations
    # from one collector. Keep the existing correlation behaviour conservative.
    corroboration = min(10, max(0, source_count - 1) * 3)
    observation_bonus = 2 if evidence_count >= 3 and source_count >= 2 else 0
    return min(100, base + corroboration + observation_bonus)
