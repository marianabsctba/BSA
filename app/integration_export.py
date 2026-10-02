"""Vendor-neutral outbound integration contracts for SIEM/SOAR consumers."""

from __future__ import annotations

from dataclasses import asdict
from datetime import datetime, timezone

from .risk_engine import assess_risk


def _iso_ts(value: str | None) -> str:
    raw=str(value or "").strip()
    if raw:
        return raw
    return datetime.now(timezone.utc).isoformat()


def siem_events(tenant_id: str, assets: list, findings: list, *, since: str | None = None, limit: int = 500) -> dict:
    """Build a stable, vendor-neutral event stream without leaking engine identities."""
    limit=max(1,min(1000,int(limit or 500)))
    asset_map={a.id:a for a in assets if getattr(a,"tenant_id",tenant_id)==tenant_id}
    events=[]

    for finding in findings:
        if getattr(finding,"tenant_id",tenant_id)!=tenant_id:
            continue
        observed_at=_iso_ts(getattr(finding,"detected_at",None))
        if since and observed_at <= since:
            continue
        asset=asset_map.get(finding.asset_id)
        risk=assess_risk(finding,asset)
        events.append({
            "schema_version":"1.0",
            "event_type":"exposure.finding",
            "event_id":f"finding:{finding.id}",
            "observed_at":observed_at,
            "tenant_id":tenant_id,
            "asset":{
                "id":asset.id if asset else finding.asset_id,
                "value":asset.value if asset else None,
                "type":asset.type.value if asset else None,
                "criticality":asset.criticality if asset else None,
                "tags":list(asset.tags) if asset else [],
            },
            "finding":{
                "id":finding.id,
                "title":finding.title,
                "severity":finding.severity.value,
                "status":finding.status,
                "confidence":finding.confidence,
                "vulnerability_id":finding.vulnerability_id,
                "cvss":finding.cvss,
                "epss":finding.epss,
                "kev":finding.kev,
                "validation_state":finding.validation_state,
                "evidence_quality":finding.evidence_quality,
                "independent_source_count":finding.independent_source_count,
                "independently_corroborated":finding.independently_corroborated,
                "affected_components":list(finding.affected_components),
            },
            "risk":asdict(risk),
            "source":"be-safe-asm",
        })

    events.sort(key=lambda x:(x["observed_at"],x["event_id"]))
    page=events[:limit]
    next_cursor=page[-1]["observed_at"] if len(events)>len(page) and page else None
    return {
        "schema_version":"1.0",
        "tenant_id":tenant_id,
        "count":len(page),
        "next_cursor":next_cursor,
        "events":page,
    }
