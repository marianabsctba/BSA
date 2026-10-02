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


def drp_siem_events(tenant_id: str, events: list[dict], *, since: str | None=None, limit: int=500) -> list[dict]:
    out=[]
    for event in events:
        observed_at=_iso_ts(event.get("last_seen") or event.get("first_seen") or event.get("updated_at"))
        if since and observed_at <= since:
            continue
        safe_evidence=event.get("evidence") if isinstance(event.get("evidence"),dict) else {}
        out.append({
            "schema_version":"1.0",
            "event_type":"digital_risk."+str(event.get("category") or "event"),
            "event_id":"drp:"+str(event.get("event_id") or ""),
            "observed_at":observed_at,
            "tenant_id":tenant_id,
            "indicator":event.get("indicator"),
            "asset_id":event.get("asset_id"),
            "brand":event.get("brand"),
            "severity":event.get("severity"),
            "confidence":event.get("confidence"),
            "risk":{
                "score":event.get("risk_score"),
                "band":event.get("risk_band"),
                "reasons":event.get("risk_reasons") or [],
            },
            "status":event.get("status"),
            "source_name":event.get("source"),
            "evidence_count":event.get("evidence_count",len(safe_evidence)),
            "source":"be-safe-asm",
        })
    out.sort(key=lambda x:(x["observed_at"],x["event_id"]))
    return out[:max(1,min(1000,int(limit or 500)))]


def unified_siem_events(tenant_id: str, assets: list, findings: list, drp_events: list[dict], *, since: str|None=None, limit: int=500) -> dict:
    limit=max(1,min(1000,int(limit or 500)))
    finding_stream=siem_events(tenant_id,assets,findings,since=since,limit=1000)["events"]
    drp_stream=drp_siem_events(tenant_id,drp_events,since=since,limit=1000)
    events=sorted(finding_stream+drp_stream,key=lambda x:(x["observed_at"],x["event_id"]))
    page=events[:limit]
    next_cursor=page[-1]["observed_at"] if len(events)>len(page) and page else None
    return {
        "schema_version":"1.0",
        "tenant_id":tenant_id,
        "count":len(page),
        "next_cursor":next_cursor,
        "event_types":sorted({x["event_type"] for x in page}),
        "events":page,
    }


def audit_siem_events(audit_rows: list[dict], *, limit: int=500) -> list[dict]:
    out=[]
    for row in audit_rows:
        created_at=int(row.get("created_at") or 0)
        observed_at=datetime.fromtimestamp(created_at,tz=timezone.utc).isoformat() if created_at else datetime.now(timezone.utc).isoformat()
        out.append({
            "schema_version":"1.0",
            "event_type":"audit."+str(row.get("action") or "event"),
            "event_id":"audit:"+str(row.get("tenant_id") or "")+":"+str(row.get("id") or ""),
            "observed_at":observed_at,
            "tenant_id":row.get("tenant_id"),
            "user_id":row.get("user_id"),
            "action":row.get("action"),
            "resource":row.get("resource"),
            "resource_id":row.get("resource_id"),
            "metadata":row.get("metadata"),
            "integrity":{
                "prev_hash":row.get("prev_hash") or "",
                "entry_hash":row.get("entry_hash") or "",
            },
            "source":"be-safe-asm",
        })
    out.sort(key=lambda x:(x["observed_at"],x["event_id"]))
    return out[:max(1,min(1000,int(limit or 500)))]
