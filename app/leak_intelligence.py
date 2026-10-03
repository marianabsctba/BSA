"""Leak intelligence enrichment for DRP events.

This module adds product-level context without persisting raw credentials or
secrets. Identity correlation uses a tenant-scoped one-way fingerprint.
"""
from __future__ import annotations

from datetime import datetime, timezone
import hashlib
from typing import Any


_SOURCE_RELIABILITY = {
    "manual": 50,
    "customer": 65,
    "internal": 75,
    "verified": 90,
}


def _parse_time(value: str | None) -> datetime | None:
    raw=str(value or "").strip()
    if not raw:
        return None
    try:
        parsed=datetime.fromisoformat(raw.replace("Z","+00:00"))
    except ValueError:
        return None
    if parsed.tzinfo is None:
        parsed=parsed.replace(tzinfo=timezone.utc)
    return parsed.astimezone(timezone.utc)


def _source_reliability(source: str, evidence: dict[str, Any]) -> int:
    explicit=evidence.get("source_reliability")
    if explicit is not None:
        try:
            return max(0,min(100,int(explicit)))
        except (TypeError,ValueError):
            pass
    normalized=str(source or "manual").strip().lower()
    return _SOURCE_RELIABILITY.get(normalized,60)


def _leak_subtype(leak_type: str, source: str, evidence: dict[str, Any]) -> str:
    hint=" ".join(
        str(value or "").lower()
        for value in (
            source,
            evidence.get("kind"),
            evidence.get("source_type"),
            evidence.get("collector"),
        )
    )
    if "stealer" in hint or "infostealer" in hint:
        return "stealer_log"
    return {
        "credential":"credential_dump",
        "combo":"combo_list",
        "data":"data_breach",
        "secret":"secret_material",
        "token":"token_exposure",
    }.get(str(leak_type or "").lower(),"unknown")


def _identity_fingerprint(tenant_id: str, indicator: str) -> str:
    normalized=str(indicator or "").strip().lower()
    material=f"{tenant_id}|{normalized}".encode()
    return hashlib.sha256(material).hexdigest()[:24]


def _same_identity(event: dict[str, Any], fingerprint: str) -> bool:
    return str(event.get("identity_fingerprint") or "")==fingerprint


def enrich_leak_intelligence(
    tenant_id: str,
    payload: Any,
    analyzed: dict[str, Any],
    prior_events: list[dict[str, Any]] | None=None,
    *,
    now: datetime | None=None,
) -> dict[str, Any]:
    """Add recurrence, source quality, recency and lifecycle to a leak event."""
    prior_events=list(prior_events or [])
    now=(now or datetime.now(timezone.utc)).astimezone(timezone.utc)
    evidence=analyzed.get("evidence") if isinstance(analyzed.get("evidence"),dict) else {}
    source=str(analyzed.get("source") or getattr(payload,"source","manual") or "manual")
    leak_type=str(getattr(payload,"leak_type","") or "")
    indicator=str(analyzed.get("indicator") or getattr(payload,"indicator","") or "")
    fingerprint=_identity_fingerprint(tenant_id,indicator)

    related=[event for event in prior_events if _same_identity(event,fingerprint)]
    occurrence_count=len(related)+1
    recurring=occurrence_count>1

    observed=_parse_time(analyzed.get("last_seen")) or _parse_time(analyzed.get("first_seen"))
    age_days=max(0,(now-observed).days) if observed else None
    if age_days is None:
        recency="unknown"
    elif age_days<=7:
        recency="fresh"
    elif age_days<=30:
        recency="recent"
    elif age_days<=180:
        recency="aging"
    else:
        recency="stale"

    reliability=_source_reliability(source,evidence)
    subtype=_leak_subtype(leak_type,source,evidence)
    base_score=int(analyzed.get("risk_score",0) or 0)
    recurrence_bonus=min(12,max(0,occurrence_count-1)*4)
    recency_bonus={"fresh":10,"recent":6,"aging":2,"stale":-8,"unknown":0}[recency]
    source_adjustment=round((reliability-50)*0.20)
    score=max(0,min(100,base_score+recurrence_bonus+recency_bonus+source_adjustment))
    if score>=85:
        band="critical"
    elif score>=70:
        band="high"
    elif score>=45:
        band="medium"
    else:
        band="low"

    previous_states={str(event.get("lifecycle_state") or event.get("status") or "") for event in related}
    resurfaced=bool(previous_states & {"resolved","contained"})
    lifecycle="resurfaced" if resurfaced else ("recurring" if recurring else "new")

    reasons=list(analyzed.get("risk_reasons") or [])
    reasons.extend([
        f"leak_subtype:{subtype}",
        f"source_reliability:{reliability}",
        f"occurrences:{occurrence_count}",
        f"recency:{recency}",
    ])

    return {
        **analyzed,
        "leak_subtype":subtype,
        "source_reliability":reliability,
        "identity_fingerprint":fingerprint,
        "occurrence_count":occurrence_count,
        "recurring":recurring,
        "recency":recency,
        "age_days":age_days,
        "lifecycle_state":lifecycle,
        "risk_score":score,
        "risk_band":band,
        "risk_reasons":reasons,
        "contains_raw_secret":False,
    }
