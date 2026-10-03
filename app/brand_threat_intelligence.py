"""Brand/VIP threat correlation for DRP.

Keeps attribution conservative: campaign grouping is evidence-based and does
not claim actor identity without an explicit source.
"""
from __future__ import annotations

import hashlib
import re
from typing import Any
from urllib.parse import urlparse


def _norm(value: str | None) -> str:
    return re.sub(r"[^a-z0-9]", "", str(value or "").lower())


def _host(indicator: str) -> str:
    raw=str(indicator or "").strip()
    if not raw:
        return ""
    parsed=urlparse(raw if "://" in raw else f"https://{raw}")
    return (parsed.hostname or raw).lower().strip(".")


def _classify(indicator: str, evidence: dict[str, Any]) -> str:
    hint=" ".join(
        str(value or "").lower()
        for value in (
            evidence.get("kind"),
            evidence.get("channel"),
            evidence.get("source_type"),
            evidence.get("platform"),
            evidence.get("artifact_type"),
        )
    )
    host=_host(indicator)
    if any(token in hint for token in ("social", "profile", "account")):
        return "fake_profile"
    if any(token in hint for token in ("mobile", "apk", "app", "store")):
        return "fake_app"
    if any(token in hint for token in ("phishing", "credential-harvest", "credential_harvest")):
        return "phishing"
    if host:
        return "lookalike_domain"
    return "impersonation"


def _brand_similarity(indicator: str, brand: str) -> int:
    host=_norm(_host(indicator))
    target=_norm(brand)
    if not host or not target:
        return 0
    if target in host:
        return 100
    overlap=len(set(host) & set(target)) / max(1, len(set(target)))
    prefix=0
    for left,right in zip(host,target):
        if left!=right:
            break
        prefix+=1
    prefix_score=round(prefix/max(1,len(target))*100)
    return max(round(overlap*70),prefix_score)


def build_brand_threat(
    *,
    tenant_id: str,
    indicator: str,
    brand: str,
    evidence: dict[str, Any] | None=None,
    confidence: int=70,
    visual_similarity: int | None=None,
    text_similarity: int | None=None,
    vip: str | None=None,
    prior_events: list[dict[str, Any]] | None=None,
) -> dict[str, Any]:
    evidence=dict(evidence or {})
    prior_events=list(prior_events or [])
    confidence=max(0,min(100,int(confidence or 0)))
    lexical=_brand_similarity(indicator,brand)
    text=max(0,min(100,int(text_similarity))) if text_similarity is not None else lexical
    visual=max(0,min(100,int(visual_similarity))) if visual_similarity is not None else None
    threat_type=_classify(indicator,evidence)

    signals=[]
    if lexical>=70: signals.append("brand_lookalike")
    if text>=70: signals.append("brand_text_similarity")
    if visual is not None and visual>=75: signals.append("brand_visual_similarity")
    if vip: signals.append("vip_target")
    if threat_type=="phishing": signals.append("phishing_signal")

    score=round(confidence*0.35 + text*0.25 + lexical*0.20 + ((visual or 0)*0.20))
    if vip:
        score+=8
    if threat_type in {"phishing","fake_app"}:
        score+=7
    score=max(0,min(100,score))

    campaign_material="|".join(sorted(filter(None,[
        _norm(brand),
        _norm(vip),
        _norm(str(evidence.get("infrastructure_fingerprint") or "")),
        _norm(str(evidence.get("certificate_sha256") or "")),
        _norm(str(evidence.get("nameserver") or "")),
        _norm(str(evidence.get("registrar") or "")),
    ]))) or f"{tenant_id}|{_norm(brand)}|{_norm(vip)}"
    campaign_key=hashlib.sha256(campaign_material.encode()).hexdigest()[:20]

    related=[]
    for event in prior_events:
        if str(event.get("campaign_key") or "")==campaign_key:
            related.append(str(event.get("event_id") or ""))
        elif _norm(str(event.get("brand") or ""))==_norm(brand) and _norm(str(event.get("vip_target") or ""))==_norm(vip):
            related.append(str(event.get("event_id") or ""))
    related=[item for item in related if item]

    takedown_candidate=score>=75 and len(signals)>=2
    return {
        "threat_type":threat_type,
        "brand":brand,
        "vip_target":vip,
        "campaign_key":campaign_key,
        "campaign_event_count":len(set(related))+1,
        "related_event_ids":sorted(set(related)),
        "lexical_similarity":lexical,
        "text_similarity":text,
        "visual_similarity":visual,
        "confidence":confidence,
        "risk_score":score,
        "signals":signals,
        "takedown_candidate":takedown_candidate,
        "human_review_required":True,
        "attribution":"unattributed",
    }
