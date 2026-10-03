"""Digital Risk Protection / CTI layer for BSA.

Vendor-neutral primitives inspired by current DRP/EASM market patterns:
brand abuse, phishing, leaks, VIP exposure, dark web and supply chain.
"""
import hashlib
import time
import uuid

from pydantic import BaseModel, Field

from .assessment_engine import mask_public_data
from .repositories.digital_risk_events import digital_risk_repository


class DigitalRiskEvent(BaseModel):
    category: str
    title: str
    indicator: str
    source: str="manual"
    severity: str="medium"
    confidence: int=70
    evidence: dict={}
    first_seen: str=""
    last_seen: str=""
    status: str="open"
    asset_id: str|None=None
    brand: str|None=None
    actor: str|None=None


SEVERITY_WEIGHT={"info":5,"low":20,"medium":45,"high":70,"critical":90}
CREDENTIAL_CATEGORIES={"credential_leak","credentials","leak","data_leak"}


def _normalized_event(event: dict) -> dict:
    category=str(event.get("category") or "unknown").strip().lower()
    severity=str(event.get("severity") or "medium").strip().lower()
    if severity not in SEVERITY_WEIGHT:
        severity="medium"
    confidence=max(0,min(100,int(event.get("confidence",70) or 70)))
    status=str(event.get("status") or "open").strip().lower()
    indicator=str(event.get("indicator") or "").strip()
    source=str(event.get("source") or "manual").strip() or "manual"
    brand=str(event.get("brand") or "").strip() or None
    asset_id=str(event.get("asset_id") or "").strip() or None
    evidence=event.get("evidence") if isinstance(event.get("evidence"),dict) else {}
    return {
        **event,
        "category":category,
        "severity":severity,
        "confidence":confidence,
        "status":status,
        "indicator":indicator,
        "source":source,
        "brand":brand,
        "asset_id":asset_id,
        "evidence":evidence,
    }


def event_correlation_key(event: dict) -> str:
    normalized=_normalized_event(event)
    raw="|".join([
        normalized["category"],
        normalized["indicator"].lower(),
        str(normalized.get("brand") or "").lower(),
        str(normalized.get("asset_id") or "").lower(),
    ])
    return hashlib.sha256(raw.encode()).hexdigest()[:24]


def event_risk(event: dict) -> dict:
    e=_normalized_event(event)
    base=SEVERITY_WEIGHT[e["severity"]]
    confidence_component=round(e["confidence"]*0.35)
    evidence_count=len(e.get("evidence") or {})
    evidence_component=min(12,evidence_count*3)
    asset_component=8 if e.get("asset_id") else 0
    credential_component=10 if e["category"] in CREDENTIAL_CATEGORIES else 0
    score=max(0,min(100,round(base*0.55+confidence_component+evidence_component+asset_component+credential_component)))
    if score>=85: band="critical"
    elif score>=70: band="high"
    elif score>=45: band="medium"
    else: band="low"
    reasons=[
        f"severity:{e['severity']}",
        f"confidence:{e['confidence']}",
    ]
    if evidence_count: reasons.append(f"evidence:{evidence_count}")
    if e.get("asset_id"): reasons.append("linked_asset")
    if e["category"] in CREDENTIAL_CATEGORIES: reasons.append("credential_exposure")
    return {
        "score":score,
        "band":band,
        "reasons":reasons,
        "evidence_count":evidence_count,
    }


def enrich_event(event: dict) -> dict:
    e=_normalized_event(event)
    risk=event_risk(e)
    specialized_score=None
    if e.get("risk_score") is not None:
        try:
            specialized_score=max(0,min(100,int(e["risk_score"])))
        except (TypeError,ValueError):
            specialized_score=None
    score=max(risk["score"],specialized_score or 0)
    if score>=85: band="critical"
    elif score>=70: band="high"
    elif score>=45: band="medium"
    else: band="low"
    specialized_reasons=e.get("risk_reasons") if isinstance(e.get("risk_reasons"),list) else []
    reasons=list(dict.fromkeys([
        *[str(reason) for reason in specialized_reasons if reason],
        *risk["reasons"],
    ]))
    return {
        **e,
        "correlation_key":event_correlation_key(e),
        "risk_score":score,
        "risk_band":band,
        "risk_reasons":reasons,
        "evidence_count":risk["evidence_count"],
    }


def summarize_events(events: list[dict]) -> dict:
    enriched=[enrich_event(x) for x in events]
    by_category={}
    by_severity={}
    by_status={}
    by_source={}
    for e in enriched:
        by_category[e["category"]]=by_category.get(e["category"],0)+1
        by_severity[e["severity"]]=by_severity.get(e["severity"],0)+1
        by_status[e["status"]]=by_status.get(e["status"],0)+1
        by_source[e["source"]]=by_source.get(e["source"],0)+1
    high_risk=[e for e in enriched if int(e.get("risk_score",0))>=70 and e.get("status")=="open"]
    return {
        "total":len(enriched),
        "open":sum(1 for e in enriched if e.get("status")=="open"),
        "critical":sum(1 for e in enriched if e.get("risk_band")=="critical" and e.get("status")=="open"),
        "high_risk_open":len(high_risk),
        "average_risk_score":round(sum(int(e.get("risk_score",0)) for e in enriched)/len(enriched)) if enriched else 0,
        "average_confidence":round(sum(int(e.get("confidence",0)) for e in enriched)/len(enriched)) if enriched else 0,
        "linked_assets":sum(1 for e in enriched if e.get("asset_id")),
        "credential_exposures":sum(1 for e in enriched if e.get("category") in CREDENTIAL_CATEGORIES and e.get("status")=="open"),
        "by_category":by_category,
        "by_severity":by_severity,
        "by_status":by_status,
        "by_source":by_source,
    }


def upsert_event(tenant_id,event):
    now=int(time.time())
    event=enrich_event(event)
    repository=digital_risk_repository()
    eid=event.get("event_id")
    if not eid:
        match=None
        for existing in repository.list(tenant_id):
            if event_correlation_key(existing)==event["correlation_key"]:
                match=existing.get("event_id")
                break
        eid=match or str(uuid.uuid4())
    previous=repository.get(tenant_id,eid)
    created_at=int(previous[1]) if previous else now
    if previous:
        old=previous[0]
        first_seen=old.get("first_seen") or event.get("first_seen") or ""
    else:
        first_seen=event.get("first_seen") or ""
    event=enrich_event({**event,"event_id":eid,"first_seen":first_seen,"updated_at":now})
    repository.put(tenant_id,eid,event,created_at,now)
    return event


def list_events(tenant_id,category=None):
    rows=digital_risk_repository().list(tenant_id,category)
    return [mask_public_data(enrich_event(item)) for item in rows]


class BrandAnalysis(BaseModel):
    indicator: str
    brand: str
    title: str=""
    html_excerpt: str=""
    image_hash: str|None=None
    visual_similarity: int|None=None
    text_similarity: int|None=None


def _similarity(a,b):
    a=set(str(a).lower().split()); b=set(str(b).lower().split())
    return round(len(a&b)/max(1,len(a|b))*100)


def analyze_brand_impersonation(tenant_id, analysis: BrandAnalysis):
    visual=analysis.visual_similarity
    text=analysis.text_similarity if analysis.text_similarity is not None else _similarity(analysis.title,analysis.brand)
    score=round((visual*0.65 + text*0.35)) if visual is not None else text
    reasons=[]
    if visual is not None and visual>=75: reasons.append("high_visual_similarity")
    if text>=60: reasons.append("brand_text_similarity")
    if analysis.indicator.lower().find(analysis.brand.lower().replace(" ",""))>=0: reasons.append("brand_in_indicator")
    verdict="likely_impersonation" if score>=70 and len(reasons)>=1 else ("needs_review" if score>=45 else "low_signal")
    return {"indicator":analysis.indicator,"brand":analysis.brand,"score":score,"visual_similarity":visual,
            "text_similarity":text,"verdict":verdict,"reasons":reasons,
            "evidence":{"html_excerpt":analysis.html_excerpt,"image_hash":analysis.image_hash},
            "human_review_required":verdict!="likely_impersonation"}


class LeakSignal(BaseModel):
    leak_type: str = Field(pattern="^(credential|data|secret|token|combo)$")
    indicator: str
    source: str="manual"
    domain: str|None=None
    asset_id: str|None=None
    account_count: int=Field(default=1,ge=0,le=100000000)
    secret_count: int=Field(default=0,ge=0,le=100000000)
    first_seen: str=""
    last_seen: str=""
    confidence: int=Field(default=70,ge=0,le=100)
    evidence: dict={}


def analyze_leak_signal(item: LeakSignal) -> dict:
    category={
        "credential":"credential_leak",
        "combo":"credential_leak",
        "data":"data_leak",
        "secret":"secret_exposure",
        "token":"secret_exposure",
    }[item.leak_type]
    account_count=max(0,int(item.account_count or 0))
    secret_count=max(0,int(item.secret_count or 0))
    volume=min(100,round((account_count**0.5)*8 + (secret_count**0.5)*12))
    confidence=max(0,min(100,int(item.confidence or 0)))
    score=min(100,round(confidence*0.45 + volume*0.35 + (15 if item.asset_id or item.domain else 0) + (10 if secret_count else 0)))
    if score>=85: severity="critical"
    elif score>=70: severity="high"
    elif score>=45: severity="medium"
    else: severity="low"
    safe_evidence={
        k:v for k,v in (item.evidence or {}).items()
        if str(k).lower() not in {"password","secret","token","credential","raw","value"}
    }
    reasons=[f"type:{item.leak_type}",f"confidence:{confidence}",f"accounts:{account_count}",f"secrets:{secret_count}"]
    if item.domain: reasons.append("linked_domain")
    if item.asset_id: reasons.append("linked_asset")
    return {
        "category":category,
        "indicator":item.indicator,
        "source":item.source,
        "domain":item.domain,
        "asset_id":item.asset_id,
        "account_count":account_count,
        "secret_count":secret_count,
        "confidence":confidence,
        "severity":severity,
        "risk_score":score,
        "risk_band":"critical" if score>=85 else "high" if score>=70 else "medium" if score>=45 else "low",
        "risk_reasons":reasons,
        "evidence":safe_evidence,
        "first_seen":item.first_seen,
        "last_seen":item.last_seen,
        "status":"open",
        "contains_raw_secret":False,
        "human_review_required":True,
    }


class InfrastructureIndicator(BaseModel):
    indicator: str
    indicator_type: str="domain"
    ip: str|None=None
    asn: str|None=None
    registrar: str|None=None
    nameservers: list[str]=[]
    certificate_sha256: str|None=None
    favicon_sha256: str|None=None
    redirect_chain: list[str]=[]
    related_domains: list[str]=[]
    screenshot_hash: str|None=None
    source: str="manual"
    confidence: int=70


def infrastructure_fingerprint(item: InfrastructureIndicator) -> str:
    parts=[item.ip,item.asn,item.registrar,item.certificate_sha256,item.favicon_sha256,item.screenshot_hash,*item.nameservers,*item.related_domains,*item.redirect_chain]
    normalized="|".join(sorted(str(x).strip().lower() for x in parts if x))
    return hashlib.sha256(normalized.encode()).hexdigest()[:20] if normalized else ""


def build_infrastructure_links(item: InfrastructureIndicator):
    links=[]
    for value,kind in [(item.ip,"ip"),(item.asn,"asn"),(item.registrar,"registrar"),(item.certificate_sha256,"certificate"),(item.favicon_sha256,"favicon"),(item.screenshot_hash,"screenshot")]:
        if value: links.append({"type":kind,"value":value,"confidence":item.confidence})
    for ns in item.nameservers: links.append({"type":"nameserver","value":ns,"confidence":item.confidence})
    for domain in item.related_domains: links.append({"type":"related_domain","value":domain,"confidence":item.confidence})
    for target in item.redirect_chain: links.append({"type":"redirect","value":target,"confidence":item.confidence})
    return {"indicator":item.indicator,"indicator_type":item.indicator_type,"infrastructure_fingerprint":infrastructure_fingerprint(item),"links":links,"link_count":len(links),
            "cluster_strength":min(100, round(sum(x["confidence"] for x in links)/max(1,len(links)))),
            "evidence_required":not bool(links)}


def build_infrastructure_graph(item: InfrastructureIndicator):
    nodes=[{"id":"indicator:"+item.indicator,"type":item.indicator_type,"label":item.indicator,"confidence":item.confidence}]
    edges=[]
    seen=set()
    for link in build_infrastructure_links(item)["links"]:
        nid=link["type"]+":"+link["value"]
        if nid in seen: continue
        seen.add(nid)
        nodes.append({"id":nid,"type":link["type"],"label":link["value"],"confidence":link["confidence"]})
        edges.append({"source":"indicator:"+item.indicator,"target":nid,"type":link["type"],"confidence":link["confidence"],"evidence":"explicit_observation"})
    return {"nodes":nodes,"edges":edges,"summary":{"nodes":len(nodes),"edges":len(edges),"avg_edge_confidence":round(sum(e["confidence"] for e in edges)/len(edges)) if edges else 0}}
