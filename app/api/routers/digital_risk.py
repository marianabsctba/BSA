from fastapi import APIRouter, HTTPException, Request

from ...auth import audit
from ...digital_risk import (
    BrandAnalysis,
    DigitalRiskEvent,
    InfrastructureIndicator,
    LeakSignal,
    analyze_brand_impersonation,
    analyze_leak_signal,
    build_infrastructure_links,
    list_events,
    summarize_events,
    upsert_event,
)
from ...leak_intelligence import enrich_leak_intelligence
from ...local_ai import analyze_brand_context, analyze_infrastructure_cluster
from ..dependencies import require
from ..tenant_scope import tenant_scope


router=APIRouter()



@router.post("/api/v1/digital-risk/infrastructure/analyze")
def digital_risk_infrastructure(payload: InfrastructureIndicator, request: Request):
    principal=require(request,"assets:read")
    result=build_infrastructure_links(payload)
    ai=analyze_infrastructure_cluster(payload.indicator,result["links"])
    if ai:
        result["ai_analysis"]=ai
    event=upsert_event(
        principal.tenant_id,
        {
            "category":"infrastructure_cluster",
            "title":f"Infrastructure correlation for {payload.indicator}",
            "indicator":payload.indicator,
            "source":payload.source,
            "severity":"medium" if result["cluster_strength"]>=60 else "low",
            "confidence":result["cluster_strength"],
            "evidence":result,
            "status":"open",
        },
    )
    result["event_id"]=event["event_id"]
    return result


@router.post("/api/v1/digital-risk/brand/analyze")
def digital_risk_brand_analyze(payload: BrandAnalysis, request: Request):
    principal=require(request,"assets:read")
    result=analyze_brand_impersonation(principal.tenant_id,payload)
    ai=analyze_brand_context(payload.brand,payload.indicator,result["evidence"])
    if ai:
        result["ai_analysis"]=ai
    if result["verdict"]=="likely_impersonation":
        event=upsert_event(
            principal.tenant_id,
            {
                "category":"brand_abuse",
                "title":f"Possible {payload.brand} impersonation",
                "indicator":payload.indicator,
                "source":"bsa_brand_engine",
                "severity":"high" if result["score"]>=85 else "medium",
                "confidence":result["score"],
                "evidence":result["evidence"],
                "status":"open",
                "brand":payload.brand,
            },
        )
        result["event_id"]=event["event_id"]
    return result


@router.get("/api/v1/digital-risk")
def digital_risk(request: Request, category: str|None=None):
    principal=require(request,"assets:read")
    events=list_events(principal.tenant_id,category)
    ordered=sorted(
        events,
        key=lambda event:(
            int(event.get("risk_score",0)),
            int(event.get("confidence",0)),
        ),
        reverse=True,
    )
    return {
        "events":ordered,
        "summary":summarize_events(events),
        "top_risk":ordered[:10],
    }


@router.post("/api/v1/digital-risk/leaks")
def digital_risk_leak_ingest(payload: LeakSignal, request: Request):
    principal=require(request,"assets:write")
    analyzed=analyze_leak_signal(payload)
    assets,_=tenant_scope(principal)
    asset=None
    if analyzed.get("asset_id"):
        asset=next((item for item in assets if item.id==analyzed["asset_id"]),None)
        if asset is None:
            raise HTTPException(status_code=404,detail="asset not found")
    elif payload.domain:
        domain=payload.domain.lower().strip()
        asset=next(
            (
                item
                for item in assets
                if str(item.value).lower()==domain
                or str(item.value).lower().endswith("."+domain)
            ),
            None,
        )
        if asset:
            analyzed["asset_id"]=asset.id
    analyzed["title"]=(
        f"Credential exposure linked to {asset.value if asset else payload.domain or payload.indicator}"
        if analyzed["category"]=="credential_leak"
        else f"External leak signal for {asset.value if asset else payload.domain or payload.indicator}"
    )
    analyzed=enrich_leak_intelligence(
        principal.tenant_id,
        payload,
        analyzed,
        list_events(principal.tenant_id),
    )
    item=upsert_event(principal.tenant_id,analyzed)
    audit(
        principal,
        "create",
        "digital_risk.leak",
        item["event_id"],
        {
            "category":item["category"],
            "asset_id":item.get("asset_id"),
            "risk_score":item.get("risk_score"),
            "account_count":item.get("account_count",0),
            "secret_count":item.get("secret_count",0),
            "leak_subtype":item.get("leak_subtype"),
            "occurrence_count":item.get("occurrence_count",1),
            "lifecycle_state":item.get("lifecycle_state"),
        },
    )
    return item


@router.post("/api/v1/digital-risk/events")
def digital_risk_ingest(payload: DigitalRiskEvent, request: Request):
    principal=require(request,"assets:write")
    item=upsert_event(principal.tenant_id,payload.model_dump())
    audit(
        principal,
        "create",
        "digital_risk",
        item["event_id"],
        {"category":item["category"],"source":item["source"]},
    )
    return item
