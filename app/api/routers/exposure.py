from datetime import datetime, timezone

from fastapi import APIRouter, HTTPException, Request
from pydantic import BaseModel, Field

from ...auth import audit
from ...ctem_store import get_plan, list_plans, upsert_plan
from ...exposure import exposure_band, exposure_breakdown
from ...exposure_dna import build_exposure_dna
from ...graph import build_risk_graph
from ...history import (
    ctem_next_action,
    ctem_verification_history,
    list_ctem_items,
)
from ...intelligence import ownership_confidence
from ...local_ai import (
    OLLAMA_MODEL,
    analyze_exposure,
    enabled as local_ai_enabled,
)
from ...remediation import build_remediation_plan
from ...scope import asset_in_scope
from ...scoring import exposure_score
from ...store import ASSETS as STORE_ASSETS, FINDINGS as STORE_FINDINGS
from ..dependencies import require


router=APIRouter()


def tenant_scope(principal):
    assets=[
        asset
        for asset in STORE_ASSETS
        if getattr(asset,"tenant_id","tenant-demo")==principal.tenant_id
        and asset_in_scope(principal,asset.value)
    ]
    asset_ids={asset.id for asset in assets}
    findings=[
        finding
        for finding in STORE_FINDINGS
        if getattr(finding,"tenant_id","tenant-demo")==principal.tenant_id
        and finding.asset_id in asset_ids
    ]
    return assets,findings


@router.get("/api/v1/exposure/storyline")
def exposure_storyline(request: Request, limit: int=50):
    principal=require(request,"assets:read")
    assets,findings=tenant_scope(principal)
    events=[]
    for asset in assets:
        dna=build_exposure_dna(asset,findings)
        if dna.change_type!="stable":
            events.append({
                "asset_id":asset.id,
                "asset":asset.value,
                "timestamp":asset.last_seen,
                "event":dna.change_type,
                "signals":dna.signals,
                "confidence":dna.confidence,
                "explainability":dna.explainability,
            })
    return {
        "events":sorted(
            events,
            key=lambda item:item["timestamp"],
            reverse=True,
        )[:max(1,min(limit,500))]
    }


@router.get("/api/v1/exposure/copilot")
def exposure_copilot(request: Request, question: str):
    principal=require(request,"assets:read")
    assets,findings=tenant_scope(principal)
    query=question.lower()
    if "owner" in query or "respons" in query:
        rows=[asset for asset in assets if not asset.owner]
        fallback="Ativos sem owner informado."
    elif "mudou" in query or "change" in query or "novo" in query:
        rows=[
            asset
            for asset in assets
            if build_exposure_dna(asset,findings).change_type!="stable"
        ]
        fallback="Ativos com sinais materiais de mudança."
    else:
        rows=sorted(
            assets,
            key=lambda asset:exposure_breakdown(asset,findings).score,
            reverse=True,
        )[:10]
        fallback="Ativos ordenados por exposição contextual."
    evidence=[
        {
            "asset_id":asset.id,
            "asset":asset.value,
            "type":getattr(asset.type,"value",asset.type),
            "confidence":asset.confidence,
            "owner":asset.owner,
            "exposure_score":exposure_breakdown(asset,findings).score,
            "signals":build_exposure_dna(asset,findings).signals,
        }
        for asset in rows
    ]
    ai=analyze_exposure(question,evidence)
    return {
        "answer":ai or fallback,
        "ai":{
            "enabled":local_ai_enabled(),
            "provider":"ollama-local",
            "model":OLLAMA_MODEL if local_ai_enabled() else None,
            "grounded":bool(ai),
            "fallback":not bool(ai),
        },
        "evidence":evidence,
    }


@router.get("/api/v1/exposure/ai/status")
def exposure_ai_status(request: Request):
    require(request,"assets:read")
    return {
        "enabled":local_ai_enabled(),
        "provider":"ollama-local",
        "model":OLLAMA_MODEL if local_ai_enabled() else None,
        "privacy":"local-server",
        "internet_required":False,
    }


@router.get("/api/v1/exposure/ctem/plans")
def exposure_ctem_plans(request: Request):
    principal=require(request,"assets:read")
    return {"items":list_plans(principal.tenant_id)}


class CTEMStatusRequest(BaseModel):
    status:str=Field(
        pattern="^(planned|approved|in_progress|remediated|retest|closed)$"
    )


@router.patch("/api/v1/exposure/ctem/plans/{plan_id}")
def update_ctem_plan(
    plan_id: str,
    payload: CTEMStatusRequest,
    request: Request,
):
    principal=require(request,"assets:read")
    item=get_plan(principal.tenant_id,plan_id)
    if item:
        item["status"]=payload.status
        item["updated_at"]=datetime.now(timezone.utc).isoformat()
        upsert_plan(principal.tenant_id,item)
        audit(
            principal,
            "update",
            "ctem.plan",
            plan_id,
            {"status":payload.status},
        )
        return item
    raise HTTPException(status_code=404,detail="CTEM plan not found")


@router.get("/api/v1/exposure/ctem")
def exposure_ctem(request: Request):
    principal=require(request,"assets:read")
    assets,findings=tenant_scope(principal)
    asset_map={asset.id:asset for asset in assets}
    finding_map={finding.id:finding for finding in findings}
    queue=[]
    persistent=list_ctem_items(principal.tenant_id)
    persistent_asset_ids=set()

    for item in persistent:
        if item.get("state")=="verified":
            continue
        asset=asset_map.get(item.get("asset_id"))
        if not asset:
            continue
        persistent_asset_ids.add(asset.id)
        finding=finding_map.get(item.get("finding_id"))
        verifications=ctem_verification_history(
            item["item_id"],
            principal.tenant_id,
        )
        regression=any(
            verification.get("result")=="failed"
            for verification in verifications
        )
        state=str(item.get("state") or "new")
        stage=(
            "retest"
            if state=="resolved"
            else "prioritize"
            if state in {"acknowledged","in_progress"}
            else "validate"
        )
        next_action=ctem_next_action(item)
        queue.append({
            "item_id":item["item_id"],
            "asset_id":asset.id,
            "asset":asset.value,
            "finding_id":item.get("finding_id"),
            "finding":finding.title if finding else item.get("title"),
            "priority_score":int(item.get("priority",0) or 0),
            "criticality":asset.criticality,
            "owner":asset.owner,
            "finding_count":1 if finding else 0,
            "stage":stage,
            "state":state,
            "next_action":next_action["action"],
            "verification_required":bool(
                next_action.get("requires_evidence")
            ),
            "regression":regression,
            "evidence_ref_count":len(item.get("evidence_refs",[]) or []),
        })

    for asset in assets:
        if asset.id in persistent_asset_ids:
            continue
        asset_findings=[
            finding
            for finding in findings
            if finding.asset_id==asset.id and finding.status=="open"
        ]
        score=exposure_breakdown(asset,findings).score
        dna=build_exposure_dna(asset,findings)
        if score>=60 or asset_findings:
            queue.append({
                "asset_id":asset.id,
                "asset":asset.value,
                "priority_score":score,
                "criticality":asset.criticality,
                "owner":asset.owner,
                "finding_count":len(asset_findings),
                "dna":dna.fingerprint,
                "signals":dna.signals,
                "stage":"prioritize" if asset_findings else "validate",
                "state":"candidate",
                "next_action":(
                    "mobilize-remediation"
                    if asset_findings
                    else "validate-exposure"
                ),
                "verification_required":False,
                "regression":False,
            })
    return {
        "items":sorted(
            queue,
            key=lambda item:item["priority_score"],
            reverse=True,
        )
    }


@router.post("/api/v1/exposure/ctem/plan")
def exposure_ctem_plan(payload: dict, request: Request):
    principal=require(request,"assets:read")
    assets,findings=tenant_scope(principal)
    asset_ids=set(payload.get("asset_ids",[]))
    finding_ids=set(payload.get("finding_ids",[]))
    selected=[asset for asset in assets if asset.id in asset_ids]
    selected_findings=[
        finding
        for finding in findings
        if finding.id in finding_ids or finding.asset_id in asset_ids
    ]
    items=list_plans(principal.tenant_id)
    created=[]
    now=datetime.now(timezone.utc).isoformat()
    for asset in selected:
        asset_findings=[
            finding
            for finding in selected_findings
            if finding.asset_id==asset.id and finding.status=="open"
        ]
        score=exposure_breakdown(asset,findings).score
        for finding in asset_findings or [None]:
            plan_id=(
                f"ctp-{principal.tenant_id[:8]}-{asset.id}-"
                f"{finding.id if finding else 'asset'}"
            )
            existing=next(
                (item for item in items if item["plan_id"]==plan_id),
                None,
            )
            if existing:
                created.append(existing)
                continue
            plan=build_remediation_plan(finding,asset) if finding else None
            item={
                "plan_id":plan_id,
                "asset_id":asset.id,
                "asset":asset.value,
                "owner":plan.owner if plan else asset.owner,
                "priority_score":score,
                "finding_ids":[finding.id] if finding else [],
                "status":"planned",
                "current_score":plan.current_score if plan else score,
                "residual_score":plan.residual_score if plan else score,
                "risk_reduction":plan.risk_reduction if plan else 0,
                "action":(
                    plan.action
                    if plan
                    else "validar exposição e ownership"
                ),
                "validation":(
                    plan.validation
                    if plan
                    else "reexecutar discovery e confirmar evidência"
                ),
                "effort":plan.effort if plan else "médio",
                "created_at":now,
                "updated_at":now,
                "reason":"Selected from Exposure/Attack Path Planner",
            }
            upsert_plan(principal.tenant_id,item)
            items.append(item)
            created.append(item)
    audit(
        principal,
        "create",
        "ctem.plan",
        None,
        {"count":len(created)},
    )
    return {"items":created,"count":len(created)}


@router.get("/api/v1/exposure/business-impact")
def exposure_business_impact(request: Request):
    principal=require(request,"assets:read")
    assets,findings=tenant_scope(principal)
    rows=[]
    for asset in assets:
        score=exposure_breakdown(asset,findings).score
        rows.append({
            "asset_id":asset.id,
            "asset":asset.value,
            "business_unit":asset.business_unit,
            "environment":asset.environment,
            "criticality":asset.criticality,
            "exposure":score,
            "owner":asset.owner or "unowned",
            "impact_index":min(
                100,
                round(score*(1+asset.criticality/5),1),
            ),
        })
    return {
        "items":sorted(
            rows,
            key=lambda item:item["impact_index"],
            reverse=True,
        )
    }


@router.get("/api/v1/exposure/reduction")
def exposure_reduction(request: Request):
    principal=require(request,"assets:read")
    assets,findings=tenant_scope(principal)
    current=sum(
        exposure_breakdown(asset,findings).score for asset in assets
    )
    open_findings=sum(
        1 for finding in findings if finding.status=="open"
    )
    internet_assets=sum(
        1 for asset in assets if "internet-facing" in asset.tags
    )
    unmanaged=sum(
        1
        for asset in assets
        if ownership_confidence(asset).state=="candidate"
    )
    return {
        "assets":len(assets),
        "open_findings":open_findings,
        "internet_facing_assets":internet_assets,
        "unmanaged_or_unconfirmed_assets":unmanaged,
        "aggregate_exposure":round(current/len(assets)) if assets else 0,
        "risk_reduction_model":"baseline-vs-current",
        "note":(
            "A redução real é calculada quando snapshots históricos "
            "comparáveis estiverem disponíveis."
        ),
    }


@router.get("/api/v1/attack-paths")
def attack_paths(request: Request):
    principal=require(request,"assets:read")
    assets,findings=tenant_scope(principal)
    graph=build_risk_graph(
        "tenant-surface",
        assets,
        [],
        source_assets=assets,
        findings=findings,
    )
    return {
        "paths":graph["top_risk_paths"],
        "summary":graph["risk_summary"],
    }


@router.get("/api/v1/score")
def score(request: Request):
    principal=require(request,"assets:read")
    assets,findings=tenant_scope(principal)
    result=exposure_score(findings,assets)
    breakdowns=[]
    for asset in assets:
        item=exposure_breakdown(asset,findings)
        breakdowns.append({
            "asset_id":asset.id,
            "asset":asset.value,
            "score":item.score,
            "band":exposure_band(item.score),
            "rationale":item.rationale,
            "dimensions":{
                "internet":item.internet,
                "exploitability":item.exploitability,
                "criticality":item.criticality,
                "intelligence":item.intelligence,
                "confidence":item.confidence,
                "shadow":item.shadow,
            },
        })
    return {
        "score":result.score,
        "penalty":result.penalty,
        "rationale":result.rationale,
        "assets":breakdowns,
    }
