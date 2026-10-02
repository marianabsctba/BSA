from fastapi import APIRouter, Request

from ...prioritization import prioritize_finding
from ...remediation import build_remediation_plan
from ...scope import asset_in_scope
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


@router.get("/api/v1/prioritization")
def prioritization(request: Request):
    principal=require(request,"findings:read")
    assets,findings=tenant_scope(principal)
    asset_map={asset.id:asset for asset in assets}
    result=[]
    for finding in findings:
        asset=asset_map.get(finding.asset_id)
        item=prioritize_finding(finding,asset)
        result.append({
            "finding_id":finding.id,
            "finding":finding.title,
            "asset":asset.value if asset else None,
            "priority":item.priority,
            "score":item.score,
            "impact":item.impact,
            "urgency":item.urgency,
            "confidence":item.confidence,
            "reasons":item.reasons,
            "recommended_action":item.action,
        })
    return sorted(result,key=lambda item:(-item["score"],item["priority"]))


@router.get("/api/v1/remediation")
def remediation(request: Request):
    principal=require(request,"remediation:write")
    assets,findings=tenant_scope(principal)
    asset_map={asset.id:asset for asset in assets}
    result=[]
    for finding in findings:
        asset=asset_map.get(finding.asset_id)
        if not asset or finding.status!="open":
            continue
        plan=build_remediation_plan(finding,asset)
        result.append({
            "finding_id":plan.finding_id,
            "asset_id":plan.asset_id,
            "asset":asset.value,
            "priority":plan.priority,
            "current_score":plan.current_score,
            "residual_score":plan.residual_score,
            "risk_reduction":plan.risk_reduction,
            "action":plan.action,
            "validation":plan.validation,
            "owner":plan.owner,
            "effort":plan.effort,
            "rationale":plan.rationale,
        })
    return sorted(
        result,
        key=lambda item:(-item["risk_reduction"],item["residual_score"]),
    )
