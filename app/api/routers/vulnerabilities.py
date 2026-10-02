from dataclasses import asdict

from fastapi import APIRouter, HTTPException, Request

from ...intelligence import finding_context_score
from ...store import ASSETS as STORE_ASSETS, FINDINGS as STORE_FINDINGS
from ...vulnerability_intelligence import vulnerability_intelligence
from ..dependencies import require, tenant_scope


router=APIRouter()


@router.get("/api/v1/vulnerabilities/intelligence")
def vulnerability_intelligence_api(request: Request):
    principal=require(request,"assets:read")
    assets,findings=tenant_scope(principal,STORE_ASSETS,STORE_FINDINGS)
    asset_map={asset.id:asset for asset in assets}
    rows=[]
    for finding in findings:
        if finding.status!="open":
            continue
        asset=asset_map.get(finding.asset_id)
        intelligence=vulnerability_intelligence(finding,asset)
        rows.append({
            "finding":finding.model_dump(),
            "asset":asset.value if asset else None,
            "intelligence":asdict(intelligence),
        })
    rows.sort(key=lambda item:item["intelligence"]["priority_score"],reverse=True)
    return {
        "summary":{
            "findings":len(rows),
            "critical":sum(item["finding"].get("severity")=="critical" for item in rows),
            "high":sum(item["finding"].get("severity")=="high" for item in rows),
            "data_quality_gaps":sum(bool(item["intelligence"]["data_quality"]) for item in rows),
        },
        "items":rows,
    }


@router.get("/api/v1/vulnerabilities/{finding_id}/intelligence")
def vulnerability_finding_intelligence(finding_id: str, request: Request):
    principal=require(request,"assets:read")
    assets,findings=tenant_scope(principal,STORE_ASSETS,STORE_FINDINGS)
    finding=next((item for item in findings if item.id==finding_id),None)
    if not finding:
        raise HTTPException(status_code=404,detail="finding not found")
    asset=next((item for item in assets if item.id==finding.asset_id),None)
    return {
        "finding":finding.model_dump(),
        "asset":asset.model_dump() if asset else None,
        "intelligence":asdict(vulnerability_intelligence(finding,asset)),
    }


@router.get("/api/v1/findings")
def list_findings(request: Request):
    principal=require(request,"assets:read")
    assets,findings=tenant_scope(principal,STORE_ASSETS,STORE_FINDINGS)
    asset_map={asset.id:asset for asset in assets}
    result=[]
    for finding in findings:
        item=finding.model_dump()
        asset=asset_map.get(finding.asset_id)
        item["context_score"]=finding_context_score(finding,asset) if asset else None
        result.append(item)
    return result
