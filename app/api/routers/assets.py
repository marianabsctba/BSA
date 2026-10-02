from dataclasses import asdict

from fastapi import APIRouter, HTTPException, Request

from ...asset_view import asset_detail
from ...auth import audit
from ...exposure_dna import build_exposure_dna
from ...history import change_summary, history_for
from ...intelligence import blast_radius, ownership_confidence
from ...scope import asset_in_scope
from ..dependencies import require
from ..tenant_scope import tenant_scope


router=APIRouter()



@router.get("/api/v1/assets")
def list_assets(request: Request):
    principal=require(request,"assets:read")
    assets,_=tenant_scope(principal)
    result=[]
    for asset in assets:
        item=asset.model_dump()
        ownership=ownership_confidence(asset)
        item["ownership"]={
            "score":ownership.score,
            "state":ownership.state,
            "reasons":ownership.reasons,
        }
        item["blast_radius"]=blast_radius(asset)
        result.append(item)
    return result


@router.get("/api/v1/assets/{asset_id}")
def asset_detail_view(asset_id: str, request: Request):
    principal=require(request,"assets:read")
    assets,findings=tenant_scope(principal)
    asset=next((item for item in assets if item.id==asset_id),None)
    if not asset:
        raise HTTPException(status_code=404,detail="asset not found")
    audit(principal,"read","asset",asset.id)
    return asset_detail(asset,findings,assets,principal.tenant_id)


@router.get("/api/v1/assets/{asset_id}/dna")
def asset_dna(asset_id: str, request: Request):
    principal=require(request,"assets:read")
    assets,findings=tenant_scope(principal)
    asset=next((item for item in assets if item.id==asset_id),None)
    if not asset:
        raise HTTPException(status_code=404,detail="asset not found")
    return asdict(build_exposure_dna(asset,findings))


@router.get("/api/v1/radar")
def exposure_radar(request: Request):
    principal=require(request,"assets:read")
    assets,findings=tenant_scope(principal)
    rows=[]
    for asset in assets:
        dna=build_exposure_dna(asset,findings)
        rows.append({
            "asset_id":asset.id,
            "value":asset.value,
            "type":asset.type.value,
            "owner":asset.owner,
            "environment":asset.environment,
            "confidence":asset.confidence,
            "criticality":asset.criticality,
            "dna":dna.fingerprint,
            "change_type":dna.change_type,
            "signals":dna.signals,
        })
    return {
        "assets":sorted(
            rows,
            key=lambda item:(
                item["change_type"]!="material-change",
                -item["criticality"],
                -item["confidence"],
            ),
        )
    }


@router.get("/api/v1/assets/{asset_id}/timeline")
def asset_timeline(asset_id: str, request: Request):
    principal=require(request,"assets:read")
    assets,_=tenant_scope(principal)
    asset=next((item for item in assets if item.id==asset_id),None)
    if not asset:
        raise HTTPException(status_code=404,detail="asset not found")
    return {
        "asset_id":asset.id,
        "first_seen":asset.first_seen,
        "last_seen":asset.last_seen,
        "change_summary":change_summary(
            asset.fingerprint,
            principal.tenant_id,
        ),
        "history":[
            item.__dict__
            for item in history_for(
                asset.fingerprint,
                principal.tenant_id,
            )
        ],
    }
