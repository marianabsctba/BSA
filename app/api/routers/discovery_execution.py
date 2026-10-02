from fastapi import APIRouter, HTTPException, Request
from pydantic import BaseModel, Field

from ...ctem_store import history
from ...exposure import exposure_band, exposure_breakdown
from ...history import lifecycle_for
from ...intelligence import ownership_confidence
from ...nuclei_engine import validate_nuclei_target
from ...scope import asset_in_scope
from ..dependencies import require
from ..tenant_scope import tenant_scope
from ..operation_queue import queue_active_operation


router=APIRouter()


class DiscoveryRequest(BaseModel):
    target:str=Field(min_length=1,max_length=253)
    checks:list[str]=Field(
        default_factory=lambda:["dns","http","tls","ct"]
    )
    authorization_ref:str=Field(default="",max_length=200)


class DASTRequest(BaseModel):
    target:str=Field(min_length=1,max_length=2048)
    authorization_ref:str=Field(min_length=1,max_length=200)
    profile:str=Field(default="safe",max_length=20)



@router.post("/api/v1/dast/nuclei")
def dast_nuclei(payload: DASTRequest, request: Request):
    principal=require(request,"discovery:run")
    if not payload.authorization_ref.strip():
        raise HTTPException(
            status_code=400,
            detail="authorization_ref is required",
        )
    if payload.profile not in {"safe","standard"}:
        raise HTTPException(
            status_code=400,
            detail="unsupported DAST profile",
        )
    try:
        validate_nuclei_target(payload.target)
    except ValueError as exc:
        raise HTTPException(status_code=400,detail=str(exc)) from exc
    if not asset_in_scope(principal,payload.target):
        raise HTTPException(
            status_code=403,
            detail="target outside assigned scope",
        )
    return queue_active_operation(
        request,
        principal,
        payload.target,
        "dast.nuclei",
        {"profile":payload.profile},
        payload.authorization_ref,
    )


@router.post("/api/v1/dast/safe-web")
def dast_safe_web(payload: DASTRequest, request: Request):
    principal=require(request,"discovery:run")
    if not payload.authorization_ref.strip():
        raise HTTPException(
            status_code=400,
            detail="authorization_ref is required",
        )
    if not asset_in_scope(principal,payload.target):
        raise HTTPException(
            status_code=403,
            detail="target outside assigned scope",
        )
    return queue_active_operation(
        request,
        principal,
        payload.target,
        "dast.safe_web",
        {},
        payload.authorization_ref,
    )


@router.post("/api/v1/discovery")
def discovery(payload: DiscoveryRequest, http_request: Request):
    principal=require(http_request,"discovery:run")
    if not asset_in_scope(principal,payload.target):
        raise HTTPException(
            status_code=403,
            detail="target outside assigned scope",
        )
    checks=list(dict.fromkeys(payload.checks))
    allowed={"dns","http","tls","ct"}
    if not checks or any(check not in allowed for check in checks):
        raise HTTPException(
            status_code=400,
            detail="checks deve conter apenas dns, http, tls e ct",
        )
    return queue_active_operation(
        http_request,
        principal,
        payload.target,
        "discovery.basic",
        {"checks":checks},
        payload.authorization_ref,
    )


def _queue_discovery(request: Request, target: str, operation: str):
    principal=require(request,"discovery:run")
    if not asset_in_scope(principal,target):
        raise HTTPException(
            status_code=403,
            detail="target outside assigned scope",
        )
    return queue_active_operation(
        request,
        principal,
        target,
        operation,
    )


@router.post("/api/v1/discovery/{target}/changes")
def discovery_changes(target: str, request: Request):
    return _queue_discovery(request,target,"discovery.changes")


@router.post("/api/v1/discovery/{target}/graph")
def discovery_graph(target: str, request: Request):
    return _queue_discovery(request,target,"discovery.graph")


@router.post("/api/v1/discovery/{target}/correlation")
def discovery_correlation(target: str, request: Request):
    return _queue_discovery(request,target,"discovery.correlation")


@router.post("/api/v1/easm/discover/{target}")
def easm_discover(
    target: str,
    request: Request,
    max_depth: int=2,
    max_assets: int=40,
):
    principal=require(request,"discovery:run")
    if not asset_in_scope(principal,target):
        raise HTTPException(
            status_code=403,
            detail="target outside assigned scope",
        )
    if max_depth<0 or max_depth>3 or max_assets<1 or max_assets>100:
        raise HTTPException(
            status_code=400,
            detail="invalid discovery bounds",
        )
    return queue_active_operation(
        request,
        principal,
        target,
        "easm.discover",
        {"max_depth":max_depth,"max_assets":max_assets},
    )


@router.post("/api/v1/easm/lifecycle/{target}")
def easm_lifecycle(target: str, request: Request):
    return _queue_discovery(request,target,"easm.lifecycle")


@router.get("/api/v1/easm/lifecycle/{target}/{fingerprint}")
def easm_asset_lifecycle(
    target: str,
    fingerprint: str,
    request: Request,
):
    principal=require(request,"assets:read")
    if not asset_in_scope(principal,target):
        raise HTTPException(
            status_code=403,
            detail="target outside assigned scope",
        )
    return lifecycle_for(fingerprint,principal.tenant_id)


@router.get("/api/v1/easm/overview")
def easm_overview(request: Request):
    principal=require(request,"assets:read")
    scoped_assets,scoped_findings=tenant_scope(principal)

    def state(asset):
        ownership=ownership_confidence(asset)
        if (
            asset.status in {"approved","owned","managed"}
            or ownership.state=="confirmed"
        ):
            return "approved"
        if asset.status in {"dependency","third_party"}:
            return "dependency"
        if asset.status in {"monitor","monitor_only"}:
            return "monitor_only"
        if asset.status in {"requires_investigation","investigate"}:
            return "requires_investigation"
        return "candidate"

    inventory=[
        {
            "id":asset.id,
            "value":asset.value,
            "type":asset.type.value,
            "state":state(asset),
            "confidence":asset.confidence,
            "criticality":asset.criticality,
            "first_seen":asset.first_seen,
            "last_seen":asset.last_seen,
            "sources":asset.sources,
            "evidence_count":asset.evidence_count,
            "owner":asset.owner,
            "environment":asset.environment,
            "cloud_provider":asset.cloud_provider,
        }
        for asset in scoped_assets
    ]
    by_state={}
    by_type={}
    for item in inventory:
        by_state[item["state"]]=by_state.get(item["state"],0)+1
        by_type[item["type"]]=by_type.get(item["type"],0)+1
    exposed=[
        item
        for item in inventory
        if item["type"] in {
            "service",
            "application",
            "ip",
            "domain",
            "subdomain",
        }
    ]
    return {
        "summary":{
            "total_assets":len(inventory),
            "exposed_assets":len(exposed),
            "approved":by_state.get("approved",0),
            "candidates":by_state.get("candidate",0),
            "requires_investigation":by_state.get(
                "requires_investigation",
                0,
            ),
            "dependencies":by_state.get("dependency",0),
            "monitor_only":by_state.get("monitor_only",0),
            "by_type":by_type,
            "by_state":by_state,
        },
        "inventory":inventory,
        "changes":{
            "recent":sum(
                1 for asset in scoped_assets if asset.status=="observed"
            ),
            "unowned":sum(
                1 for asset in scoped_assets if not asset.owner
            ),
            "low_confidence":sum(
                1 for asset in scoped_assets if asset.confidence<70
            ),
        },
        "risk":{
            "critical_findings":sum(
                1
                for finding in scoped_findings
                if finding.status=="open"
                and finding.severity.value=="critical"
            ),
            "high_findings":sum(
                1
                for finding in scoped_findings
                if finding.status=="open"
                and finding.severity.value=="high"
            ),
        },
    }


@router.get("/api/v1/exposure")
def exposure(request: Request):
    principal=require(request,"assets:read")
    assets,findings=tenant_scope(principal)
    items=[]
    for asset in assets:
        item=exposure_breakdown(asset,findings)
        items.append({
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
    return sorted(items,key=lambda item:item["score"],reverse=True)


@router.post("/api/v1/discovery/{target}/infrastructure/graph")
def discovery_infrastructure_graph(target: str, request: Request):
    return _queue_discovery(
        request,
        target,
        "discovery.infrastructure_graph",
    )


@router.post("/api/v1/discovery/{target}/infrastructure")
def discovery_infrastructure(target: str, request: Request):
    return _queue_discovery(
        request,
        target,
        "discovery.infrastructure",
    )


@router.post("/api/v1/discovery/{target}/risk-paths")
def discovery_risk_paths(target: str, request: Request):
    return _queue_discovery(
        request,
        target,
        "discovery.risk_paths",
    )
