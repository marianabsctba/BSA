from datetime import datetime, timezone

from fastapi import APIRouter, HTTPException, Request

from ...application.services.ctem_service import (
    build_ctem_operations,
    build_ctem_queue_page,
    list_ctem_queue,
)
from ...history import (
    ctem_audit_diff,
    ctem_audit_integrity,
    ctem_audit_outcome,
    ctem_audit_timeline,
    ctem_transition_history,
    ctem_verification_history,
    list_ctem_items,
)
from ..dependencies import require


router=APIRouter()


@router.get("/api/v1/ctem/operations")
def ctem_operations(request: Request):
    principal=require(request,"findings:read")
    return build_ctem_operations(principal.tenant_id)


@router.get("/api/v1/ctem/{item_id}/audit")
def ctem_audit(item_id: str, request: Request):
    principal=require(request,"findings:read")
    items=list_ctem_items(principal.tenant_id)
    item=next((entry for entry in items if entry.get("item_id")==item_id),None)
    if item is None:
        raise HTTPException(status_code=404,detail="CTEM item not found")
    verifications=ctem_verification_history(item_id,principal.tenant_id)
    transitions=ctem_transition_history(item_id,principal.tenant_id)
    timeline=ctem_audit_timeline(item,verifications,transitions)
    return {
        "item_id":item_id,
        "outcome":ctem_audit_outcome(item,verifications),
        "timeline":timeline,
    }


@router.get("/api/v1/ctem/{item_id}/audit/export")
def ctem_audit_export(item_id: str, request: Request):
    principal=require(request,"findings:read")
    items=list_ctem_items(principal.tenant_id)
    item=next((entry for entry in items if entry.get("item_id")==item_id),None)
    if item is None:
        raise HTTPException(status_code=404,detail="CTEM item not found")
    verifications=ctem_verification_history(item_id,principal.tenant_id)
    transitions=ctem_transition_history(item_id,principal.tenant_id)
    timeline=ctem_audit_timeline(item,verifications,transitions)
    integrity=ctem_audit_integrity(item,verifications,transitions)
    outcome=ctem_audit_outcome(item,verifications)
    diffs=[]
    for current in timeline[1:]:
        if current.get("event")=="verification":
            diffs.append({
                "event":"verification",
                "timestamp":current.get("timestamp"),
                "result":current.get("result"),
                "diff":ctem_audit_diff(timeline[0],current),
            })
    return {
        "format":"ctem-audit-v1",
        "tenant_id":principal.tenant_id,
        "item_id":item_id,
        "generated_at":datetime.now(timezone.utc).isoformat(),
        "integrity":integrity,
        "outcome":outcome,
        "timeline":timeline,
        "diffs":diffs,
    }


@router.get("/api/v1/ctem/queue")
def ctem_queue_page_api(
    request: Request,
    state: str | None = None,
    bucket: str | None = None,
    min_leverage: int | None = None,
    page: int = 1,
    page_size: int = 50,
):
    principal=require(request,"findings:read")
    return build_ctem_queue_page(
        principal.tenant_id,
        state=state,
        bucket=bucket,
        min_leverage=min_leverage,
        page=page,
        page_size=page_size,
    )


@router.get("/api/v1/ctem")
def ctem_queue(request: Request, state: str | None = None):
    principal=require(request,"findings:read")
    return list_ctem_queue(principal.tenant_id,state)
