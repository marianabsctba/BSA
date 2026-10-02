from datetime import datetime, timezone

from fastapi import APIRouter, HTTPException, Request
from fastapi.responses import JSONResponse

from ...application.services.ctem_service import (
    build_ctem_operations,
    build_ctem_queue_page,
    list_ctem_queue,
)
from ...auth import audit
from ...job_queue import enqueue_assessment
from ...history import (
    ctem_audit_diff,
    ctem_audit_integrity,
    ctem_audit_outcome,
    ctem_audit_timeline,
    ctem_transition_history,
    ctem_verification_history,
    list_ctem_items,
    ctem_action_idempotency_key,
    ctem_action_transition,
    ctem_claim_operation,
    ctem_operation_result,
    ctem_store_operation_result,
    record_ctem_transition,
    record_ctem_retest,
    update_ctem_state,
    verify_ctem_item,
)
from ..active_scan import govern_active_scan
from ..dependencies import require
from ..tenant_scope import tenant_scope


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


@router.post("/api/v1/ctem/{item_id}/verify")
def ctem_verify(item_id: str, request: Request, payload: dict):
    principal=require(request,"remediation:write")
    try:
        result=verify_ctem_item(
            item_id,
            principal.tenant_id,
            str(payload.get("result","")),
            list(payload.get("evidence_refs") or []),
            str(payload.get("notes","")),
        )
        audit(
            principal,
            "ctem_verification",
            "ctem",
            item_id,
            {
                "result":str(payload.get("result","")),
                "evidence_count":len(list(payload.get("evidence_refs") or [])),
            },
        )
        return result
    except KeyError:
        raise HTTPException(status_code=404,detail="CTEM item not found")
    except ValueError as exc:
        raise HTTPException(status_code=400,detail=str(exc))


@router.post("/api/v1/ctem/{item_id}/state")
def ctem_state(item_id: str, request: Request, payload: dict):
    principal=require(request,"remediation:write")
    new_state=str(payload.get("state",""))
    request_id=str(payload.get("request_id") or request.headers.get("Idempotency-Key") or "")
    items=list_ctem_items(principal.tenant_id)
    item=next((entry for entry in items if entry.get("item_id")==item_id),None)
    if item is None:
        raise HTTPException(status_code=404,detail="CTEM item not found")

    transitions={
        "acknowledged":"acknowledge",
        "in_progress":"start_remediation",
        "resolved":"submit_for_verification",
        "verified":"verify",
    }
    action=transitions.get(new_state)
    if not action:
        raise HTTPException(status_code=400,detail="invalid CTEM target state")

    try:
        target=ctem_action_transition(item,action)
        operation_key=ctem_action_idempotency_key(item_id,action,request_id)
        if not ctem_claim_operation(principal.tenant_id,operation_key,action,item_id):
            previous=ctem_operation_result(principal.tenant_id,operation_key)
            return previous or {"status":"already_processed","operation_key":operation_key}

        result=update_ctem_state(item_id,principal.tenant_id,target)
        record_ctem_transition(
            item_id,
            principal.tenant_id,
            action,
            str(item.get("state") or ""),
            target,
            actor_id=str(getattr(principal,"user_id","") or ""),
            request_id=request_id or operation_key,
        )
        audit(
            principal,
            "ctem_state_transition",
            "ctem",
            item_id,
            {"action":action,"from":item.get("state"),"to":target},
        )
        ctem_store_operation_result(principal.tenant_id,operation_key,result)
        return result
    except KeyError:
        raise HTTPException(status_code=404,detail="CTEM item not found")
    except ValueError as exc:
        raise HTTPException(status_code=400,detail=str(exc))


@router.post("/api/v1/ctem/{item_id}/retest")
def ctem_retest(item_id: str, request: Request, payload: dict):
    principal=require(request,"remediation:write")
    item=next(
        (entry for entry in list_ctem_items(principal.tenant_id)
         if entry.get("item_id")==item_id),
        None,
    )
    if item is None:
        raise HTTPException(status_code=404,detail="CTEM item not found")
    if item.get("state") not in {"in_progress","resolved"}:
        raise HTTPException(status_code=400,detail="CTEM item is not ready for retest")

    asset_id=str(item.get("asset_id") or "")
    assets,_=tenant_scope(principal)
    asset=next((entry for entry in assets if entry.id==asset_id),None)
    if asset is None:
        raise HTTPException(status_code=404,detail="CTEM asset not found")

    profile=str(payload.get("profile") or "rapid")
    if profile not in {"rapid","network","balanced"}:
        raise HTTPException(status_code=400,detail="invalid retest profile")

    authorization_ref=govern_active_scan(
        request,
        principal,
        asset.value,
        str(payload.get("authorization_ref") or ""),
    )
    job=enqueue_assessment(
        principal,
        asset.value,
        profile,
        authorization_ref or "development-retest",
    )
    record_ctem_retest(
        job["job_id"],
        principal.tenant_id,
        item_id,
        profile,
        authorization_ref or "development-retest",
    )
    audit(
        principal,
        "queue",
        "ctem_retest",
        item_id,
        {
            "job_id":job["job_id"],
            "asset_id":asset.id,
            "profile":profile,
            "authorization_ref":authorization_ref or "development",
        },
    )
    record_ctem_transition(
        item_id,
        principal.tenant_id,
        "queue_retest",
        str(item.get("state") or ""),
        str(item.get("state") or ""),
        actor_id=str(getattr(principal,"user_id","") or ""),
        request_id=str(job.get("job_id") or ""),
    )
    return JSONResponse(
        status_code=202,
        content={
            "item_id":item_id,
            "job_id":job["job_id"],
            "status":job["status"],
            "profile":job["profile"],
            "verification_required":True,
        },
    )
