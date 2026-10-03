from datetime import datetime, timezone

from fastapi import APIRouter, HTTPException, Request

from ...auth import audit
from ...digital_risk import list_events
from ...integration_export import unified_siem_events
from ...itsm_webhook import (
    ITSMWebhookError,
    build_mobilization_event,
    config_from_env as itsm_config_from_env,
    deliver_event as deliver_itsm_event,
)
from ...syslog_export import config_from_env, send_event, send_events
from ..dependencies import require
from ..tenant_scope import tenant_scope


router=APIRouter()
_MANAGER_ROLES={"superadmin","admin","manager"}


def _require_manager(principal):
    if principal.role not in _MANAGER_ROLES:
        raise HTTPException(status_code=403,detail="manager role required")


@router.get("/api/v1/integrations/siem/export")
def integrations_siem_export(
    request: Request,
    since: str | None = None,
    limit: int = 500,
):
    principal=require(request,"assets:read")
    assets,findings=tenant_scope(principal)
    drp=list_events(principal.tenant_id)
    return unified_siem_events(
        principal.tenant_id,
        assets,
        findings,
        drp,
        since=since,
        limit=limit,
    )


@router.get("/api/v1/integrations/siem/status")
def integrations_siem_status(request: Request):
    principal=require(request,"assets:read")
    _require_manager(principal)
    cfg=config_from_env()
    return {
        "api_export":True,
        "syslog_enabled":cfg is not None,
        "transport":cfg.transport if cfg else None,
        "port":cfg.port if cfg else None,
        "tls":bool(cfg and cfg.transport=="tls"),
        "configured":cfg is not None,
    }


@router.post("/api/v1/integrations/siem/syslog/test")
def integrations_siem_syslog_test(request: Request):
    principal=require(request,"assets:read")
    _require_manager(principal)
    cfg=config_from_env()
    if cfg is None:
        raise HTTPException(status_code=400,detail="syslog not configured")
    event={
        "schema_version":"1.0",
        "event_type":"integration.test",
        "event_id":f"syslog-test:{principal.tenant_id}",
        "observed_at":datetime.now(timezone.utc).isoformat(),
        "tenant_id":principal.tenant_id,
        "severity":"info",
        "source":"be-safe-asm",
        "message":"Be Safe ASM Syslog integration test",
    }
    result=send_event(event,cfg)
    audit(
        principal,
        "test",
        "integration.syslog",
        None,
        {
            "transport":cfg.transport,
            "port":cfg.port,
            "delivered":bool(result.get("delivered")),
        },
    )
    return result


@router.post("/api/v1/integrations/siem/syslog/push")
def integrations_siem_syslog_push(
    request: Request,
    since: str | None = None,
    limit: int = 500,
):
    principal=require(request,"assets:read")
    _require_manager(principal)
    cfg=config_from_env()
    if cfg is None:
        raise HTTPException(status_code=400,detail="syslog not configured")
    assets,findings=tenant_scope(principal)
    stream=unified_siem_events(
        principal.tenant_id,
        assets,
        findings,
        list_events(principal.tenant_id),
        since=since,
        limit=limit,
    )
    result=send_events(stream["events"],cfg,limit=limit)
    audit(
        principal,
        "push",
        "integration.syslog",
        None,
        {
            "requested":stream["count"],
            "delivered":result.get("delivered",0),
            "failed":result.get("failed",0),
            "transport":cfg.transport,
        },
    )
    return {"stream_count":stream["count"],**result}


@router.get("/api/v1/integrations/itsm/status")
def integrations_itsm_status(request: Request):
    principal=require(request,"assets:read")
    _require_manager(principal)
    try:
        cfg=itsm_config_from_env()
    except ValueError:
        return {"configured":False,"healthy":False,"signed":False,"idempotency":True}
    return {
        "configured":cfg is not None,
        "healthy":cfg is not None,
        "signed":cfg is not None,
        "idempotency":True,
        "max_attempts":cfg.max_attempts if cfg else 0,
    }


@router.post("/api/v1/integrations/itsm/test")
def integrations_itsm_test(request: Request):
    principal=require(request,"assets:write")
    _require_manager(principal)
    event=build_mobilization_event(
        tenant_id=principal.tenant_id,
        resource_type="integration_test",
        resource_id=f"itsm-test:{principal.tenant_id}",
        severity="info",
        title="Be Safe ASM ITSM integration test",
        payload={"test":True},
    )
    try:
        result=deliver_itsm_event(event)
    except (ITSMWebhookError,ValueError) as exc:
        raise HTTPException(status_code=502,detail=str(exc)) from exc
    audit(
        principal,
        "test",
        "integration.itsm",
        event["event_id"],
        {"delivered":bool(result.get("delivered")),"attempts":result.get("attempts")},
    )
    return result


def _finding_payload(finding) -> dict:
    return {
        "finding_id":finding.id,
        "asset_id":finding.asset_id,
        "title":finding.title,
        "severity":getattr(finding.severity,"value",finding.severity),
        "status":finding.status,
        "vulnerability_id":getattr(finding,"vulnerability_id",None),
        "affected_component":getattr(finding,"affected_component",None),
    }


def _drp_payload(event: dict) -> dict:
    return {
        "event_id":event.get("event_id"),
        "category":event.get("category"),
        "indicator":event.get("indicator"),
        "brand":event.get("brand"),
        "risk_score":event.get("risk_score"),
        "risk_band":event.get("risk_band"),
        "status":event.get("status"),
        "lifecycle_state":event.get("lifecycle_state"),
        "campaign_key":event.get("campaign_key"),
    }


@router.post("/api/v1/integrations/itsm/mobilize/{resource_type}/{resource_id}")
def integrations_itsm_mobilize(resource_type: str, resource_id: str, request: Request):
    principal=require(request,"assets:write")
    _require_manager(principal)
    if resource_type=="finding":
        _,findings=tenant_scope(principal)
        finding=next((item for item in findings if item.id==resource_id),None)
        if finding is None:
            raise HTTPException(status_code=404,detail="finding not found")
        payload=_finding_payload(finding)
        severity=str(payload.get("severity") or "medium")
        title=str(payload.get("title") or resource_id)
    elif resource_type=="digital_risk":
        event=next((item for item in list_events(principal.tenant_id) if item.get("event_id")==resource_id),None)
        if event is None:
            raise HTTPException(status_code=404,detail="digital risk event not found")
        payload=_drp_payload(event)
        severity=str(event.get("risk_band") or event.get("severity") or "medium")
        title=str(event.get("title") or resource_id)
    else:
        raise HTTPException(status_code=400,detail="unsupported mobilization resource")
    outbound=build_mobilization_event(
        tenant_id=principal.tenant_id,
        resource_type=resource_type,
        resource_id=resource_id,
        severity=severity,
        title=title,
        payload=payload,
    )
    try:
        result=deliver_itsm_event(outbound)
    except (ITSMWebhookError,ValueError) as exc:
        raise HTTPException(status_code=502,detail=str(exc)) from exc
    audit(
        principal,
        "mobilize",
        "integration.itsm",
        resource_id,
        {
            "resource_type":resource_type,
            "event_id":outbound["event_id"],
            "delivered":bool(result.get("delivered")),
            "attempts":result.get("attempts"),
        },
    )
    return {"resource_type":resource_type,"resource_id":resource_id,**result}
