from datetime import datetime, timezone

from fastapi import APIRouter, HTTPException, Request

from ...auth import audit
from ...digital_risk import list_events
from ...integration_export import unified_siem_events
from ...syslog_export import config_from_env, send_event, send_events
from ..dependencies import require
from ..tenant_scope import tenant_scope


router=APIRouter()


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
    if principal.role not in {"superadmin","admin","manager"}:
        raise HTTPException(status_code=403,detail="manager role required")
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
    if principal.role not in {"superadmin","admin","manager"}:
        raise HTTPException(status_code=403,detail="manager role required")
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
    if principal.role not in {"superadmin","admin","manager"}:
        raise HTTPException(status_code=403,detail="manager role required")
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
