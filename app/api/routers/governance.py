from fastapi import APIRouter, HTTPException, Request
from pydantic import BaseModel, Field

from ...auth import (
    audit,
    list_audit,
    tenant_settings,
    update_tenant_locale,
    verify_audit_chain,
)
from ...integration_export import audit_siem_events
from ...retention import (
    apply_retention,
    get_retention_policy,
    retention_preview,
    set_retention_policy,
)
from ...scope import create_group, list_groups
from ...syslog_export import config_from_env, send_events
from ..dependencies import current_principal, require


router=APIRouter()


class GroupCreateRequest(BaseModel):
    name: str = Field(min_length=1, max_length=120)
    pattern: str = Field(min_length=1, max_length=253)


class RetentionPolicyRequest(BaseModel):
    retention_days: int = Field(ge=30, le=3650)


class RetentionApplyRequest(BaseModel):
    execute: bool = False


class TenantLocaleRequest(BaseModel):
    locale: str = Field(pattern=r"^(pt-BR|en|es)$")


@router.get("/api/v1/groups")
def groups(request: Request):
    principal=require(request,"users:read")
    return list_groups(principal)


@router.post("/api/v1/groups")
def groups_create(request: Request, payload: GroupCreateRequest):
    principal=current_principal(request)
    try:
        result=create_group(principal,payload.name,payload.pattern)
        audit(
            principal,
            "create",
            "asset_group",
            result["id"],
            {"pattern":payload.pattern},
        )
        return result
    except PermissionError as exc:
        raise HTTPException(status_code=403,detail=str(exc)) from exc


@router.get("/api/v1/audit")
def audit_events(request: Request, limit: int=100):
    principal=current_principal(request)
    try:
        return list_audit(principal,limit)
    except PermissionError as exc:
        raise HTTPException(status_code=403,detail=str(exc)) from exc


@router.get("/api/v1/audit/integrity")
def audit_integrity(request: Request):
    principal=current_principal(request)
    try:
        return verify_audit_chain(principal)
    except PermissionError as exc:
        raise HTTPException(status_code=403,detail=str(exc)) from exc


@router.get("/api/v1/audit/export")
def audit_export(request: Request, limit: int=500):
    principal=current_principal(request)
    try:
        rows=list_audit(principal,limit)
    except PermissionError as exc:
        raise HTTPException(status_code=403,detail=str(exc)) from exc
    integrity=verify_audit_chain(principal)
    return {
        "schema_version":"1.0",
        "count":len(rows),
        "integrity":integrity,
        "events":audit_siem_events(rows,limit=limit),
    }


@router.post("/api/v1/audit/syslog/push")
def audit_syslog_push(request: Request, limit: int=500):
    principal=current_principal(request)
    if principal.role not in {"superadmin","admin","manager"}:
        raise HTTPException(status_code=403,detail="manager role required")
    cfg=config_from_env()
    if cfg is None:
        raise HTTPException(status_code=400,detail="syslog not configured")
    rows=list_audit(principal,limit)
    integrity=verify_audit_chain(principal)
    if not integrity.get("valid"):
        raise HTTPException(status_code=409,detail="audit integrity check failed")
    events=audit_siem_events(rows,limit=limit)
    result=send_events(events,cfg,limit=limit)
    audit(
        principal,
        "push",
        "audit.syslog",
        None,
        {
            "requested":len(events),
            "delivered":result.get("delivered",0),
            "failed":result.get("failed",0),
            "transport":cfg.transport,
        },
    )
    return {"stream_count":len(events),"integrity":integrity,**result}


@router.get("/api/v1/tenant/retention")
def tenant_retention_get(request: Request):
    principal=current_principal(request)
    return get_retention_policy(principal.tenant_id)


@router.patch("/api/v1/tenant/retention")
def tenant_retention_update(request: Request, payload: RetentionPolicyRequest):
    principal=current_principal(request)
    try:
        result=set_retention_policy(principal,payload.retention_days)
        audit(
            principal,
            "update",
            "tenant_retention",
            principal.tenant_id,
            {"retention_days":payload.retention_days},
        )
        return result
    except PermissionError as exc:
        raise HTTPException(status_code=403,detail=str(exc)) from exc
    except ValueError as exc:
        raise HTTPException(status_code=400,detail=str(exc)) from exc


@router.post("/api/v1/tenant/retention/apply")
def tenant_retention_apply(request: Request, payload: RetentionApplyRequest):
    principal=current_principal(request)
    try:
        if not payload.execute:
            return {"dry_run":True,**retention_preview(principal.tenant_id)}
        result=apply_retention(principal)
        audit(
            principal,
            "apply",
            "tenant_retention",
            principal.tenant_id,
            {
                "retention_days":result["retention_days"],
                "deleted_total":result["deleted_total"],
            },
        )
        return {"dry_run":False,**result}
    except PermissionError as exc:
        raise HTTPException(status_code=403,detail=str(exc)) from exc


@router.get("/api/v1/tenant/settings")
def tenant_settings_get(request: Request):
    principal=current_principal(request)
    return tenant_settings(principal)


@router.patch("/api/v1/tenant/settings")
def tenant_settings_update(request: Request, payload: TenantLocaleRequest):
    principal=current_principal(request)
    try:
        result=update_tenant_locale(principal,payload.locale)
        audit(
            principal,
            "update",
            "tenant_settings",
            principal.tenant_id,
            {"locale":payload.locale},
        )
        return result
    except PermissionError as exc:
        raise HTTPException(status_code=403,detail=str(exc)) from exc
    except ValueError as exc:
        raise HTTPException(status_code=400,detail=str(exc)) from exc
