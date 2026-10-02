from fastapi import APIRouter, HTTPException, Request
from pydantic import BaseModel, Field

from ...application.services.policy_service import (
    build_and_save_risk_policy,
    build_and_save_sla_policy,
    get_risk_policy_view,
    get_sla_policy_view,
)
from ...application.services.risk_service import build_risk_overview, build_risk_register
from ...auth import audit
from ...tenant_risk_policy import serialize_policy
from ...tenant_sla_policy import serialize_sla_policy
from ..dependencies import require
from ..tenant_scope import tenant_scope


router=APIRouter()


class TenantSLAPolicyRequest(BaseModel):
    critical_hours: int = Field(default=24, ge=1, le=8760)
    high_hours: int = Field(default=48, ge=1, le=8760)
    medium_hours: int = Field(default=168, ge=1, le=8760)
    low_hours: int = Field(default=336, ge=1, le=8760)


@router.get("/api/v1/risk/policy")
def get_risk_policy(request: Request):
    principal=require(request,"assets:read")
    return get_risk_policy_view(principal.tenant_id)


@router.put("/api/v1/risk/policy")
async def update_risk_policy(request: Request):
    principal=require(request,"remediation:write")
    body=await request.json()
    try:
        candidate=build_and_save_risk_policy(principal.tenant_id,principal.user_id,body)
    except ValueError as exc:
        detail=exc.args[0] if exc.args else ["invalid risk policy"]
        raise HTTPException(status_code=400,detail={"errors":detail}) from exc
    audit(principal,"risk_policy_update","risk_policy",metadata=serialize_policy(candidate))
    return {"policy":serialize_policy(candidate),"validation":[],"persisted":True}


@router.get("/api/v1/operations/sla-policy")
def get_tenant_sla_policy(request: Request):
    principal=require(request,"assets:read")
    return get_sla_policy_view(principal.tenant_id)


@router.put("/api/v1/operations/sla-policy")
def update_tenant_sla_policy(payload: TenantSLAPolicyRequest, request: Request):
    principal=require(request,"remediation:write")
    try:
        candidate=build_and_save_sla_policy(
            principal.tenant_id,
            principal.user_id,
            payload.critical_hours,
            payload.high_hours,
            payload.medium_hours,
            payload.low_hours,
        )
    except ValueError as exc:
        detail=exc.args[0] if exc.args else ["invalid SLA policy"]
        raise HTTPException(status_code=400,detail={"errors":detail}) from exc
    audit(principal,"sla_policy_update","tenant_sla_policy",metadata=serialize_sla_policy(candidate))
    return {"policy":serialize_sla_policy(candidate),"validation":[],"persisted":True}


@router.get("/api/v1/risk/register")
def risk_register(request: Request):
    principal=require(request,"assets:read")
    assets,findings=tenant_scope(principal)
    return build_risk_register(principal.tenant_id,assets,findings)


@router.get("/api/v1/risk/overview")
def risk_overview(request: Request):
    principal=require(request,"assets:read")
    assets,findings=tenant_scope(principal)
    return build_risk_overview(assets,findings)
