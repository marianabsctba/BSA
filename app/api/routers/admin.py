from fastapi import APIRouter, HTTPException, Request
from pydantic import BaseModel, Field

from ...auth import (
    PERMISSION_CATALOG,
    audit,
    create_custom_role,
    create_tenant,
    create_user,
    list_custom_roles,
    list_tenants,
    list_users,
    rate_limit_action,
    reset_user_password,
    role_permissions,
    set_user_active,
    update_user,
)
from ...scope import (
    assign_scan_scope_to_user,
    assign_scope_to_user,
    list_user_scan_scopes,
    list_user_scopes,
)
from ...tenant_lifecycle import purge_tenant, retire_tenant, tenant_purge_preview
from ..dependencies import current_principal, require


router=APIRouter()


class TenantCreateRequest(BaseModel):
    id: str = Field(min_length=3, max_length=64, pattern=r"^[a-z0-9][a-z0-9-]+$")
    name: str = Field(min_length=1, max_length=120)
    locale: str = Field(default="pt-BR", pattern=r"^(pt-BR|en|es)$")


class TenantPurgeRequest(BaseModel):
    execute: bool = False
    preserve_audit: bool = True


class UserCreateRequest(BaseModel):
    email: str
    name: str = Field(min_length=1, max_length=120)
    password: str = Field(min_length=12, max_length=256)
    role: str


class UserScopeRequest(BaseModel):
    scope_id: str = Field(min_length=1, max_length=120)
    active: bool = True


class CustomRoleRequest(BaseModel):
    name: str = Field(min_length=1, max_length=80)
    permissions: list[str] = Field(min_length=1, max_length=50)


class UserUpdateRequest(BaseModel):
    name: str = Field(min_length=1, max_length=120)
    role: str | None = None


class UserActiveRequest(BaseModel):
    active: bool


class UserPasswordResetRequest(BaseModel):
    password: str = Field(min_length=12, max_length=256)


@router.post("/api/v1/tenants/{tenant_id}/retire")
def tenant_retire(tenant_id: str, request: Request):
    principal=current_principal(request)
    try:
        result=retire_tenant(principal,tenant_id)
        audit(principal,"retire","tenant",tenant_id,{})
        return result
    except PermissionError as exc:
        raise HTTPException(status_code=403,detail=str(exc)) from exc
    except ValueError as exc:
        raise HTTPException(status_code=400,detail=str(exc)) from exc


@router.post("/api/v1/tenants/{tenant_id}/purge")
def tenant_purge(tenant_id: str, request: Request, payload: TenantPurgeRequest):
    principal=current_principal(request)
    if principal.role!="superadmin":
        raise HTTPException(status_code=403,detail="superadmin required")
    try:
        if not payload.execute:
            return {"dry_run":True,**tenant_purge_preview(tenant_id,preserve_audit=payload.preserve_audit)}
        result=purge_tenant(principal,tenant_id,preserve_audit=payload.preserve_audit)
        audit(principal,"purge","tenant",tenant_id,{"preserve_audit":payload.preserve_audit})
        return {"dry_run":False,**result}
    except PermissionError as exc:
        raise HTTPException(status_code=403,detail=str(exc)) from exc
    except ValueError as exc:
        raise HTTPException(status_code=400,detail=str(exc)) from exc


@router.get("/api/v1/tenants")
def tenants(request: Request):
    principal=current_principal(request)
    if principal.role!="superadmin":
        raise HTTPException(status_code=403,detail="superadmin required")
    return list_tenants(principal)


@router.post("/api/v1/tenants")
def tenants_create(request: Request, payload: TenantCreateRequest):
    principal=current_principal(request)
    if principal.role!="superadmin":
        raise HTTPException(status_code=403,detail="superadmin required")
    try:
        result=create_tenant(principal,payload.id,payload.name,payload.locale)
        audit(principal,"create","tenant",payload.id)
        return result
    except PermissionError as exc:
        raise HTTPException(status_code=403,detail=str(exc)) from exc
    except Exception as exc:
        raise HTTPException(status_code=409,detail="tenant already exists or invalid data") from exc


@router.get("/api/v1/users")
def users(request: Request):
    principal=require(request,"users:read")
    try:
        return list_users(principal)
    except PermissionError as exc:
        raise HTTPException(status_code=403,detail=str(exc)) from exc


@router.post("/api/v1/users")
def users_create(request: Request, payload: UserCreateRequest):
    principal=current_principal(request)
    if principal.role not in {"admin","superadmin"}:
        raise HTTPException(status_code=403,detail="admin required")
    try:
        result=create_user(
            principal,
            payload.email,
            payload.name,
            payload.password,
            payload.role,
        )
        audit(principal,"create","user",result["id"],{"role":payload.role})
        return result
    except ValueError as exc:
        raise HTTPException(status_code=400,detail=str(exc)) from exc
    except Exception as exc:
        raise HTTPException(status_code=409,detail="user already exists or invalid data") from exc


@router.get("/api/v1/rbac/permissions")
def rbac_permissions():
    return {"permissions":PERMISSION_CATALOG}


@router.get("/api/v1/rbac/custom-roles")
def custom_roles_list(request: Request):
    principal=current_principal(request)
    try:
        return list_custom_roles(principal)
    except PermissionError as exc:
        raise HTTPException(status_code=403,detail=str(exc)) from exc


@router.post("/api/v1/rbac/custom-roles")
def custom_roles_create(request: Request, payload: CustomRoleRequest):
    principal=current_principal(request)
    try:
        result=create_custom_role(principal,payload.name,payload.permissions)
        audit(
            principal,
            "create",
            "custom_role",
            result["name"],
            {"permissions":result["permissions"]},
        )
        return result
    except PermissionError as exc:
        raise HTTPException(status_code=403,detail=str(exc)) from exc
    except ValueError as exc:
        raise HTTPException(status_code=400,detail=str(exc)) from exc


@router.get("/api/v1/users/{user_id}/scopes")
def users_scopes_list(user_id: str, request: Request):
    principal=current_principal(request)
    try:
        return list_user_scopes(principal,user_id)
    except PermissionError as exc:
        raise HTTPException(status_code=403,detail=str(exc)) from exc
    except ValueError:
        raise HTTPException(status_code=404,detail="user not found")


@router.post("/api/v1/users/{user_id}/scopes")
def users_scopes_set(user_id: str, request: Request, payload: UserScopeRequest):
    principal=current_principal(request)
    try:
        result=assign_scope_to_user(principal,user_id,payload.scope_id)
        audit(principal,"scope_change","user",user_id,result)
        return result
    except PermissionError as exc:
        raise HTTPException(status_code=403,detail=str(exc)) from exc
    except ValueError as exc:
        raise HTTPException(status_code=400,detail=str(exc)) from exc


@router.get("/api/v1/users/{user_id}/scan-scopes")
def users_scan_scopes_list(user_id: str, request: Request):
    principal=current_principal(request)
    try:
        return list_user_scan_scopes(principal,user_id)
    except PermissionError as exc:
        raise HTTPException(status_code=403,detail=str(exc)) from exc
    except ValueError:
        raise HTTPException(status_code=404,detail="user not found")


@router.post("/api/v1/users/{user_id}/scan-scopes")
def users_scan_scopes_set(user_id: str, request: Request, payload: UserScopeRequest):
    principal=current_principal(request)
    try:
        result=assign_scan_scope_to_user(principal,user_id,payload.scope_id)
        audit(principal,"scan_scope_change","user",user_id,result)
        return result
    except PermissionError as exc:
        raise HTTPException(status_code=403,detail=str(exc)) from exc
    except ValueError as exc:
        raise HTTPException(status_code=400,detail=str(exc)) from exc


@router.patch("/api/v1/users/{user_id}")
def users_update(user_id: str, request: Request, payload: UserUpdateRequest):
    principal=current_principal(request)
    try:
        result=update_user(principal,user_id,payload.name,payload.role)
        audit(
            principal,
            "update",
            "user",
            user_id,
            {"role":payload.role} if payload.role else {},
        )
        return result
    except PermissionError as exc:
        raise HTTPException(status_code=403,detail=str(exc)) from exc
    except ValueError as exc:
        raise HTTPException(status_code=400,detail=str(exc)) from exc


@router.patch("/api/v1/users/{user_id}/active")
def users_active(user_id: str, request: Request, payload: UserActiveRequest):
    principal=current_principal(request)
    try:
        result=set_user_active(principal,user_id,payload.active)
        audit(
            principal,
            "activate" if payload.active else "deactivate",
            "user",
            user_id,
        )
        return result
    except PermissionError as exc:
        raise HTTPException(status_code=403,detail=str(exc)) from exc
    except ValueError as exc:
        raise HTTPException(status_code=400,detail=str(exc)) from exc


@router.post("/api/v1/users/{user_id}/reset-password")
def users_reset_password(user_id: str, request: Request, payload: UserPasswordResetRequest):
    principal=current_principal(request)
    if not rate_limit_action("password-reset",principal.user_id,limit=5,window_seconds=300):
        raise HTTPException(status_code=429,detail="too many password reset attempts")
    try:
        result=reset_user_password(principal,user_id,payload.password)
        audit(principal,"reset_password","user",user_id)
        return result
    except PermissionError as exc:
        raise HTTPException(status_code=403,detail=str(exc)) from exc
    except ValueError as exc:
        raise HTTPException(status_code=400,detail=str(exc)) from exc
