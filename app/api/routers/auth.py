import ipaddress
import os

from fastapi import APIRouter, HTTPException, Request
from fastapi.responses import JSONResponse
from pydantic import BaseModel, Field

from ...auth import (
    TOKEN_TTL,
    _rate_limit_blocked,
    audit,
    authenticate,
    can,
    change_own_password,
    generate_mfa_recovery_codes,
    issue_mfa_recovery_codes,
    mfa_disable,
    mfa_enable,
    mfa_enroll,
    mfa_status,
    principal_from_token,
    rate_limit_action,
    revoke_session,
    role_permissions,
    set_tenant_mfa_policy,
    tenant_mfa_policy,
    tenant_settings,
)
from ..dependencies import current_principal


router=APIRouter()
LOGIN_RATE_LIMIT_WINDOW_SECONDS=900


class LoginRequest(BaseModel):
    email: str
    password: str = Field(min_length=8, max_length=256)
    mfa_code: str | None = Field(default=None, min_length=6, max_length=64)


class MFAEnrollRequest(BaseModel):
    current_password: str = Field(min_length=1, max_length=256)
    current_mfa_code: str | None = Field(default=None, min_length=6, max_length=64)


class MFAEnableRequest(BaseModel):
    code: str = Field(min_length=6, max_length=6)


class MFAReauthRequest(BaseModel):
    current_password: str = Field(min_length=1, max_length=256)
    current_mfa_code: str = Field(min_length=6, max_length=64)


class MFAPolicyRequest(BaseModel):
    required_roles: list[str] = Field(default_factory=list)


class ChangeOwnPasswordRequest(BaseModel):
    current_password: str = Field(min_length=1, max_length=256)
    new_password: str = Field(min_length=12, max_length=256)


def _client_ip(request: Request) -> str:
    peer=(request.client.host if request.client else "") or "unknown"
    if os.getenv("BSA_TRUST_PROXY_HEADERS","0")!="1":
        return peer
    try:
        peer_ip=ipaddress.ip_address(peer)
    except ValueError:
        return peer
    if not (peer_ip.is_private or peer_ip.is_loopback):
        return peer
    forwarded=(request.headers.get("X-Real-IP") or "").strip()
    try:
        return str(ipaddress.ip_address(forwarded)) if forwarded else peer
    except ValueError:
        return peer


def _login_rate_limited(email: str, client_ip: str) -> bool:
    account=(email or "").strip().lower()
    source=(client_ip or "").strip() or "unknown"
    return _rate_limit_blocked("login-account",account) or _rate_limit_blocked("login-ip",source)


def _login_rate_limit_error() -> HTTPException:
    return HTTPException(
        status_code=429,
        detail="too many login attempts",
        headers={"Retry-After":str(LOGIN_RATE_LIMIT_WINDOW_SECONDS)},
    )


@router.post("/api/v1/auth/logout")
def auth_logout(request: Request):
    principal=current_principal(request)
    auth=request.headers.get("Authorization","")
    token=auth.split(" ",1)[1] if auth.lower().startswith("bearer ") else request.cookies.get("bsa_session","")
    try:
        claims=__import__("app.auth",fromlist=["_decode"])._decode(token)
        revoke_session(principal,claims.get("jti"))
    except Exception:
        revoke_session(principal)
    response=JSONResponse({"ok":True})
    response.delete_cookie("bsa_session",path="/")
    return response


@router.get("/api/v1/auth/mfa")
def auth_mfa_status(request: Request):
    principal=current_principal(request)
    return mfa_status(principal)


@router.post("/api/v1/auth/mfa/enroll")
def auth_mfa_enroll(request: Request, payload: MFAEnrollRequest):
    principal=current_principal(request)
    if not rate_limit_action("mfa-enroll",principal.user_id,limit=5,window_seconds=300):
        raise HTTPException(status_code=429,detail="too many MFA enrollment attempts")
    try:
        result=mfa_enroll(
            principal,
            payload.current_password,
            payload.current_mfa_code,
        )
        audit(principal,"enroll","mfa")
        return result
    except PermissionError as exc:
        raise HTTPException(status_code=403,detail=str(exc)) from exc
    except ValueError as exc:
        raise HTTPException(status_code=400,detail=str(exc)) from exc


@router.post("/api/v1/auth/mfa/enable")
def auth_mfa_enable(request: Request, payload: MFAEnableRequest):
    principal=current_principal(request)
    if not rate_limit_action("mfa-enable",principal.user_id,limit=5,window_seconds=300):
        raise HTTPException(status_code=429,detail="too many MFA attempts")
    try:
        if not mfa_enable(principal,payload.code):
            raise HTTPException(status_code=400,detail="invalid MFA code")
        recovery_codes=issue_mfa_recovery_codes(principal)
        audit(principal,"enable","mfa")
        return {"enabled":True,"recovery_codes":recovery_codes}
    except PermissionError as exc:
        raise HTTPException(status_code=403,detail=str(exc)) from exc


@router.post("/api/v1/auth/mfa/recovery-codes")
def auth_mfa_recovery_codes(request: Request, payload: MFAReauthRequest):
    principal=current_principal(request)
    if not rate_limit_action("mfa-recovery",principal.user_id,limit=3,window_seconds=300):
        raise HTTPException(status_code=429,detail="too many MFA recovery attempts")
    try:
        codes=generate_mfa_recovery_codes(
            principal,
            payload.current_password,
            payload.current_mfa_code,
        )
        audit(principal,"rotate_recovery_codes","mfa")
        return {"recovery_codes":codes}
    except PermissionError as exc:
        raise HTTPException(status_code=403,detail=str(exc)) from exc
    except ValueError as exc:
        raise HTTPException(status_code=400,detail=str(exc)) from exc


@router.post("/api/v1/auth/mfa/disable")
def auth_mfa_disable(request: Request, payload: MFAReauthRequest):
    principal=current_principal(request)
    if not rate_limit_action("mfa-disable",principal.user_id,limit=3,window_seconds=300):
        raise HTTPException(status_code=429,detail="too many MFA disable attempts")
    try:
        mfa_disable(
            principal,
            payload.current_password,
            payload.current_mfa_code,
        )
        audit(principal,"disable","mfa")
        return {"enabled":False}
    except PermissionError as exc:
        raise HTTPException(status_code=403,detail=str(exc)) from exc
    except ValueError as exc:
        raise HTTPException(status_code=400,detail=str(exc)) from exc


@router.get("/api/v1/tenant/security/mfa")
def tenant_mfa_policy_get(request: Request):
    principal=current_principal(request)
    if principal.role not in {"admin","superadmin"} and not can(principal,"tenant:manage"):
        raise HTTPException(status_code=403,detail="admin required")
    return tenant_mfa_policy(principal.tenant_id)


@router.put("/api/v1/tenant/security/mfa")
def tenant_mfa_policy_update(request: Request, payload: MFAPolicyRequest):
    principal=current_principal(request)
    try:
        result=set_tenant_mfa_policy(principal,payload.required_roles)
        audit(
            principal,
            "update",
            "tenant_mfa_policy",
            principal.tenant_id,
            {"required_roles":result["mfa_required_roles"]},
        )
        return result
    except PermissionError as exc:
        raise HTTPException(status_code=403,detail=str(exc)) from exc
    except ValueError as exc:
        raise HTTPException(status_code=400,detail=str(exc)) from exc


@router.post("/api/v1/auth/login")
def login(payload: LoginRequest, request: Request):
    client_ip=_client_ip(request)
    token=authenticate(
        payload.email,
        payload.password,
        client_ip,
        payload.mfa_code,
    )
    if not token:
        # Password verification happens before throttle enforcement so a valid
        # credential can recover from a challenge while invalid attempts remain
        # rate-limited at both account and source-IP scope.
        if _login_rate_limited(payload.email,client_ip):
            raise _login_rate_limit_error()
        raise HTTPException(status_code=401,detail="invalid credentials")
    principal=principal_from_token(token)
    audit(principal,"login","session")
    response=JSONResponse({
        "token_type":"bearer",
        "expires_in":TOKEN_TTL,
        "user":{
            "id":principal.user_id,
            "email":principal.email,
            "name":principal.name,
            "role":principal.role,
            "tenant_id":principal.tenant_id,
        },
    })
    response.set_cookie(
        "bsa_session",
        token,
        httponly=True,
        secure=os.getenv("BSA_ENV","development").lower() in {"production","prod"},
        samesite="strict",
        max_age=TOKEN_TTL,
        path="/",
    )
    return response


@router.post("/api/v1/auth/change-password")
def auth_change_password(request: Request, payload: ChangeOwnPasswordRequest):
    principal=current_principal(request)
    if not rate_limit_action("change-password",principal.user_id,limit=5,window_seconds=300):
        raise HTTPException(status_code=429,detail="too many password change attempts")
    try:
        result=change_own_password(
            principal,
            payload.current_password,
            payload.new_password,
        )
        audit(principal,"change_password","user",principal.user_id)
        response=JSONResponse(result)
        response.delete_cookie("bsa_session",path="/")
        return response
    except PermissionError as exc:
        raise HTTPException(status_code=403,detail=str(exc)) from exc
    except ValueError as exc:
        raise HTTPException(status_code=400,detail=str(exc)) from exc


@router.get("/api/v1/auth/me")
def me(request: Request):
    principal=current_principal(request)
    tenant=tenant_settings(principal)
    return {
        "id":principal.user_id,
        "email":principal.email,
        "name":principal.name,
        "role":principal.role,
        "tenant_id":principal.tenant_id,
        "tenant_name":tenant["name"],
        "locale":tenant["locale"],
    }


@router.get("/api/v1/auth/permissions")
def auth_permissions(request: Request):
    principal=current_principal(request)
    try:
        return {
            "role":principal.role,
            "permissions":role_permissions(principal.role,principal.tenant_id),
        }
    except ValueError as exc:
        raise HTTPException(status_code=403,detail="invalid role permissions") from exc
