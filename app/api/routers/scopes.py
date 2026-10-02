from fastapi import APIRouter, HTTPException, Request
from pydantic import BaseModel, Field

from ...auth import audit
from ...scan_authorization import (
    create_authorization_grant,
    list_authorization_grants,
    revoke_authorization_grant,
)
from ...scope import (
    assign_scan_scope,
    assign_scope,
    create_domain_ownership_proof,
    create_ip_ownership_approval,
    create_scan_scope,
    create_scope,
    list_scan_scopes,
    list_scopes,
    verify_domain_ownership_proof,
)
from ..dependencies import current_principal, require


router=APIRouter()


class ScopeCreateRequest(BaseModel):
    name: str = Field(min_length=1, max_length=120)
    pattern: str = Field(min_length=1, max_length=253)
    ownership_ref: str | None = Field(default=None, max_length=200)


class ScopeAssignRequest(BaseModel):
    user_id: str
    scope_id: str


class DomainOwnershipProofRequest(BaseModel):
    domain: str = Field(min_length=3, max_length=253)
    method: str = Field(default="dns_txt", pattern="^(dns_txt|well_known)$")


class IPOwnershipApprovalRequest(BaseModel):
    ip: str = Field(min_length=3, max_length=64)
    tenant_id: str | None = Field(default=None, min_length=1, max_length=128)
    authorization_ref: str = Field(min_length=3, max_length=200)
    evidence_type: str = Field(default="contract", pattern="^(contract|rdap|whois|asn|ptr)$")
    ttl_seconds: int = Field(default=86400, ge=300, le=2592000)


class ScanGrantCreateRequest(BaseModel):
    user_id: str = Field(min_length=1, max_length=128)
    authorization_ref: str = Field(min_length=1, max_length=200)
    pattern: str = Field(min_length=1, max_length=253)
    ttl_seconds: int = Field(default=3600, ge=60, le=2592000)


@router.get("/api/v1/scopes")
def scopes(request: Request):
    principal=require(request,"users:read")
    return list_scopes(principal)


@router.post("/api/v1/scopes")
def scopes_create(request: Request, payload: ScopeCreateRequest):
    principal=current_principal(request)
    try:
        result=create_scope(principal,payload.name,payload.pattern)
        audit(principal,"create","scope",result["id"],{"pattern":payload.pattern})
        return result
    except PermissionError as exc:
        raise HTTPException(status_code=403,detail=str(exc)) from exc


@router.post("/api/v1/scopes/assign")
def scopes_assign(request: Request, payload: ScopeAssignRequest):
    principal=current_principal(request)
    try:
        assign_scope(principal,payload.user_id,payload.scope_id)
        audit(principal,"assign","scope",payload.scope_id,{"user_id":payload.user_id})
        return {"ok":True}
    except PermissionError as exc:
        raise HTTPException(status_code=403,detail=str(exc)) from exc
    except ValueError as exc:
        raise HTTPException(status_code=400,detail=str(exc)) from exc


@router.get("/api/v1/scan-scopes")
def scan_scopes(request: Request):
    principal=require(request,"users:read")
    return list_scan_scopes(principal)


@router.post("/api/v1/domain-ownership/proofs")
def domain_ownership_proof_create(request: Request, payload: DomainOwnershipProofRequest):
    principal=current_principal(request)
    try:
        result=create_domain_ownership_proof(principal,payload.domain,payload.method)
        audit(
            principal,
            "create",
            "domain_ownership_proof",
            result["proof_id"],
            {
                "domain":result["domain"],
                "method":result["method"],
                "expires_at":result["expires_at"],
            },
        )
        return result
    except PermissionError as exc:
        raise HTTPException(status_code=403,detail=str(exc)) from exc
    except ValueError as exc:
        raise HTTPException(status_code=400,detail=str(exc)) from exc


@router.post("/api/v1/domain-ownership/proofs/{proof_id}/verify")
def domain_ownership_proof_verify(proof_id: str, request: Request):
    principal=current_principal(request)
    try:
        result=verify_domain_ownership_proof(principal,proof_id)
        audit(
            principal,
            "verify",
            "domain_ownership_proof",
            proof_id,
            {
                "domain":result["domain"],
                "method":result["method"],
                "verified":result["verified"],
            },
        )
        return result
    except PermissionError as exc:
        raise HTTPException(status_code=403,detail=str(exc)) from exc
    except ValueError as exc:
        raise HTTPException(status_code=400,detail=str(exc)) from exc


@router.post("/api/v1/ip-ownership/approvals")
def ip_ownership_approval_create(request: Request, payload: IPOwnershipApprovalRequest):
    principal=current_principal(request)
    try:
        result=create_ip_ownership_approval(
            principal,
            payload.ip,
            payload.authorization_ref,
            payload.evidence_type,
            payload.ttl_seconds,
            payload.tenant_id,
        )
        audit(
            principal,
            "approve",
            "ip_ownership",
            result["approval_id"],
            {
                "ip":result["ip"],
                "tenant_id":result["tenant_id"],
                "authorization_ref":result["authorization_ref"],
                "evidence_type":result["evidence_type"],
                "expires_at":result["expires_at"],
            },
        )
        return result
    except PermissionError as exc:
        raise HTTPException(status_code=403,detail=str(exc)) from exc
    except ValueError as exc:
        raise HTTPException(status_code=400,detail=str(exc)) from exc


@router.post("/api/v1/scan-scopes")
def scan_scopes_create(request: Request, payload: ScopeCreateRequest):
    principal=current_principal(request)
    try:
        result=create_scan_scope(
            principal,
            payload.name,
            payload.pattern,
            payload.ownership_ref,
        )
        audit(
            principal,
            "create",
            "scan_scope",
            result["id"],
            {"pattern":payload.pattern,"ownership_ref":payload.ownership_ref},
        )
        return result
    except PermissionError as exc:
        raise HTTPException(status_code=403,detail=str(exc)) from exc


@router.post("/api/v1/scan-scopes/assign")
def scan_scopes_assign(request: Request, payload: ScopeAssignRequest):
    principal=current_principal(request)
    try:
        assign_scan_scope(principal,payload.user_id,payload.scope_id)
        audit(
            principal,
            "assign",
            "scan_scope",
            payload.scope_id,
            {"user_id":payload.user_id},
        )
        return {"ok":True}
    except PermissionError as exc:
        raise HTTPException(status_code=403,detail=str(exc)) from exc
    except ValueError as exc:
        raise HTTPException(status_code=400,detail=str(exc)) from exc


@router.get("/api/v1/scan-authorizations")
def scan_authorizations(request: Request):
    principal=require(request,"users:read")
    try:
        return list_authorization_grants(principal)
    except PermissionError as exc:
        raise HTTPException(status_code=403,detail=str(exc)) from exc


@router.post("/api/v1/scan-authorizations")
def scan_authorizations_create(request: Request, payload: ScanGrantCreateRequest):
    principal=current_principal(request)
    try:
        result=create_authorization_grant(
            principal,
            payload.user_id,
            payload.authorization_ref,
            payload.pattern,
            payload.ttl_seconds,
        )
        audit(
            principal,
            "create",
            "scan_authorization",
            result["grant_id"],
            {
                "user_id":payload.user_id,
                "pattern":payload.pattern,
                "expires_at":result["expires_at"],
            },
        )
        return result
    except PermissionError as exc:
        raise HTTPException(status_code=403,detail=str(exc)) from exc
    except ValueError as exc:
        raise HTTPException(status_code=400,detail=str(exc)) from exc


@router.post("/api/v1/scan-authorizations/{grant_id}/revoke")
def scan_authorizations_revoke(grant_id: str, request: Request):
    principal=current_principal(request)
    try:
        result=revoke_authorization_grant(principal,grant_id)
        audit(principal,"revoke","scan_authorization",grant_id,{})
        return result
    except PermissionError as exc:
        raise HTTPException(status_code=403,detail=str(exc)) from exc
    except ValueError as exc:
        raise HTTPException(status_code=404,detail=str(exc)) from exc
