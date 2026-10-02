from fastapi import HTTPException, Request

from ..auth import can, principal_from_token
from ..scope import asset_in_scope


def current_principal(request: Request):
    header=request.headers.get("Authorization","")
    token=header[7:] if header.startswith("Bearer ") else request.cookies.get("bsa_session","")
    if not token:
        raise HTTPException(status_code=401,detail="authentication required")
    try:
        principal=principal_from_token(token)
        request.state.authenticated_principal=principal
        return principal
    except Exception as exc:
        raise HTTPException(status_code=401,detail="invalid or expired token") from exc


def require(request: Request, permission: str):
    principal=current_principal(request)
    if not can(principal,permission):
        raise HTTPException(status_code=403,detail="permission denied")
    return principal


def tenant_scope(principal, assets, findings):
    scoped_assets=[
        asset for asset in assets
        if getattr(asset,"tenant_id","tenant-demo")==principal.tenant_id
        and asset_in_scope(principal,asset.value)
    ]
    scoped_ids={asset.id for asset in scoped_assets}
    scoped_findings=[
        finding for finding in findings
        if getattr(finding,"tenant_id","tenant-demo")==principal.tenant_id
        and finding.asset_id in scoped_ids
    ]
    return scoped_assets,scoped_findings
