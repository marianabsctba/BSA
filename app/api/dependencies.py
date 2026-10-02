from fastapi import HTTPException, Request

from ..auth import can, principal_from_token
from .tenant_scope import tenant_scope as _tenant_scope


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
    return _tenant_scope(principal,assets,findings)
