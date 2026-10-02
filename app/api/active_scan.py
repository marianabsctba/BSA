import os

from fastapi import HTTPException, Request

from ..auth import audit, rate_limit_action
from ..scan_authorization import authorization_grant_valid
from ..scope import active_scan_in_scope


IS_PRODUCTION=os.getenv("BSA_ENV","development").lower() in {"production","prod"}


def govern_active_scan(
    http_request: Request,
    principal,
    target: str,
    authorization_ref: str | None = None,
):
    ref=(authorization_ref or http_request.headers.get("X-Authorization-Ref","")).strip()
    if IS_PRODUCTION and not ref:
        raise HTTPException(
            status_code=400,
            detail="authorization_ref is required for active scans",
        )
    if IS_PRODUCTION and not authorization_grant_valid(principal,ref,target):
        raise HTTPException(
            status_code=403,
            detail="authorization_ref is expired, revoked, or not valid for target",
        )
    if not active_scan_in_scope(principal,target):
        raise HTTPException(status_code=403,detail="target not authorized for active scanning")

    rate_key=f"{principal.tenant_id}:{principal.user_id}"
    if not rate_limit_action("active-scan",rate_key,limit=30,window_seconds=300):
        raise HTTPException(status_code=429,detail="active scan rate limit exceeded")

    audit(
        principal,
        "request",
        "active_scan",
        target,
        {
            "authorization_ref":ref or "development",
            "method":http_request.method,
            "path":http_request.url.path,
        },
    )
    return ref
