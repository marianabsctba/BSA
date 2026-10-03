import os

from fastapi import APIRouter, HTTPException, Request
from fastapi.responses import JSONResponse, RedirectResponse

from ...auth import TOKEN_TTL, audit
from ...sso import (
    build_authorization_request,
    config_from_env,
    exchange_code,
    issue_local_session,
    parse_state_cookie,
    validate_id_token,
)


router=APIRouter()
STATE_COOKIE="bsa_oidc_state"
STATE_COOKIE_PATH="/api/v1/auth/sso"


def _secure_cookie() -> bool:
    return os.getenv("BSA_ENV","development").lower() in {"production","prod"}


def _clear_state(response):
    response.delete_cookie(STATE_COOKIE,path=STATE_COOKIE_PATH)
    return response


@router.get("/api/v1/auth/sso/status")
def sso_status():
    try:
        cfg=config_from_env()
    except RuntimeError:
        return {"enabled":False,"mode":"oidc","authorization_code_pkce":True,"configuration_valid":False}
    return {
        "enabled":cfg is not None,
        "mode":"oidc",
        "authorization_code_pkce":True,
        "configuration_valid":cfg is not None,
    }


@router.get("/api/v1/auth/sso/login")
def sso_login():
    try:
        cfg=config_from_env()
        if cfg is None:
            raise HTTPException(status_code=404,detail="SSO is not configured")
        authorization_url,state_cookie=build_authorization_request(cfg)
    except HTTPException:
        raise
    except Exception as exc:
        raise HTTPException(status_code=503,detail="SSO provider unavailable") from exc
    response=RedirectResponse(authorization_url,status_code=302)
    response.set_cookie(
        STATE_COOKIE,
        state_cookie,
        httponly=True,
        secure=_secure_cookie(),
        samesite="lax",
        max_age=300,
        path=STATE_COOKIE_PATH,
    )
    return response


@router.get("/api/v1/auth/sso/callback")
def sso_callback(request: Request, code: str | None=None, state: str | None=None, error: str | None=None):
    cfg=config_from_env()
    if cfg is None:
        raise HTTPException(status_code=404,detail="SSO is not configured")
    if error or not code or not state:
        return _clear_state(JSONResponse(status_code=401,content={"detail":"SSO authentication failed"}))
    state_cookie=request.cookies.get(STATE_COOKIE,"")
    try:
        state_data=parse_state_cookie(state_cookie,state)
        tokens=exchange_code(cfg,code,str(state_data["verifier"]))
        id_token=str(tokens.get("id_token") or "")
        if not id_token:
            raise ValueError("OIDC ID token missing")
        claims=validate_id_token(cfg,id_token,str(state_data["nonce"]))
        token,principal=issue_local_session(claims)
        audit(
            principal,
            "login",
            "session",
            None,
            {"authentication":"oidc","federated_mfa":bool(claims.get("amr") or claims.get("acr"))},
        )
    except Exception:
        return _clear_state(JSONResponse(status_code=401,content={"detail":"SSO authentication failed"}))

    response=RedirectResponse(cfg.success_url,status_code=302)
    response.set_cookie(
        "bsa_session",
        token,
        httponly=True,
        secure=_secure_cookie(),
        samesite="strict",
        max_age=TOKEN_TTL,
        path="/",
    )
    return _clear_state(response)
