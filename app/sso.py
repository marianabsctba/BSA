"""OIDC single sign-on for BSA.

The federation layer is intentionally conservative:
- authorization code + PKCE
- signed short-lived state cookie + nonce
- issuer/audience/JWKS validation
- no JIT user or tenant provisioning
- local tenant/RBAC remain authoritative
- MFA claims are required when the local tenant policy requires MFA
"""
from __future__ import annotations

import base64
import hashlib
import hmac
import json
import os
import secrets
import time
import urllib.parse
import urllib.request
from dataclasses import dataclass
from typing import Any

import jwt

from . import auth

STATE_TTL_SECONDS = 300
DISCOVERY_TTL_SECONDS = 300
_DISCOVERY_CACHE: dict[str, tuple[int, dict[str, Any]]] = {}


@dataclass(frozen=True)
class OIDCConfig:
    issuer: str
    client_id: str
    client_secret: str | None
    redirect_uri: str
    success_url: str
    scopes: str = "openid email profile"


def _is_production() -> bool:
    return os.getenv("BSA_ENV", "development").lower() in {"production", "prod"}


def config_from_env() -> OIDCConfig | None:
    issuer=os.getenv("BSA_OIDC_ISSUER", "").strip().rstrip("/")
    client_id=os.getenv("BSA_OIDC_CLIENT_ID", "").strip()
    redirect_uri=os.getenv("BSA_OIDC_REDIRECT_URI", "").strip()
    if not issuer or not client_id or not redirect_uri:
        return None
    _validate_https_url(issuer, "issuer")
    _validate_https_url(redirect_uri, "redirect URI", allow_loopback=not _is_production())
    secret=os.getenv("BSA_JWT_SECRET", "")
    if len(secret) < 32:
        raise RuntimeError("BSA_JWT_SECRET must be at least 32 characters when OIDC is enabled")
    return OIDCConfig(
        issuer=issuer,
        client_id=client_id,
        client_secret=os.getenv("BSA_OIDC_CLIENT_SECRET", "").strip() or None,
        redirect_uri=redirect_uri,
        success_url=os.getenv("BSA_OIDC_SUCCESS_URL", "/").strip() or "/",
        scopes=os.getenv("BSA_OIDC_SCOPES", "openid email profile").strip() or "openid email profile",
    )


def _validate_https_url(value: str, label: str, *, allow_loopback: bool=False) -> None:
    parsed=urllib.parse.urlparse(value)
    if parsed.scheme not in {"https", "http"} or not parsed.hostname or parsed.username or parsed.password:
        raise RuntimeError(f"invalid OIDC {label}")
    if _is_production() and parsed.scheme != "https":
        raise RuntimeError(f"OIDC {label} must use HTTPS in production")
    if not allow_loopback and parsed.hostname in {"localhost", "127.0.0.1", "::1"}:
        raise RuntimeError(f"OIDC {label} cannot use loopback")


def _json_request(url: str, *, data: bytes | None=None, headers: dict[str,str] | None=None) -> dict[str, Any]:
    _validate_https_url(url, "endpoint", allow_loopback=not _is_production())
    request=urllib.request.Request(url, data=data, headers=headers or {}, method="POST" if data is not None else "GET")
    with urllib.request.urlopen(request, timeout=8) as response:  # nosec B310 - URL is server configuration/discovery, validated above
        if int(getattr(response, "status", 200)) >= 400:
            raise RuntimeError("OIDC endpoint returned an error")
        payload=json.loads(response.read().decode("utf-8"))
    if not isinstance(payload, dict):
        raise RuntimeError("invalid OIDC response")
    return payload


def discovery(config: OIDCConfig) -> dict[str, Any]:
    now=int(time.time())
    cached=_DISCOVERY_CACHE.get(config.issuer)
    if cached and now-cached[0] < DISCOVERY_TTL_SECONDS:
        return cached[1]
    metadata=_json_request(config.issuer + "/.well-known/openid-configuration")
    if str(metadata.get("issuer") or "").rstrip("/") != config.issuer:
        raise RuntimeError("OIDC discovery issuer mismatch")
    for key in ("authorization_endpoint", "token_endpoint", "jwks_uri"):
        value=str(metadata.get(key) or "")
        _validate_https_url(value, key, allow_loopback=not _is_production())
    _DISCOVERY_CACHE[config.issuer]=(now, metadata)
    return metadata


def _b64url(raw: bytes) -> str:
    return base64.urlsafe_b64encode(raw).rstrip(b"=").decode("ascii")


def _state_key() -> bytes:
    secret=os.getenv("BSA_JWT_SECRET", "")
    if len(secret) < 32:
        raise RuntimeError("BSA_JWT_SECRET must be at least 32 characters when OIDC is enabled")
    return hashlib.sha256((secret + ":oidc-state").encode()).digest()


def build_state_cookie(state: str, nonce: str, verifier: str, *, now: int | None=None) -> str:
    payload={"state":state,"nonce":nonce,"verifier":verifier,"iat":int(now or time.time())}
    body=_b64url(json.dumps(payload,separators=(",",":"),sort_keys=True).encode())
    signature=_b64url(hmac.new(_state_key(),body.encode(),hashlib.sha256).digest())
    return body + "." + signature


def parse_state_cookie(value: str, expected_state: str, *, now: int | None=None) -> dict[str, Any]:
    try:
        body,signature=value.split(".",1)
        expected=_b64url(hmac.new(_state_key(),body.encode(),hashlib.sha256).digest())
        if not hmac.compare_digest(signature,expected):
            raise ValueError("invalid SSO state")
        padded=body + "="*((4-len(body)%4)%4)
        payload=json.loads(base64.urlsafe_b64decode(padded.encode()).decode())
    except Exception as exc:
        raise ValueError("invalid SSO state") from exc
    if not hmac.compare_digest(str(payload.get("state") or ""), str(expected_state or "")):
        raise ValueError("invalid SSO state")
    age=int(now or time.time())-int(payload.get("iat") or 0)
    if age < 0 or age > STATE_TTL_SECONDS:
        raise ValueError("expired SSO state")
    if not payload.get("nonce") or not payload.get("verifier"):
        raise ValueError("invalid SSO state")
    return payload


def build_authorization_request(config: OIDCConfig) -> tuple[str,str]:
    metadata=discovery(config)
    state=secrets.token_urlsafe(24)
    nonce=secrets.token_urlsafe(24)
    verifier=secrets.token_urlsafe(48)
    challenge=_b64url(hashlib.sha256(verifier.encode()).digest())
    query=urllib.parse.urlencode({
        "response_type":"code",
        "client_id":config.client_id,
        "redirect_uri":config.redirect_uri,
        "scope":config.scopes,
        "state":state,
        "nonce":nonce,
        "code_challenge":challenge,
        "code_challenge_method":"S256",
    })
    return str(metadata["authorization_endpoint"]) + "?" + query, build_state_cookie(state,nonce,verifier)


def exchange_code(config: OIDCConfig, code: str, verifier: str) -> dict[str, Any]:
    metadata=discovery(config)
    form={
        "grant_type":"authorization_code",
        "code":code,
        "redirect_uri":config.redirect_uri,
        "client_id":config.client_id,
        "code_verifier":verifier,
    }
    if config.client_secret:
        form["client_secret"]=config.client_secret
    payload=urllib.parse.urlencode(form).encode()
    return _json_request(
        str(metadata["token_endpoint"]),
        data=payload,
        headers={"Content-Type":"application/x-www-form-urlencoded","Accept":"application/json"},
    )


def validate_id_token(config: OIDCConfig, id_token: str, nonce: str) -> dict[str, Any]:
    metadata=discovery(config)
    jwk_client=jwt.PyJWKClient(str(metadata["jwks_uri"]), cache_keys=True)
    signing_key=jwk_client.get_signing_key_from_jwt(id_token)
    claims=jwt.decode(
        id_token,
        signing_key.key,
        algorithms=["RS256","RS384","RS512","ES256","ES384","ES512"],
        audience=config.client_id,
        issuer=config.issuer,
        options={"require":["exp","iat","iss","aud","sub"]},
    )
    if not hmac.compare_digest(str(claims.get("nonce") or ""), nonce):
        raise ValueError("OIDC nonce mismatch")
    email=str(claims.get("email") or "").strip().lower()
    if not email:
        raise ValueError("OIDC email claim required")
    if os.getenv("BSA_OIDC_REQUIRE_EMAIL_VERIFIED","1") != "0" and claims.get("email_verified") is not True:
        raise ValueError("OIDC verified email required")
    return claims


def _federated_mfa(claims: dict[str, Any]) -> bool:
    amr=claims.get("amr") or []
    if isinstance(amr,str):
        amr=[amr]
    methods={str(value).lower() for value in amr if value}
    if methods & {"mfa","otp","fido","webauthn","hwk","sms"}:
        return True
    allowed_acr={x.strip() for x in os.getenv("BSA_OIDC_MFA_ACR_VALUES","").split(",") if x.strip()}
    return bool(allowed_acr and str(claims.get("acr") or "") in allowed_acr)


def issue_local_session(claims: dict[str, Any]) -> tuple[str, auth.Principal]:
    """Map a verified federated identity to an existing local user and issue a BSA session."""
    email=str(claims.get("email") or "").strip().lower()
    if not email:
        raise PermissionError("federated identity has no email")
    conn=auth._db()
    row=conn.execute(
        """SELECT u.id,u.tenant_id,u.email,u.name,u.role,u.active,t.active AS tenant_active
           FROM users u JOIN tenants t ON t.id=u.tenant_id WHERE lower(u.email)=?""",
        (email,),
    ).fetchone()
    conn.close()
    if not row or not row["active"] or not row["tenant_active"]:
        raise PermissionError("SSO user is not provisioned or inactive")

    auth.role_permissions(row["role"],row["tenant_id"])
    policy=auth.tenant_mfa_policy(row["tenant_id"])
    required_roles=set(policy.get("mfa_required_roles") or [])
    if row["role"] in required_roles and not _federated_mfa(claims):
        raise PermissionError("federated MFA required for this role")

    now=int(time.time())
    exp=now+auth.TOKEN_TTL
    jti=secrets.token_urlsafe(24)
    conn=auth._db()
    conn.execute(
        "INSERT INTO sessions(jti,user_id,tenant_id,created_at,expires_at,last_seen_at) VALUES(?,?,?,?,?,?)",
        (jti,row["id"],row["tenant_id"],now,exp,now),
    )
    conn.commit(); conn.close()
    token=auth._token({
        "sub":row["id"],"tenant":row["tenant_id"],"email":row["email"],"name":row["name"],
        "role":row["role"],"iat":now,"exp":exp,"jti":jti,"amr":"oidc",
    })
    principal=auth.Principal(row["id"],row["tenant_id"],row["email"],row["role"],row["name"])
    return token,principal
