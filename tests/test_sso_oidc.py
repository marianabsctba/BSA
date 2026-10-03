import hashlib
import json
import urllib.parse

import pytest

from app import auth, sso


SECRET="s"*64


def _security_env(monkeypatch):
    monkeypatch.setenv("BSA_JWT_SECRET",SECRET)
    monkeypatch.setattr(auth,"JWT_SECRET",SECRET)


def _provision_user(tmp_path, monkeypatch, *, email="admin@example.org", role="admin", mfa_roles=None):
    _security_env(monkeypatch)
    monkeypatch.setattr(auth,"DB_PATH",str(tmp_path/"auth.db"))
    conn=auth._db()
    conn.execute("INSERT INTO tenants(id,name,active) VALUES(?,?,1)",( "tenant-a","Tenant A"))
    conn.execute(
        "INSERT INTO users(id,tenant_id,email,name,password_hash,role,active,created_at) VALUES(?,?,?,?,?,?,1,1)",
        ("user-a","tenant-a",email,"SSO User","unused",role),
    )
    if mfa_roles is not None:
        conn.execute(
            "INSERT INTO tenant_security_policy(tenant_id,mfa_required_roles,updated_at) VALUES(?,?,1)",
            ("tenant-a",json.dumps(mfa_roles)),
        )
    conn.commit(); conn.close()


def test_oidc_state_cookie_rejects_tamper_and_expiry(monkeypatch):
    _security_env(monkeypatch)
    cookie=sso.build_state_cookie("state-a","nonce-a","verifier-a",now=1000)
    parsed=sso.parse_state_cookie(cookie,"state-a",now=1100)
    assert parsed["nonce"]=="nonce-a"
    tampered=cookie[:-1]+("A" if cookie[-1]!="A" else "B")
    with pytest.raises(ValueError):
        sso.parse_state_cookie(tampered,"state-a",now=1100)
    with pytest.raises(ValueError):
        sso.parse_state_cookie(cookie,"state-a",now=1400)
    with pytest.raises(ValueError):
        sso.parse_state_cookie(cookie,"different-state",now=1100)


def test_oidc_authorization_request_uses_pkce_and_nonce(monkeypatch):
    _security_env(monkeypatch)
    cfg=sso.OIDCConfig(
        issuer="https://id.example.org",
        client_id="client-a",
        client_secret=None,
        redirect_uri="https://asm.example.org/api/v1/auth/sso/callback",
        success_url="/",
    )
    monkeypatch.setattr(sso,"discovery",lambda config:{
        "issuer":config.issuer,
        "authorization_endpoint":"https://id.example.org/authorize",
        "token_endpoint":"https://id.example.org/token",
        "jwks_uri":"https://id.example.org/jwks",
    })
    url,cookie=sso.build_authorization_request(cfg)
    query=urllib.parse.parse_qs(urllib.parse.urlparse(url).query)
    state=query["state"][0]
    parsed=sso.parse_state_cookie(cookie,state)
    expected=sso._b64url(hashlib.sha256(parsed["verifier"].encode()).digest())
    assert query["response_type"]==["code"]
    assert query["code_challenge_method"]==["S256"]
    assert query["code_challenge"]==[expected]
    assert query["nonce"]==[parsed["nonce"]]


def test_sso_never_jit_provisions_unknown_identity(tmp_path, monkeypatch):
    _security_env(monkeypatch)
    monkeypatch.setattr(auth,"DB_PATH",str(tmp_path/"auth.db"))
    conn=auth._db()
    conn.execute("INSERT INTO tenants(id,name,active) VALUES(?,?,1)",( "tenant-a","Tenant A"))
    conn.commit(); conn.close()
    with pytest.raises(PermissionError,match="not provisioned"):
        sso.issue_local_session({"email":"unknown@example.org","amr":["mfa"]})
    conn=auth._db()
    assert conn.execute("SELECT COUNT(*) AS n FROM users").fetchone()["n"]==0
    conn.close()


def test_sso_uses_local_tenant_and_requires_federated_mfa_by_policy(tmp_path, monkeypatch):
    _provision_user(tmp_path,monkeypatch,mfa_roles=["admin"])
    with pytest.raises(PermissionError,match="MFA"):
        sso.issue_local_session({"email":"admin@example.org","amr":["pwd"]})

    token,principal=sso.issue_local_session({
        "email":"admin@example.org",
        "tenant":"attacker-controlled-tenant",
        "amr":["pwd","mfa"],
    })
    assert principal.tenant_id=="tenant-a"
    assert principal.role=="admin"
    verified=auth.principal_from_token(token)
    assert verified.user_id=="user-a"
    assert verified.tenant_id=="tenant-a"


def test_sso_non_mfa_role_can_use_verified_federation(tmp_path, monkeypatch):
    _provision_user(tmp_path,monkeypatch,email="viewer@example.org",role="viewer",mfa_roles=["admin","superadmin"])
    token,principal=sso.issue_local_session({"email":"viewer@example.org","amr":["pwd"]})
    assert principal.role=="viewer"
    assert auth.principal_from_token(token).email=="viewer@example.org"
