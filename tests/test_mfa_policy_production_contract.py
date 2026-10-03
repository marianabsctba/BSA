from app import auth
from app.api.routers import auth as auth_router


class _Request:
    pass


def test_production_policy_cannot_remove_admin_or_superadmin(monkeypatch):
    principal=auth.Principal(
        user_id="admin-1",
        tenant_id="tenant-1",
        email="admin@example.org",
        role="admin",
        name="Admin",
    )
    captured={}
    monkeypatch.setenv("BSA_ENV","production")
    monkeypatch.setattr(auth_router,"current_principal",lambda request: principal)
    monkeypatch.setattr(
        auth_router,
        "set_tenant_mfa_policy",
        lambda principal,roles: captured.update({"roles":roles}) or {
            "tenant_id":"tenant-1",
            "mfa_required_roles":roles,
            "updated_at":1,
        },
    )
    monkeypatch.setattr(auth_router,"audit",lambda *args,**kwargs: None)

    result=auth_router.tenant_mfa_policy_update(
        _Request(),
        auth_router.MFAPolicyRequest(required_roles=[]),
    )

    assert set(captured["roles"])=={"admin","superadmin"}
    assert set(result["mfa_required_roles"])=={"admin","superadmin"}
