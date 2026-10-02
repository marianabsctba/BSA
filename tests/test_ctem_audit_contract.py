from types import SimpleNamespace

import pytest

import app.main as main


def _principal(tenant_id="tenant-a"):
    return SimpleNamespace(tenant_id=tenant_id, role="admin", user_id="user-a")


def test_ctem_audit_endpoint_is_tenant_scoped(monkeypatch):
    principal=_principal()
    monkeypatch.setattr(main, "require", lambda request, permission: principal)
    monkeypatch.setattr(
        main,
        "list_ctem_items",
        lambda tenant_id: [
            {
                "item_id":"item-a",
                "tenant_id":"tenant-a",
                "state":"resolved",
                "priority":80,
                "evidence_refs":["evidence-a"],
                "created_at":"2026-10-01T10:00:00+00:00",
            }
        ] if tenant_id=="tenant-a" else [],
    )
    monkeypatch.setattr(
        main,
        "ctem_verification_history",
        lambda item_id, tenant_id: [
            {
                "result":"passed",
                "evidence_refs":["verify-a"],
                "notes":"retest passed",
                "verified_at":"2026-10-01T11:00:00+00:00",
            }
        ],
    )

    result=main.ctem_audit("item-a",None)

    assert result["item_id"]=="item-a"
    assert result["outcome"]["verification_count"]==1
    assert result["timeline"][0]["evidence_refs"]==["evidence-a"]
    assert result["timeline"][1]["evidence_refs"]==["verify-a"]


def test_ctem_audit_does_not_resolve_other_tenant_item(monkeypatch):
    principal=_principal("tenant-a")
    monkeypatch.setattr(main, "require", lambda request, permission: principal)
    monkeypatch.setattr(main, "list_ctem_items", lambda tenant_id: [])

    with pytest.raises(main.HTTPException) as exc:
        main.ctem_audit("tenant-b-item",None)

    assert exc.value.status_code==404
