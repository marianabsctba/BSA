from types import SimpleNamespace

import pytest

import app.main as main
from app.api.routers import ctem as ctem_router


def _principal(tenant_id="tenant-a"):
    return SimpleNamespace(tenant_id=tenant_id, role="admin", user_id="user-a")


def test_ctem_audit_endpoint_is_tenant_scoped(monkeypatch):
    principal=_principal()
    monkeypatch.setattr(ctem_router, "require", lambda request, permission: principal)
    monkeypatch.setattr(
        ctem_router,
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
        ctem_router,
        "ctem_transition_history",
        lambda item_id, tenant_id: [
            {
                "event":"lifecycle",
                "action":"acknowledge",
                "from_state":"new",
                "to_state":"acknowledged",
                "state":"acknowledged",
                "actor_id":"user-a",
                "request_id":"req-1",
                "timestamp":"2026-10-01T10:30:00+00:00",
                "evidence_refs":[],
            }
        ],
    )
    monkeypatch.setattr(
        ctem_router,
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

    result=ctem_router.ctem_audit("item-a",None)

    assert result["item_id"]=="item-a"
    assert result["outcome"]["verification_count"]==1
    assert result["timeline"][0]["evidence_refs"]==["evidence-a"]
    assert result["timeline"][1]["event"]=="lifecycle"
    assert result["timeline"][1]["action"]=="acknowledge"
    assert result["timeline"][1]["to_state"]=="acknowledged"
    assert result["timeline"][2]["evidence_refs"]==["verify-a"]


def test_ctem_audit_does_not_resolve_other_tenant_item(monkeypatch):
    principal=_principal("tenant-a")
    monkeypatch.setattr(ctem_router, "require", lambda request, permission: principal)
    monkeypatch.setattr(ctem_router, "list_ctem_items", lambda tenant_id: [])

    with pytest.raises(ctem_router.HTTPException) as exc:
        ctem_router.ctem_audit("tenant-b-item",None)

    assert exc.value.status_code==404


def test_ctem_transition_history_is_tenant_scoped(tmp_path,monkeypatch):
    import app.history as history

    monkeypatch.setenv("BSA_HISTORY_DB",str(tmp_path/"history.db"))
    history.record_ctem_transition(
        "shared-item","tenant-a","acknowledge","new","acknowledged",
        actor_id="user-a",request_id="request-a",
    )
    history.record_ctem_transition(
        "shared-item","tenant-b","acknowledge","new","acknowledged",
        actor_id="user-b",request_id="request-b",
    )

    rows=history.ctem_transition_history("shared-item","tenant-a")

    assert len(rows)==1
    assert rows[0]["actor_id"]=="user-a"
    assert rows[0]["request_id"]=="request-a"
    assert rows[0]["to_state"]=="acknowledged"


def test_ctem_audit_timeline_orders_lifecycle_before_verification():
    import app.history as history

    item={
        "state":"verified",
        "priority":90,
        "created_at":"2026-10-01T10:00:00+00:00",
        "evidence_refs":["evidence-a"],
    }
    transitions=[{
        "event":"lifecycle","action":"submit_for_verification",
        "from_state":"in_progress","to_state":"resolved","state":"resolved",
        "timestamp":"2026-10-01T10:30:00+00:00","evidence_refs":[],
    }]
    verifications=[{
        "result":"passed","state":"verified","evidence_refs":["verify-a"],
        "notes":"passed","verified_at":"2026-10-01T11:00:00+00:00",
    }]

    timeline=history.ctem_audit_timeline(item,verifications,transitions)

    assert [x["event"] for x in timeline]==["created","lifecycle","verification"]
    assert timeline[0]["state"]=="new"
    assert timeline[-1]["state"]=="verified"
