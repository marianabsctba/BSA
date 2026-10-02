from app.changes import seed_changes
from app.models import Asset, AssetType


def test_change_engine_emits_tagged_changes():
    assets = [Asset(
        id="a1", value="vpn.example.org", type=AssetType.SUBDOMAIN,
        confidence=90, criticality=5, source="dns",
        tags=["new", "changed"], first_seen="now", last_seen="now"
    )]
    changes = seed_changes(assets)
    assert len(changes) == 2
    assert {c.kind for c in changes} == {"new_asset", "service_change"}


def test_changes_endpoint_filters_out_of_scope_history(monkeypatch):
    from types import SimpleNamespace

    from app.api.routers import graph_assessment as graph_assessment_router

    principal=SimpleNamespace(tenant_id="tenant-a",user_id="user-a",role="analyst")
    visible=SimpleNamespace(
        id="asset-visible",
        fingerprint="fp-visible",
        value="visible.example.org",
        type=SimpleNamespace(value="domain"),
    )
    monkeypatch.setattr(graph_assessment_router,"require",lambda request,permission:principal)
    monkeypatch.setattr(graph_assessment_router,"tenant_scope",lambda p:([visible],[]))
    monkeypatch.setattr(
        graph_assessment_router,
        "recent_change_events",
        lambda tenant_id,hours,limit:[
            {"fingerprint":"fp-visible","kind":"service_change"},
            {"fingerprint":"fp-hidden","kind":"service_change","asset":"hidden.example.org"},
        ],
    )

    result=graph_assessment_router.list_changes(None)

    assert result["count"]==1
    assert [item["fingerprint"] for item in result["items"]]==["fp-visible"]
    assert result["items"][0]["asset_id"]=="asset-visible"
