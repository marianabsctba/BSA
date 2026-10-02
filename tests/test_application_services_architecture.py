from app.application.services.ctem_service import build_ctem_queue_page
from app.application.services.risk_service import build_risk_overview


def test_risk_overview_service_accepts_empty_scope():
    result=build_risk_overview([],[])
    assert result["summary"]["findings"]==0
    assert result["summary"]["average"]==0
    assert result["items"]==[]


def test_ctem_queue_service_isolated_by_tenant(monkeypatch):
    monkeypatch.setattr(
        "app.application.services.ctem_service.list_ctem_items",
        lambda tenant_id: [
            {"item_id":"a","state":"acknowledged","priority":90}
        ] if tenant_id=="tenant-a" else [],
    )
    monkeypatch.setattr(
        "app.application.services.ctem_service.ctem_queue_filter",
        lambda items,**kwargs: items,
    )
    monkeypatch.setattr(
        "app.application.services.ctem_service.ctem_queue_page",
        lambda items,page,page_size: {"page":page,"page_size":page_size,"items":items},
    )
    monkeypatch.setattr(
        "app.application.services.ctem_service.ctem_next_action",
        lambda item:"start_remediation",
    )

    a=build_ctem_queue_page("tenant-a")
    b=build_ctem_queue_page("tenant-b")

    assert [x["item_id"] for x in a["items"]]==["a"]
    assert b["items"]==[]
