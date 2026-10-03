from types import SimpleNamespace

from fastapi.testclient import TestClient

import app.main as main
from app import digital_risk
from app.api.routers import digital_risk as digital_risk_router
from app.drp_lifecycle import lifecycle_summary, update_event_lifecycle


client=TestClient(main.app)


def _principal(tenant_id: str):
    return SimpleNamespace(
        tenant_id=tenant_id,
        user_id=f"{tenant_id}-admin",
        email=f"{tenant_id}@example.org",
        role="admin",
        name=f"Admin {tenant_id}",
    )


def _event(tenant_id: str, indicator: str):
    return digital_risk.upsert_event(
        tenant_id,
        {
            "category":"credential_leak",
            "title":"Credential exposure",
            "indicator":indicator,
            "severity":"high",
            "confidence":90,
            "status":"open",
            "lifecycle_state":"new",
            "evidence":{"sample_hash":"safe"},
        },
    )


def test_lifecycle_persists_and_tracks_history(tmp_path, monkeypatch):
    monkeypatch.setattr(digital_risk,"DB_PATH",str(tmp_path/"drp.db"))
    item=_event("tenant-a","leak-a")

    contained=update_event_lifecycle("tenant-a",item["event_id"],"contained")
    assert contained is not None
    assert contained["lifecycle_state"]=="contained"
    assert contained["status"]=="contained"
    assert contained["lifecycle_history"][-1]["from"]=="new"
    assert contained["lifecycle_history"][-1]["to"]=="contained"

    resolved=update_event_lifecycle("tenant-a",item["event_id"],"resolved")
    assert resolved is not None
    assert resolved["status"]=="resolved"
    assert resolved["lifecycle_history"][-1]["to"]=="resolved"

    resurfaced=update_event_lifecycle("tenant-a",item["event_id"],"resurfaced")
    assert resurfaced is not None
    assert resurfaced["lifecycle_state"]=="resurfaced"
    assert resurfaced["status"]=="open"


def test_lifecycle_rejects_invalid_transition(tmp_path, monkeypatch):
    monkeypatch.setattr(digital_risk,"DB_PATH",str(tmp_path/"drp.db"))
    item=_event("tenant-a","leak-a")

    try:
        update_event_lifecycle("tenant-a",item["event_id"],"resurfaced")
    except ValueError as exc:
        assert "invalid lifecycle transition" in str(exc)
    else:
        raise AssertionError("new -> resurfaced must be rejected")


def test_lifecycle_is_tenant_scoped(tmp_path, monkeypatch):
    monkeypatch.setattr(digital_risk,"DB_PATH",str(tmp_path/"drp.db"))
    item=_event("tenant-a","leak-a")

    assert update_event_lifecycle("tenant-b",item["event_id"],"contained") is None
    original=digital_risk.list_events("tenant-a")[0]
    assert original["lifecycle_state"]=="new"


def test_drp_api_exposes_lifecycle_metrics_and_audited_update(tmp_path, monkeypatch):
    monkeypatch.setattr(digital_risk,"DB_PATH",str(tmp_path/"drp.db"))
    principal=_principal("tenant-a")
    monkeypatch.setattr(digital_risk_router,"require",lambda request,permission:principal)
    monkeypatch.setattr(digital_risk_router,"audit",lambda *args,**kwargs:None)

    item=_event("tenant-a","leak-a")
    response=client.patch(
        f"/api/v1/digital-risk/events/{item['event_id']}/lifecycle",
        json={"state":"contained"},
    )
    assert response.status_code==200
    assert response.json()["lifecycle_state"]=="contained"

    overview=client.get("/api/v1/digital-risk")
    assert overview.status_code==200
    summary=overview.json()["summary"]
    assert summary["contained"]==1
    assert summary["by_lifecycle"]["contained"]==1


def test_lifecycle_summary_counts_recurring_and_resurfaced():
    summary=lifecycle_summary([
        {"lifecycle_state":"recurring","recurring":True},
        {"lifecycle_state":"resurfaced","recurring":True},
        {"lifecycle_state":"resolved","recurring":False},
    ])

    assert summary["recurring"]==2
    assert summary["resurfaced"]==1
    assert summary["resolved"]==1
