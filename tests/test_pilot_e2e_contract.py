from types import SimpleNamespace

from fastapi.testclient import TestClient

import app.main as main
from app import history


client=TestClient(main.app)


def _principal():
    return SimpleNamespace(
        tenant_id="tenant-demo",
        user_id="pilot-admin",
        email="pilot@example.org",
        role="admin",
        name="Pilot Admin",
    )


def test_pilot_customer_journey_contract(tmp_path, monkeypatch):
    principal=_principal()
    monkeypatch.setenv("BSA_HISTORY_DB",str(tmp_path/"history.db"))
    monkeypatch.setenv("BSA_JOBS_DB",str(tmp_path/"jobs.db"))

    monkeypatch.setattr(main,"require",lambda request,permission:principal)
    monkeypatch.setattr(main,"current_principal",lambda request:principal)
    monkeypatch.setattr(main,"asset_in_scope",lambda p,target:True)
    monkeypatch.setattr(main,"active_scan_in_scope",lambda p,target:True)
    monkeypatch.setattr(main,"govern_active_scan",lambda request,p,target,authorization_ref=None:"development")
    monkeypatch.setattr(
        main,
        "collect_target",
        lambda target,checks:{
            "target":target,
            "evidence":[
                {"kind":"a_record","value":"203.0.113.10","confidence":95},
                {"kind":"http_status","value":"200","confidence":90},
            ],
            "evidence_count":2,
            "confidence":92,
        },
    )
    monkeypatch.setattr(
        main,
        "public_engine_health",
        lambda:{
            "profiles":{
                "rapid":{"state":"ready","coverage_percent":100},
                "balanced":{"state":"ready","coverage_percent":100},
            }
        },
    )

    dashboard=client.get("/api/v1/dashboard")
    assert dashboard.status_code==200
    assert "total_assets" in dashboard.json()
    assert "exposure_score" in dashboard.json()

    discovery=client.post(
        "/api/v1/discovery",
        json={"target":"pilot.example.org","checks":["dns","http"],"authorization_ref":"development"},
    )
    assert discovery.status_code==200
    assert discovery.json()["target"]=="pilot.example.org"
    assert discovery.json()["evidence_count"]==2

    findings=client.get("/api/v1/findings")
    assert findings.status_code==200
    assert isinstance(findings.json(),list)

    item=history.upsert_ctem_item(
        {
            "item_id":"pilot-item",
            "asset_id":"asset-demo",
            "finding_id":None,
            "priority":85,
            "action":"immediate",
            "title":"Pilot CTEM item",
            "drivers":["pilot contract"],
            "evidence_refs":["evidence://pilot/1"],
        },
        principal.tenant_id,
    )
    assert item["state"]=="new"

    queue=client.get("/api/v1/ctem/queue")
    assert queue.status_code==200
    assert any(x["item_id"]=="pilot-item" for x in queue.json()["items"])

    acknowledged=client.post(
        "/api/v1/ctem/pilot-item/state",
        json={"state":"acknowledged","request_id":"pilot-ack"},
    )
    assert acknowledged.status_code==200
    assert acknowledged.json()["state"]=="acknowledged"

    in_progress=client.post(
        "/api/v1/ctem/pilot-item/state",
        json={"state":"in_progress","request_id":"pilot-start"},
    )
    assert in_progress.status_code==200
    assert in_progress.json()["state"]=="in_progress"

    report=client.get("/api/v1/reports/summary")
    assert report.status_code==200
    body=report.json()
    assert "executive" in body
    assert "vulnerabilities" in body
    assert "operations" in body
    assert body["operations"]["ctem"]["active_items"]>=1

    operations=client.get("/api/v1/operations/assessment-queue")
    assert operations.status_code==200
    assert operations.json()["tenant_id"]==principal.tenant_id
    assert "health" in operations.json()
