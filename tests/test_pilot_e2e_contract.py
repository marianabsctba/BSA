from types import SimpleNamespace

from fastapi.testclient import TestClient

import app.main as main
from app.api import dependencies as api_dependencies
from app.api.routers import vulnerabilities as vulnerabilities_router
from app.api.routers import ctem as ctem_router
from app.api.routers import operations as operations_router
from app.api.routers import reporting as reporting_router
from app.api.routers import discovery_execution as discovery_execution_router
from app import history, worker, job_queue


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

    monkeypatch.setattr(reporting_router,"require",lambda request,permission:principal)
    monkeypatch.setattr(discovery_execution_router,"require",lambda request,permission:principal)
    monkeypatch.setattr(api_dependencies,"require",lambda request,permission:principal)
    monkeypatch.setattr(vulnerabilities_router,"require",lambda request,permission:principal)
    monkeypatch.setattr(ctem_router,"require",lambda request,permission:principal)
    monkeypatch.setattr(operations_router,"require",lambda request,permission:principal)
    monkeypatch.setattr(reporting_router,"asset_in_scope",lambda p,target:True)
    monkeypatch.setattr(discovery_execution_router,"asset_in_scope",lambda p,target:True)
    monkeypatch.setattr(api_dependencies,"asset_in_scope",lambda p,target:True)
    monkeypatch.setattr(discovery_execution_router,"queue_active_operation",lambda request,p,target,operation,payload=None,authorization_ref=None: __import__("fastapi").responses.JSONResponse(status_code=202,content={"job_id":job_queue.enqueue_operation(p,target,operation,authorization_ref or "development",payload or {})["job_id"],"status":"queued","target":target,"operation":operation}))
    monkeypatch.setattr(
        reporting_router,
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
    assert discovery.status_code==202
    queued=discovery.json()
    assert queued["target"]=="pilot.example.org"
    assert queued["status"]=="queued"
    assert queued["operation"]=="discovery.basic"
    assert queued["job_id"]

    job=job_queue.get_job(queued["job_id"],principal.tenant_id)
    assert job and job["status"]=="queued"

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


def test_pilot_ctem_retest_closes_verified_with_full_evidence(tmp_path, monkeypatch):
    principal=_principal()
    monkeypatch.setenv("BSA_HISTORY_DB",str(tmp_path/"history.db"))
    monkeypatch.setenv("BSA_JOBS_DB",str(tmp_path/"jobs.db"))

    tenant_assets=[
        asset for asset in discovery_execution_router.STORE_ASSETS
        if getattr(asset,"tenant_id","tenant-demo")==principal.tenant_id
    ]
    assert tenant_assets
    asset=tenant_assets[0]

    monkeypatch.setattr(reporting_router,"require",lambda request,permission:principal)
    monkeypatch.setattr(ctem_router,"require",lambda request,permission:principal)
    monkeypatch.setattr(ctem_router,"tenant_scope",lambda p,assets,findings:(assets,findings))
    monkeypatch.setattr(ctem_router,"govern_active_scan",lambda request,p,target,authorization_ref=None:"AUTH-PILOT")
    monkeypatch.setattr(discovery_execution_router,"asset_in_scope",lambda p,target:True)

    item=history.upsert_ctem_item(
        {
            "item_id":"pilot-retest-item",
            "asset_id":asset.id,
            "finding_id":None,
            "priority":90,
            "action":"immediate",
            "title":"Surface change requiring CTEM attention",
            "drivers":["pilot retest contract"],
            "evidence_refs":["evidence://pilot/retest-before"],
        },
        principal.tenant_id,
    )
    assert item["state"]=="new"

    for state,request_id in [
        ("acknowledged","pilot-r1"),
        ("in_progress","pilot-r2"),
        ("resolved","pilot-r3"),
    ]:
        response=client.post(
            "/api/v1/ctem/pilot-retest-item/state",
            json={"state":state,"request_id":request_id},
        )
        assert response.status_code==200
        assert response.json()["state"]==state

    queued=client.post(
        "/api/v1/ctem/pilot-retest-item/retest",
        json={"profile":"rapid","authorization_ref":"AUTH-PILOT"},
    )
    assert queued.status_code==202
    job_id=queued.json()["job_id"]

    result={
        "finding_count":0,
        "findings":[],
        "partial_coverage":False,
        "coverage":{"capability_coverage_percent":100},
    }
    job=job_queue.get_job(job_id,principal.tenant_id)
    assert job and job["status"]=="queued"

    monkeypatch.setattr(worker,"claim_next_job",lambda:job_queue.claim_next_job())
    monkeypatch.setattr(worker,"current_principal_for_user",lambda user_id,tenant_id:principal)
    monkeypatch.setattr(worker,"can",lambda p,permission:True)
    monkeypatch.setattr(worker,"active_scan_in_scope",lambda p,target:True)
    monkeypatch.setattr(worker,"run_public_assessment",lambda *args,**kwargs:result)
    monkeypatch.setattr(worker,"audit",lambda *args,**kwargs:None)

    assert worker.run_once() is True

    final=next(
        x for x in history.list_ctem_items(principal.tenant_id)
        if x["item_id"]=="pilot-retest-item"
    )
    assert final["state"]=="verified"

    verifications=history.ctem_verification_history(
        "pilot-retest-item",principal.tenant_id,
    )
    assert len(verifications)==1
    assert verifications[0]["result"]=="passed"
    assert verifications[0]["evidence_refs"]==[
        f"assessment-job:{job_id}:coverage:100"
    ]

    retest=history.ctem_retest_for_job(job_id,principal.tenant_id)
    assert retest["status"]=="reconciled"
    assert retest["outcome"]=="passed"

    timeline=history.ctem_audit_timeline(
        final,
        verifications,
        history.ctem_transition_history("pilot-retest-item",principal.tenant_id),
    )
    assert any(x.get("action")=="retest_verified" for x in timeline)

    report=client.get("/api/v1/reports/summary")
    assert report.status_code==200
    assert report.json()["operations"]["ctem"]["retest"]==0
