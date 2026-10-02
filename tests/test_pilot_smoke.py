from types import SimpleNamespace

from app import job_queue, worker
import app.main as main
from app.auth import Principal


def test_pilot_smoke_queue_worker_materialization_and_ctem(tmp_path, monkeypatch):
    monkeypatch.setenv("BSA_JOBS_DB", str(tmp_path / "jobs.db"))

    principal = Principal(
        user_id="pilot-user",
        tenant_id="tenant-pilot",
        email="pilot@example.org",
        role="admin",
        name="Pilot Admin",
    )

    job = job_queue.enqueue_assessment(
        principal,
        "api.example.org",
        "rapid",
        "PILOT-AUTH-001",
    )
    assert job["status"] == "queued"
    assert job_queue.get_job(job["job_id"], "another-tenant") is None

    assessment_result = {
        "profile": "rapid",
        "partial_coverage": False,
        "finding_count": 1,
        "findings": [
            {
                "asset": "https://api.example.org",
                "category": "web_assessment",
                "title": "Evidence-backed external exposure",
                "severity": "high",
                "confidence": 92,
                "evidence": {
                    "url": "https://api.example.org",
                    "relationship": "web-assessment",
                    "validation_state": "confirmed_evidence",
                    "reference": ["pilot-evidence-1"],
                },
            }
        ],
    }

    monkeypatch.setattr(worker, "current_principal_for_user", lambda user_id, tenant_id: principal)
    monkeypatch.setattr(worker, "can", lambda principal, permission: True)
    monkeypatch.setattr(worker, "active_scan_in_scope", lambda principal, target: True)
    monkeypatch.setattr(worker, "authorization_grant_valid", lambda principal, ref, target: True)
    monkeypatch.setattr(worker, "run_public_assessment", lambda *args, **kwargs: assessment_result)

    assert worker.run_once() is True

    completed = job_queue.get_job(job["job_id"], "tenant-pilot")
    assert completed is not None
    assert completed["status"] == "succeeded"
    assert completed["result"]["finding_count"] == 1
    assert completed["materialized"] is False

    monkeypatch.setattr(main, "STORE_ASSETS", [])
    monkeypatch.setattr(main, "STORE_FINDINGS", [])
    monkeypatch.setattr(main, "asset_in_scope", lambda principal, value: True)
    monkeypatch.setattr(main, "persist_state", lambda assets, findings: None)

    ctem = []
    monkeypatch.setattr(main, "upsert_ctem_item", lambda item, tenant_id: ctem.append((tenant_id, item)))
    monkeypatch.setattr(
        main,
        "assess_ctem_priority",
        lambda finding, asset: {
            "priority": 80,
            "action": "expedite",
            "drivers": ["pilot smoke deterministic risk"],
        },
    )

    materialized = main._materialize_assessment_result(principal, completed["result"])

    assert materialized["assets_created"] == 1
    assert materialized["findings_created"] == 1
    assert materialized["skipped_out_of_scope"] == 0
    assert len(main.STORE_ASSETS) == 1
    assert len(main.STORE_FINDINGS) == 1
    assert main.STORE_ASSETS[0].tenant_id == "tenant-pilot"
    assert main.STORE_FINDINGS[0].tenant_id == "tenant-pilot"
    assert ctem
    assert all(tenant_id == "tenant-pilot" for tenant_id, _ in ctem)

    second = main._materialize_assessment_result(principal, completed["result"])
    assert second["assets_created"] == 0
    assert second["findings_created"] == 0
    assert len(main.STORE_ASSETS) == 1
    assert len(main.STORE_FINDINGS) == 1

    job_queue.mark_materialized(job["job_id"], "tenant-pilot")
    final = job_queue.get_job(job["job_id"], "tenant-pilot")
    assert final["materialized"] is True
