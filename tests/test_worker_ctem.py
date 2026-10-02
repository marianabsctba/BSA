from types import SimpleNamespace

from app import worker


def test_worker_reconciles_ctem_retest_after_successful_completion(monkeypatch):
    principal=SimpleNamespace(
        tenant_id="tenant-a",
        user_id="user-a",
        email="a@example.org",
        role="admin",
        name="Admin A",
    )
    job={
        "job_id":"job-a",
        "tenant_id":"tenant-a",
        "user_id":"user-a",
        "target":"app.example.org",
        "profile":"rapid",
        "authorization_ref":"AUTH-A",
        "run_token":"lease-a",
    }
    result={
        "finding_count":0,
        "findings":[],
        "partial_coverage":False,
        "coverage":{"capability_coverage_percent":100},
    }
    reconciled=[]

    monkeypatch.setattr(worker,"claim_next_job",lambda:job)
    monkeypatch.setattr(worker,"current_principal_for_user",lambda user_id,tenant_id:principal)
    monkeypatch.setattr(worker,"can",lambda p,permission:True)
    monkeypatch.setattr(worker,"active_scan_in_scope",lambda p,target:True)
    monkeypatch.setattr(worker,"run_public_assessment",lambda *args,**kwargs:result)
    monkeypatch.setattr(worker,"complete_job",lambda job_id,payload,run_token=None:True)
    monkeypatch.setattr(
        worker,
        "reconcile_ctem_retest_job",
        lambda p,j,payload,audit_callback=None: reconciled.append(
            (p.tenant_id,j["job_id"],payload["finding_count"])
        ),
    )
    monkeypatch.setattr(worker,"audit",lambda *args,**kwargs:None)

    assert worker.run_once() is True
    assert reconciled==[("tenant-a","job-a",0)]


def test_worker_does_not_reconcile_when_lease_cannot_complete(monkeypatch):
    principal=SimpleNamespace(
        tenant_id="tenant-a",
        user_id="user-a",
        email="a@example.org",
        role="admin",
        name="Admin A",
    )
    job={
        "job_id":"job-stale",
        "tenant_id":"tenant-a",
        "user_id":"user-a",
        "target":"app.example.org",
        "profile":"rapid",
        "authorization_ref":"AUTH-A",
        "run_token":"stale-lease",
    }
    reconciled=[]

    monkeypatch.setattr(worker,"claim_next_job",lambda:job)
    monkeypatch.setattr(worker,"current_principal_for_user",lambda user_id,tenant_id:principal)
    monkeypatch.setattr(worker,"can",lambda p,permission:True)
    monkeypatch.setattr(worker,"active_scan_in_scope",lambda p,target:True)
    monkeypatch.setattr(
        worker,
        "run_public_assessment",
        lambda *args,**kwargs:{
            "finding_count":0,"findings":[],"partial_coverage":False,
            "coverage":{"capability_coverage_percent":100},
        },
    )
    monkeypatch.setattr(worker,"complete_job",lambda job_id,payload,run_token=None:False)
    monkeypatch.setattr(
        worker,"reconcile_ctem_retest_job",
        lambda *args,**kwargs: reconciled.append(True),
    )

    assert worker.run_once() is True
    assert reconciled==[]
