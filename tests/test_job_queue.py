from types import SimpleNamespace

from app import job_queue


def test_assessment_job_queue_is_persistent_and_tenant_scoped(tmp_path, monkeypatch):
    monkeypatch.setenv("BSA_JOBS_DB", str(tmp_path / "jobs.db"))
    principal=SimpleNamespace(
        tenant_id="tenant-a",
        user_id="user-a",
        email="a@example.org",
        role="admin",
        name="Admin A",
    )
    job=job_queue.enqueue_assessment(
        principal,
        "example.org",
        "surface",
        "AUTH-123",
    )
    assert job["status"]=="queued"
    assert job_queue.get_job(job["job_id"],"tenant-b") is None

    claimed=job_queue.claim_next_job()
    assert claimed["job_id"]==job["job_id"]
    assert claimed["tenant_id"]=="tenant-a"

    job_queue.complete_job(job["job_id"],{"finding_count":1,"findings":[]})
    completed=job_queue.get_job(job["job_id"],"tenant-a")
    assert completed["status"]=="succeeded"
    assert completed["result"]["finding_count"]==1
    assert completed["materialized"] is False

    job_queue.mark_materialized(job["job_id"],"tenant-a")
    completed=job_queue.get_job(job["job_id"],"tenant-a")
    assert completed["materialized"] is True


def test_stale_running_job_is_requeued(tmp_path, monkeypatch):
    monkeypatch.setenv("BSA_JOBS_DB", str(tmp_path / "jobs.db"))
    principal=SimpleNamespace(
        tenant_id="tenant-a",user_id="user-a",email="a@example.org",role="admin",name="Admin A",
    )
    job=job_queue.enqueue_assessment(principal,"example.org","surface","AUTH-123")
    claimed=job_queue.claim_next_job(lease_seconds=1)
    assert claimed["attempts"]==1
    conn=job_queue._db()
    conn.execute("UPDATE assessment_jobs SET lease_expires_at=? WHERE job_id=?",(1,job["job_id"]))
    conn.commit(); conn.close()
    recovered=job_queue.recover_stale_jobs(now=2)
    assert recovered["requeued"]==1
    assert job_queue.get_job(job["job_id"],"tenant-a")["status"]=="queued"


def test_retry_budget_exhaustion_marks_failed(tmp_path, monkeypatch):
    monkeypatch.setenv("BSA_JOBS_DB", str(tmp_path / "jobs.db"))
    principal=SimpleNamespace(
        tenant_id="tenant-a",user_id="user-a",email="a@example.org",role="admin",name="Admin A",
    )
    job=job_queue.enqueue_assessment(principal,"example.org","surface","AUTH-123")
    for _ in range(3):
        claimed=job_queue.claim_next_job()
        assert claimed is not None
        state=job_queue.retry_or_fail_job(job["job_id"],"boom")
    assert state=="failed"
    final=job_queue.get_job(job["job_id"],"tenant-a")
    assert final["status"]=="failed"
    assert final["attempts"]==3


def test_cancelled_job_stays_cancelled(tmp_path, monkeypatch):
    monkeypatch.setenv("BSA_JOBS_DB", str(tmp_path / "jobs.db"))
    principal=SimpleNamespace(
        tenant_id="tenant-a",user_id="user-a",email="a@example.org",role="admin",name="Admin A",
    )
    job=job_queue.enqueue_assessment(principal,"example.org","surface","AUTH-123")
    claimed=job_queue.claim_next_job()
    assert claimed["status"]=="running"

    cancelled=job_queue.cancel_job(job["job_id"],"tenant-a")
    assert cancelled["status"]=="cancelled"
    assert job_queue.complete_job(job["job_id"],{"finding_count":0,"findings":[]}) is False
    assert job_queue.retry_or_fail_job(job["job_id"],"late worker error")=="cancelled"
    final=job_queue.get_job(job["job_id"],"tenant-a")
    assert final["status"]=="cancelled"


def test_materialization_claim_is_atomic(tmp_path, monkeypatch):
    monkeypatch.setenv("BSA_JOBS_DB", str(tmp_path / "jobs.db"))
    principal=SimpleNamespace(
        tenant_id="tenant-a",user_id="user-a",email="a@example.org",role="admin",name="Admin A",
    )
    job=job_queue.enqueue_assessment(principal,"example.org","surface","AUTH-123")
    job_queue.claim_next_job()
    assert job_queue.complete_job(job["job_id"],{"finding_count":0,"findings":[]}) is True

    assert job_queue.claim_materialization(job["job_id"],"tenant-a") is True
    assert job_queue.claim_materialization(job["job_id"],"tenant-a") is False
    in_progress=job_queue.get_job(job["job_id"],"tenant-a")
    assert in_progress["materializing"] is True
    assert in_progress["materialized"] is False

    job_queue.finish_materialization(job["job_id"],"tenant-a",True)
    final=job_queue.get_job(job["job_id"],"tenant-a")
    assert final["materialized"] is True
    assert final["materializing"] is False
