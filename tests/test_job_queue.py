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
