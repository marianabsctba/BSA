from types import SimpleNamespace
import threading

from app import job_queue


def _tenant(idx: int):
    return SimpleNamespace(
        tenant_id=f"tenant-{idx:02d}",
        user_id=f"user-{idx:02d}",
        email=f"user-{idx:02d}@example.org",
        role="admin",
        name=f"Admin {idx:02d}",
    )


def test_multi_tenant_queue_load_completes_without_duplicate_claims(tmp_path, monkeypatch):
    monkeypatch.setenv("BSA_JOBS_DB", str(tmp_path / "jobs.db"))

    tenants=[_tenant(i) for i in range(12)]
    jobs=[]
    for tenant in tenants:
        for n in range(20):
            jobs.append(
                job_queue.enqueue_assessment(
                    tenant,
                    f"asset-{n}.{tenant.tenant_id}.example.org",
                    "rapid",
                    f"AUTH-{tenant.tenant_id}-{n}",
                )
            )

    completed=[]
    lock=threading.Lock()

    def worker_loop():
        while True:
            job=job_queue.claim_next_job()
            if job is None:
                return
            ok=job_queue.complete_job(
                job["job_id"],
                {"finding_count":0,"findings":[]},
                run_token=job["run_token"],
            )
            assert ok is True
            with lock:
                completed.append((job["job_id"],job["tenant_id"]))

    threads=[threading.Thread(target=worker_loop) for _ in range(16)]
    for thread in threads:
        thread.start()
    for thread in threads:
        thread.join()

    ids=[job_id for job_id,_ in completed]
    assert len(ids)==len(jobs)
    assert len(set(ids))==len(jobs)

    expected={tenant.tenant_id for tenant in tenants}
    observed={tenant_id for _,tenant_id in completed}
    assert observed==expected

    for tenant in tenants:
        metrics=job_queue.queue_metrics(tenant.tenant_id)
        assert metrics["total_jobs"]==20
        assert metrics["succeeded"]==20
        assert metrics["queued"]==0
        assert metrics["running"]==0
        assert metrics["failed"]==0
