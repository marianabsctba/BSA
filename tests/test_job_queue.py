from types import SimpleNamespace
import threading

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


def test_two_workers_never_claim_same_job(tmp_path, monkeypatch):
    monkeypatch.setenv("BSA_JOBS_DB", str(tmp_path / "jobs.db"))
    principal=SimpleNamespace(
        tenant_id="tenant-a",user_id="user-a",email="a@example.org",role="admin",name="Admin A",
    )
    job=job_queue.enqueue_assessment(principal,"example.org","surface","AUTH-123")
    claimed=[]
    lock=threading.Lock()

    def claim():
        value=job_queue.claim_next_job()
        with lock:
            claimed.append(value)

    threads=[threading.Thread(target=claim) for _ in range(2)]
    for thread in threads:
        thread.start()
    for thread in threads:
        thread.join()

    winners=[x for x in claimed if x is not None]
    assert len(winners)==1
    assert winners[0]["job_id"]==job["job_id"]
    assert winners[0]["run_token"]


def test_stale_worker_cannot_complete_after_lease_reclaim(tmp_path, monkeypatch):
    monkeypatch.setenv("BSA_JOBS_DB", str(tmp_path / "jobs.db"))
    principal=SimpleNamespace(
        tenant_id="tenant-a",user_id="user-a",email="a@example.org",role="admin",name="Admin A",
    )
    job=job_queue.enqueue_assessment(principal,"example.org","surface","AUTH-123")
    first=job_queue.claim_next_job(lease_seconds=1)
    assert first is not None
    old_token=first["run_token"]

    conn=job_queue._db()
    conn.execute("UPDATE assessment_jobs SET lease_expires_at=? WHERE job_id=?",(1,job["job_id"]))
    conn.commit(); conn.close()

    recovered=job_queue.recover_stale_jobs(now=2)
    assert recovered["requeued"]==1

    second=job_queue.claim_next_job()
    assert second is not None
    assert second["run_token"] != old_token

    assert job_queue.complete_job(
        job["job_id"],{"finding_count":99,"findings":[]},run_token=old_token
    ) is False
    assert job_queue.complete_job(
        job["job_id"],{"finding_count":1,"findings":[]},run_token=second["run_token"]
    ) is True

    final=job_queue.get_job(job["job_id"],"tenant-a")
    assert final["status"]=="succeeded"
    assert final["result"]["finding_count"]==1
    assert final["attempts"]==2


def test_stale_worker_cannot_heartbeat_new_lease(tmp_path, monkeypatch):
    monkeypatch.setenv("BSA_JOBS_DB", str(tmp_path / "jobs.db"))
    principal=SimpleNamespace(
        tenant_id="tenant-a",user_id="user-a",email="a@example.org",role="admin",name="Admin A",
    )
    job=job_queue.enqueue_assessment(principal,"example.org","surface","AUTH-123")
    first=job_queue.claim_next_job(lease_seconds=1)
    old_token=first["run_token"]

    conn=job_queue._db()
    conn.execute("UPDATE assessment_jobs SET lease_expires_at=? WHERE job_id=?",(1,job["job_id"]))
    conn.commit(); conn.close()
    job_queue.recover_stale_jobs(now=2)
    second=job_queue.claim_next_job()

    assert job_queue.heartbeat_job(job["job_id"],run_token=old_token) is False
    assert job_queue.heartbeat_job(job["job_id"],run_token=second["run_token"]) is True



def test_stale_materialization_claim_is_recoverable(tmp_path, monkeypatch):
    monkeypatch.setenv("BSA_JOBS_DB", str(tmp_path / "jobs.db"))
    principal=SimpleNamespace(
        tenant_id="tenant-a",user_id="user-a",email="a@example.org",role="admin",name="Admin A",
    )
    job=job_queue.enqueue_assessment(principal,"example.org","surface","AUTH-123")
    claimed=job_queue.claim_next_job()
    assert claimed is not None
    assert job_queue.complete_job(
        job["job_id"],{"finding_count":0,"findings":[]},run_token=claimed["run_token"]
    ) is True

    assert job_queue.claim_materialization(job["job_id"],"tenant-a") is True
    conn=job_queue._db()
    conn.execute(
        "UPDATE assessment_jobs SET materialization_started_at=? WHERE job_id=?",
        (1,job["job_id"]),
    )
    conn.commit(); conn.close()

    assert job_queue.recover_stale_materializations(now=1000,stale_seconds=300)==1
    recovered=job_queue.get_job(job["job_id"],"tenant-a")
    assert recovered["materializing"] is False
    assert recovered["materialized"] is False
    assert job_queue.claim_materialization(job["job_id"],"tenant-a") is True


def test_many_workers_claim_each_job_at_most_once(tmp_path, monkeypatch):
    monkeypatch.setenv("BSA_JOBS_DB", str(tmp_path / "jobs.db"))
    principal=SimpleNamespace(
        tenant_id="tenant-a",user_id="user-a",email="a@example.org",role="admin",name="Admin A",
    )

    jobs=[
        job_queue.enqueue_assessment(
            principal,
            f"asset-{idx}.example.org",
            "surface",
            f"AUTH-{idx}",
        )
        for idx in range(40)
    ]

    claimed=[]
    lock=threading.Lock()

    def worker_claim_loop():
        while True:
            item=job_queue.claim_next_job()
            if item is None:
                return
            with lock:
                claimed.append((item["job_id"],item["run_token"]))

    threads=[threading.Thread(target=worker_claim_loop) for _ in range(8)]
    for thread in threads:
        thread.start()
    for thread in threads:
        thread.join()

    ids=[job_id for job_id,_ in claimed]
    assert len(ids)==len(jobs)
    assert len(set(ids))==len(jobs)
    assert all(token for _,token in claimed)



def test_tenant_fair_scheduler_does_not_starve_other_tenants(tmp_path, monkeypatch):
    monkeypatch.setenv("BSA_JOBS_DB", str(tmp_path / "jobs.db"))
    tenant_a=SimpleNamespace(
        tenant_id="tenant-a",user_id="user-a",email="a@example.org",role="admin",name="Admin A",
    )
    tenant_b=SimpleNamespace(
        tenant_id="tenant-b",user_id="user-b",email="b@example.org",role="admin",name="Admin B",
    )

    a1=job_queue.enqueue_assessment(tenant_a,"a1.example.org","surface","AUTH-A1")
    a2=job_queue.enqueue_assessment(tenant_a,"a2.example.org","surface","AUTH-A2")
    b1=job_queue.enqueue_assessment(tenant_b,"b1.example.org","surface","AUTH-B1")

    conn=job_queue._db()
    conn.execute("UPDATE assessment_jobs SET created_at=? WHERE job_id=?",(1,a1["job_id"]))
    conn.execute("UPDATE assessment_jobs SET created_at=? WHERE job_id=?",(2,a2["job_id"]))
    conn.execute("UPDATE assessment_jobs SET created_at=? WHERE job_id=?",(3,b1["job_id"]))
    conn.commit(); conn.close()

    first=job_queue.claim_next_job()
    assert first["job_id"]==a1["job_id"]

    second=job_queue.claim_next_job()
    assert second["job_id"]==b1["job_id"]
    assert second["tenant_id"]=="tenant-b"
