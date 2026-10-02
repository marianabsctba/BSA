import os
import time
import threading

from .auth import current_principal_for_user, can, audit
from .assessment_orchestrator import run_public_assessment
from .job_queue import claim_next_job, complete_job, retry_or_fail_job, heartbeat_job
from .scope import active_scan_in_scope
from .scan_authorization import authorization_grant_valid
from .ctem_retest import reconcile_ctem_retest_job


def _heartbeat(job_id:str,run_token:str,stop:threading.Event):
    while not stop.wait(30):
        if not heartbeat_job(job_id,run_token=run_token):
            return


def run_once()->bool:
    job=claim_next_job()
    if not job:
        return False
    try:
        principal=current_principal_for_user(job["user_id"],job["tenant_id"])
    except ValueError as exc:
        from .job_queue import fail_job
        fail_job(job["job_id"],f"background principal invalid: {exc}")
        return True
    if not can(principal,"discovery:run"):
        from .job_queue import fail_job
        fail_job(job["job_id"],"background principal no longer has discovery:run")
        return True
    if not active_scan_in_scope(principal,job["target"]):
        from .job_queue import fail_job
        fail_job(job["job_id"],"active scan scope no longer valid")
        return True
    if os.getenv("BSA_ENV","development").lower() in {"production","prod"}:
        if not authorization_grant_valid(principal,job["authorization_ref"],job["target"]):
            from .job_queue import fail_job
            fail_job(job["job_id"],"active scan authorization grant expired or revoked")
            return True
    run_token=job.get("run_token")
    stop=threading.Event()
    heartbeat=threading.Thread(target=_heartbeat,args=(job["job_id"],run_token,stop),daemon=True)
    heartbeat.start()
    try:
        result=run_public_assessment(
            job["target"],
            profile=job["profile"],
            authorize=lambda target: (
                active_scan_in_scope(principal,target)
                and (
                    os.getenv("BSA_ENV","development").lower() not in {"production","prod"}
                    or authorization_grant_valid(principal,job["authorization_ref"],target)
                )
            ),
        )
        completed=complete_job(job["job_id"],result,run_token=run_token)
        if completed:
            try:
                reconcile_ctem_retest_job(principal,job,result,audit)
            except Exception as exc:
                audit(
                    principal,
                    "ctem_retest_reconcile_error",
                    "ctem",
                    job["job_id"],
                    {"error":exc.__class__.__name__},
                )
    except Exception as exc:
        retry_or_fail_job(job["job_id"],str(exc),run_token=run_token)
    finally:
        stop.set()
        heartbeat.join(timeout=1)
    return True


def main():
    while True:
        worked=run_once()
        if not worked:
            time.sleep(1)


if __name__=="__main__":
    main()
