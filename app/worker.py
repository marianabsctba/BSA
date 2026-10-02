import time
import threading

from .auth import Principal
from .assessment_orchestrator import run_public_assessment
from .job_queue import claim_next_job, complete_job, retry_or_fail_job, heartbeat_job
from .scope import active_scan_in_scope


def _heartbeat(job_id:str,stop:threading.Event):
    while not stop.wait(30):
        if not heartbeat_job(job_id):
            return


def run_once()->bool:
    job=claim_next_job()
    if not job:
        return False
    principal=Principal(
        user_id=job["user_id"],
        tenant_id=job["tenant_id"],
        email=job["email"],
        role=job["role"],
        name=job["name"],
    )
    if not active_scan_in_scope(principal,job["target"]):
        retry_or_fail_job(job["job_id"],"active scan authorization no longer valid")
        return True
    stop=threading.Event()
    heartbeat=threading.Thread(target=_heartbeat,args=(job["job_id"],stop),daemon=True)
    heartbeat.start()
    try:
        result=run_public_assessment(
            job["target"],
            profile=job["profile"],
            authorize=lambda target: active_scan_in_scope(principal,target),
        )
        complete_job(job["job_id"],result)
    except Exception as exc:
        retry_or_fail_job(job["job_id"],str(exc))
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
