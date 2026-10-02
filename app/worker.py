import time

from .auth import Principal
from .assessment_orchestrator import run_public_assessment
from .job_queue import claim_next_job, complete_job, fail_job
from .scope import asset_in_scope


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
    try:
        result=run_public_assessment(
            job["target"],
            profile=job["profile"],
            authorize=lambda target: asset_in_scope(principal,target),
        )
        complete_job(job["job_id"],result)
    except Exception as exc:
        fail_job(job["job_id"],str(exc))
    return True


def main():
    while True:
        worked=run_once()
        if not worked:
            time.sleep(1)


if __name__=="__main__":
    main()
