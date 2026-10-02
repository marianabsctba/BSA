from fastapi import APIRouter, HTTPException, Request
from fastapi.responses import JSONResponse, Response

from ...job_queue import get_job, queue_health, queue_metrics, worker_health
from ...metrics import operational_alerts, prometheus_metrics
from ...release_readiness import release_readiness
from ...runtime_health import runtime_health
from ...version import __version__
from ..dependencies import require


router=APIRouter()


@router.get("/api/v1/operations/jobs/{job_id}")
def active_operation_job(job_id: str, request: Request):
    principal=require(request,"discovery:run")
    job=get_job(job_id,principal.tenant_id)
    if not job:
        raise HTTPException(status_code=404,detail="job not found")
    return {
        "job_id":job["job_id"],
        "job_type":job.get("job_type"),
        "operation":job.get("operation"),
        "status":job["status"],
        "target":job["target"],
        "created_at":job["created_at"],
        "started_at":job.get("started_at"),
        "completed_at":job.get("completed_at"),
        "error":job.get("error"),
        "result":job.get("result"),
    }


@router.get("/health")
def health():
    return {"status":"ok"}


@router.get("/ready")
def ready():
    data=runtime_health()
    status_code=200 if data.get("status")=="healthy" else 503
    return JSONResponse(
        status_code=status_code,
        content={
            **data,
            "product":"BSA",
            "version":__version__,
            "powered_by":"Mariana BS",
        },
    )


@router.get("/metrics")
def metrics(request: Request):
    principal=require(request,"assets:read")
    tenant_id=None if principal.role=="superadmin" else principal.tenant_id
    return Response(
        content=prometheus_metrics(tenant_id),
        media_type="text/plain; version=0.0.4; charset=utf-8",
    )


@router.get("/api/v1/operations/alerts")
def operations_alerts(request: Request):
    principal=require(request,"assets:read")
    if principal.role not in {"superadmin","admin","manager"}:
        raise HTTPException(status_code=403,detail="manager role required")
    tenant_id=None if principal.role=="superadmin" else principal.tenant_id
    return operational_alerts(tenant_id)


@router.get("/api/v1/operations/assessment-queue")
def operations_assessment_queue(request: Request):
    principal=require(request,"assets:read")
    if principal.role not in {"superadmin","admin","manager"}:
        raise HTTPException(status_code=403,detail="manager role required")
    return {
        "tenant_id":principal.tenant_id,
        "queue":queue_metrics(principal.tenant_id),
        "health":queue_health(principal.tenant_id),
        "workers":worker_health(),
    }


@router.get("/api/v1/operations/release-readiness")
def operations_release_readiness(request: Request):
    principal=require(request,"assets:read")
    if principal.role not in {"superadmin","admin","manager"}:
        raise HTTPException(status_code=403,detail="manager role required")
    return release_readiness()
