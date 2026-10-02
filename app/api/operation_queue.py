from fastapi import Request
from fastapi.responses import JSONResponse

from ..auth import audit
from ..job_queue import enqueue_operation
from .active_scan import govern_active_scan


def queue_active_operation(
    http_request: Request,
    principal,
    target: str,
    operation: str,
    payload: dict | None=None,
    authorization_ref: str | None=None,
):
    ref=govern_active_scan(
        http_request,
        principal,
        target,
        authorization_ref,
    )
    job=enqueue_operation(
        principal,
        target,
        operation,
        ref or "development",
        payload or {},
    )
    audit(
        principal,
        "queue",
        "active_operation",
        target,
        {
            "job_id":job["job_id"],
            "operation":operation,
            "authorization_ref":ref or "development",
        },
    )
    return JSONResponse(
        status_code=202,
        content={
            "job_id":job["job_id"],
            "status":job["status"],
            "target":job["target"],
            "operation":operation,
        },
    )
