"""Pilot/release readiness derived only from verifiable runtime state."""

from __future__ import annotations

import os
from pathlib import Path

from .engine_health import engine_health
from .store import _store_path
from .job_queue import _db_path, queue_health, worker_health
from .retention import get_retention_policy
from .scan_authorization import ensure_authorization_schema


def _persistent_path(value: str | None) -> bool:
    if not value:
        return False
    try:
        path = Path(value)
    except TypeError:
        return False
    return not str(path).startswith("/tmp/")


def _asset_store_persistent() -> bool:
    backend=os.getenv("BSA_ASSET_REPOSITORY_BACKEND","legacy").strip().lower()
    if backend in {"legacy","sqlite","memory"}:
        return _persistent_path(_store_path())
    if backend=="postgres":
        return bool(os.getenv("BSA_DATABASE_URL","").strip())
    return False


def release_readiness() -> dict:
    env = os.getenv("BSA_ENV", "development").lower()
    production = env in {"production", "prod"}
    jwt_secret = os.getenv("BSA_JWT_SECRET", "")
    auth_db = os.getenv("BSA_AUTH_DB", "/data/bsa_auth.db" if production else str(Path("/tmp") / "bsa_auth.db"))
    history_db = os.getenv("BSA_HISTORY_DB", "/data/bsa_history.db" if production else str(Path("/tmp") / "bsa_history.db"))
    demo_enabled = os.getenv("BSA_DEMO_DATA","0").strip().lower() in {"1","true","yes","on"}
    origins = [x.strip() for x in os.getenv("BSA_ALLOWED_ORIGINS", "").split(",") if x.strip()]
    hosts = [x.strip() for x in os.getenv("BSA_ALLOWED_HOSTS", "").split(",") if x.strip()]

    ensure_authorization_schema()
    health = engine_health()
    rapid = health.get("profiles", {}).get("rapid", {})
    balanced = health.get("profiles", {}).get("balanced", {})
    queue = queue_health()
    workers = worker_health()

    checks = [
        {
            "name": "production_mode",
            "status": "pass" if production else "warn",
            "required": False,
        },
        {
            "name": "persistent_asset_store",
            "status": "pass" if _asset_store_persistent() else "fail",
            "required": True,
        },
        {
            "name": "persistent_job_queue",
            "status": "pass" if _persistent_path(_db_path()) else "fail",
            "required": True,
        },
        {
            "name": "persistent_auth_store",
            "status": "pass" if _persistent_path(auth_db) else "fail",
            "required": True,
        },
        {
            "name": "persistent_history_store",
            "status": "pass" if _persistent_path(history_db) else "fail",
            "required": True,
        },
        {
            "name": "demo_data_disabled",
            "status": "pass" if not demo_enabled else "fail",
            "required": True,
        },
        {
            "name": "strong_auth_secret",
            "status": "pass" if len(jwt_secret) >= 32 else "fail",
            "required": True,
        },
        {
            "name": "rapid_assessment_coverage",
            "status": "pass" if rapid.get("ready") else "warn",
            "required": False,
            "coverage_percent": int(rapid.get("coverage_percent", 0) or 0),
        },
        {
            "name": "balanced_assessment_coverage",
            "status": "pass" if balanced.get("ready") else "warn",
            "required": False,
            "coverage_percent": int(balanced.get("coverage_percent", 0) or 0),
        },
        {
            "name": "origin_policy",
            "status": "pass" if origins else ("fail" if production else "warn"),
            "required": production,
        },
        {
            "name": "host_policy",
            "status": "pass" if hosts else ("fail" if production else "warn"),
            "required": production,
        },
        {
            "name": "tenant_retention_policy",
            "status": "pass" if int(get_retention_policy("tenant-demo").get("retention_days",0) or 0) >= 30 else "fail",
            "required": True,
        },
        {
            "name": "assessment_queue_health",
            "status": "pass" if queue.get("status")=="healthy" else "warn",
            "required": False,
            "queue_status": queue.get("status"),
            "oldest_queued_age_seconds": int(queue.get("oldest_queued_age_seconds",0) or 0),
            "expired_running_leases": int(queue.get("expired_running_leases",0) or 0),
            "stale_materializations": int(queue.get("stale_materializations",0) or 0),
            "retry_pressure_jobs": int(queue.get("retry_pressure_jobs",0) or 0),
        },
        {
            "name": "assessment_worker_health",
            "status": "pass" if workers.get("status")=="healthy" else "warn",
            "required": False,
            "worker_status": workers.get("status"),
            "workers": int(workers.get("workers",0) or 0),
            "active_workers": int(workers.get("active_workers",0) or 0),
            "stale_workers": int(workers.get("stale_workers",0) or 0),
            "last_seen_age_seconds": workers.get("last_seen_age_seconds"),
        },
        {
            "name": "scan_authorization_store",
            "status": "pass",
            "required": True,
        },
    ]

    required_failures = [x["name"] for x in checks if x["required"] and x["status"] == "fail"]
    warnings = [x["name"] for x in checks if x["status"] == "warn"]

    if required_failures:
        state = "blocked"
    elif warnings:
        state = "degraded"
    else:
        state = "ready"

    return {
        "state": state,
        "pilot_ready": state != "blocked",
        "checks": checks,
        "required_failures": required_failures,
        "warnings": warnings,
    }
