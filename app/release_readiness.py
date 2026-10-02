"""Pilot/release readiness derived only from verifiable runtime state."""

from __future__ import annotations

import os
from pathlib import Path

from .engine_health import engine_health
from .store import _store_path
from .job_queue import _db_path


def _persistent_path(value: str | None) -> bool:
    if not value:
        return False
    try:
        path = Path(value)
    except TypeError:
        return False
    return not str(path).startswith("/tmp/")


def release_readiness() -> dict:
    env = os.getenv("BSA_ENV", "development").lower()
    production = env in {"production", "prod"}
    jwt_secret = os.getenv("BSA_JWT_SECRET", "")
    auth_db = os.getenv("BSA_AUTH_DB", str(Path("/tmp") / "bsa_auth.db"))
    origins = [x.strip() for x in os.getenv("BSA_ALLOWED_ORIGINS", "").split(",") if x.strip()]
    hosts = [x.strip() for x in os.getenv("BSA_ALLOWED_HOSTS", "").split(",") if x.strip()]

    health = engine_health()
    rapid = health.get("profiles", {}).get("rapid", {})
    balanced = health.get("profiles", {}).get("balanced", {})

    checks = [
        {
            "name": "production_mode",
            "status": "pass" if production else "warn",
            "required": False,
        },
        {
            "name": "persistent_asset_store",
            "status": "pass" if _persistent_path(_store_path()) else "fail",
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
            "status": "pass" if origins else "warn",
            "required": False,
        },
        {
            "name": "host_policy",
            "status": "pass" if hosts else "warn",
            "required": False,
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
