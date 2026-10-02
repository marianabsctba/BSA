"""Runtime health for optional integrated assessment engines."""

from __future__ import annotations

from .assessment_registry import registry
from .assessment_orchestrator import (
    PROFILES,
    PROFILE_CAPABILITIES,
    PROFILE_COVERAGE_POLICY,
    PROFILE_OPTIONAL_CAPABILITIES,
)


def engine_health(target: str | None = None) -> dict:
    names = sorted(registry.providers.keys())
    rows = []
    for name in names:
        available = False
        readiness = None
        try:
            provider = registry.provider(name)
            readiness_fn = getattr(provider, "readiness", None)
            if callable(readiness_fn):
                readiness = dict(readiness_fn())
                available = bool(readiness.get("ready"))
            else:
                available = registry.available(name, target)
        except Exception:
            available = False
            readiness = {"ready": False}
        rows.append({"name": name, "available": bool(available), "readiness": readiness})

    by_name = {row["name"]: row["available"] for row in rows}
    profiles = {}
    for profile, providers in PROFILES.items():
        capability_health = registry.capability_health(target, PROFILE_CAPABILITIES[profile])
        optional = set(PROFILE_OPTIONAL_CAPABILITIES.get(profile, ()))
        core_rows = [row for row in capability_health if row.get("name") not in optional]
        optional_rows = [row for row in capability_health if row.get("name") in optional]

        available_count = sum(1 for name in providers if by_name.get(name, False))
        requested_count = len(providers)
        core_operational = sum(1 for row in core_rows if row.get("operational"))
        core_requested = len(core_rows)
        coverage_percent = round(100 * core_operational / max(1, core_requested))
        optional_operational = sum(1 for row in optional_rows if row.get("operational"))
        missing_core = [
            row["name"] for row in core_rows if not row.get("operational")
        ]
        degraded_core = [
            row["name"]
            for row in core_rows
            if row.get("operational") and row.get("status") == "degraded"
        ]
        missing_optional = [
            row["name"] for row in optional_rows if not row.get("operational")
        ]
        degraded_optional = [
            row["name"]
            for row in optional_rows
            if row.get("operational") and row.get("status") == "degraded"
        ]
        backend_slots = sum(int(row.get("backend_count", 0) or 0) for row in core_rows)
        backend_available = sum(
            int(row.get("available_backends", 0) or 0) for row in core_rows
        )
        backend_coverage_percent = round(
            100 * backend_available / max(1, backend_slots)
        )

        policy = PROFILE_COVERAGE_POLICY.get(profile, {})
        min_core_coverage = int(policy.get("min_core_coverage_percent", 100))
        min_backend_coverage = int(policy.get("min_backend_coverage_percent", 0))
        allow_degraded_core = bool(policy.get("allow_degraded_core", True))

        readiness_blockers = []
        if not core_requested or coverage_percent < min_core_coverage:
            readiness_blockers.append("core_coverage")
        if backend_coverage_percent < min_backend_coverage:
            readiness_blockers.append("backend_coverage")
        if degraded_core and not allow_degraded_core:
            readiness_blockers.append("degraded_core")

        policy_ready = not readiness_blockers
        state = (
            "ready"
            if policy_ready
            else "partial"
            if core_operational
            else "unavailable"
        )

        profiles[profile] = {
            "available_engines": available_count,
            "requested_engines": requested_count,
            "coverage_percent": coverage_percent,
            "backend_coverage_percent": backend_coverage_percent,
            "capabilities": list(PROFILE_CAPABILITIES[profile]),
            "core_capabilities": core_requested,
            "core_operational_capabilities": core_operational,
            "optional_capabilities": len(optional_rows),
            "optional_operational_capabilities": optional_operational,
            "missing_capabilities": missing_core,
            "degraded_capabilities": degraded_core,
            "optional_missing_capabilities": missing_optional,
            "optional_degraded_capabilities": degraded_optional,
            "coverage_policy": {
                "min_core_coverage_percent": min_core_coverage,
                "min_backend_coverage_percent": min_backend_coverage,
                "allow_degraded_core": allow_degraded_core,
            },
            "readiness_blockers": readiness_blockers,
            "state": state,
            "ready": policy_ready,
        }

    return {
        "engine_count": len(rows),
        "available_count": sum(1 for row in rows if row["available"]),
        "engines": rows,
        "profiles": profiles,
    }


def public_engine_health(target: str | None = None) -> dict:
    data = engine_health(target)
    return {
        "available_engine_count": data["available_count"],
        "engine_count": data["engine_count"],
        "profiles": data["profiles"],
    }
