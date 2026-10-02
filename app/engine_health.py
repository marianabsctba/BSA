"""Runtime health for optional integrated assessment engines."""

from __future__ import annotations

from .assessment_registry import registry
from .assessment_orchestrator import PROFILES, PROFILE_CAPABILITIES, PROFILE_OPTIONAL_CAPABILITIES


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

        profiles[profile] = {
            "available_engines": available_count,
            "requested_engines": requested_count,
            "coverage_percent": coverage_percent,
            "capabilities": list(PROFILE_CAPABILITIES[profile]),
            "core_capabilities": core_requested,
            "core_operational_capabilities": core_operational,
            "optional_capabilities": len(optional_rows),
            "optional_operational_capabilities": optional_operational,
            "state": "ready" if core_requested and core_operational == core_requested else "partial" if core_operational else "unavailable",
            "ready": bool(core_requested) and core_operational == core_requested,
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
