"""Runtime health for optional integrated assessment engines."""

from __future__ import annotations

from .assessment_registry import registry
from .assessment_orchestrator import PROFILES, PROFILE_CAPABILITIES


def engine_health(target: str | None = None) -> dict:
    names = sorted(registry.providers.keys())
    rows = []
    for name in names:
        available = False
        try:
            available = registry.available(name, target)
        except Exception:
            available = False
        rows.append({"name": name, "available": bool(available)})

    by_name = {row["name"]: row["available"] for row in rows}
    profiles = {}
    for profile, providers in PROFILES.items():
        available_count = sum(1 for name in providers if by_name.get(name, False))
        profiles[profile] = {
            "available_engines": available_count,
            "requested_engines": len(providers),
            "coverage_percent": round(100 * available_count / max(1, len(providers))),
            "capabilities": list(PROFILE_CAPABILITIES[profile]),
            "ready": available_count > 0,
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
