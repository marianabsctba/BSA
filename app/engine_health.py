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
        requested_count = len(providers)
        coverage_percent = round(100 * available_count / max(1, requested_count))
        profiles[profile] = {
            "available_engines": available_count,
            "requested_engines": requested_count,
            "coverage_percent": coverage_percent,
            "capabilities": list(PROFILE_CAPABILITIES[profile]),
            "state": "ready" if available_count == requested_count else "partial" if available_count else "unavailable",
            "ready": available_count == requested_count,
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
