"""Unified exposure assessment orchestration for Be Safe ASM.

Profiles describe product intent, not underlying tools. The orchestrator runs
only engines available on the worker, normalizes their evidence and returns a
product-safe payload.
"""

from dataclasses import asdict
from typing import Callable

from .assessment_engine import AssessmentEngine
from .assessment_registry import registry


PROFILES = {
    "surface": ("subfinder", "amass", "httpx"),
    "rapid": ("httpx", "nuclei"),
    "network": ("httpx", "nmap"),
    "balanced": ("subfinder", "amass", "httpx", "safeweb", "nuclei", "nmap"),
}

PROFILE_CAPABILITIES = {
    "surface": ("discovery", "fingerprint"),
    "rapid": ("fingerprint", "vulnerability"),
    "network": ("fingerprint", "service_exposure"),
    "balanced": ("discovery", "fingerprint", "web_assessment", "vulnerability", "service_exposure"),
}


def run_assessment(
    target: str,
    *,
    profile: str = "rapid",
    authorize: Callable[[str], bool] | None = None,
) -> dict:
    if profile not in PROFILES:
        raise ValueError("unknown assessment profile")
    if authorize is not None and not authorize(target):
        raise PermissionError("target outside authorized scope")

    engine = AssessmentEngine()
    internal = {
        "profile": profile,
        "attempted": [],
        "available": [],
        "errors": [],
    }

    for provider_name in PROFILES[profile]:
        internal["attempted"].append(provider_name)
        try:
            if not registry.available(provider_name):
                continue
            internal["available"].append(provider_name)
            results = registry.execute(provider_name, target=target)
            for result in results:
                payload = asdict(result)
                evidence = payload.get("evidence") or {}
                subject = (
                    evidence.get("asset")
                    or evidence.get("url")
                    or evidence.get("matched_at")
                    or target
                )
                engine.add_provider_result(provider_name, str(subject), payload)
        except Exception as exc:
            internal["errors"].append(
                {
                    "provider": provider_name,
                    "error": exc.__class__.__name__,
                }
            )

    public = engine.export_public()
    public.update(
        {
            "profile": profile,
            "capabilities": list(PROFILE_CAPABILITIES[profile]),
            "partial_coverage": len(internal["available"]) < len(PROFILES[profile]),
            "coverage": {
                "requested_capabilities": len(PROFILE_CAPABILITIES[profile]),
                "evidence_count": public["finding_count"],
            },
        }
    )

    return {"public": public, "internal": internal}


def run_public_assessment(
    target: str,
    *,
    profile: str = "rapid",
    authorize: Callable[[str], bool] | None = None,
) -> dict:
    return run_assessment(target, profile=profile, authorize=authorize)["public"]
