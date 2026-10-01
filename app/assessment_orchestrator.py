"""Unified exposure assessment orchestration for Be Safe ASM.

Profiles describe product intent, not underlying tools. The orchestrator runs
only engines available on the worker, normalizes their evidence and returns a
product-safe payload.
"""

from dataclasses import asdict
from typing import Callable

from .assessment_engine import AssessmentEngine
from .assessment_registry import registry
from .exposure_signals import cloud_signals, summarize_signals


PROFILES = {
    "surface": ("subfinder", "amass", "dnsx", "asnmap", "httpx", "tlsx", "gau"),
    "rapid": ("httpx", "tlsx", "nuclei"),
    "network": ("dnsx", "httpx", "naabu", "nmap"),
    "balanced": ("subfinder", "amass", "dnsx", "asnmap", "httpx", "tlsx", "gau", "katana", "safeweb", "nuclei", "naabu", "nmap", "trufflehog"),
}

PROFILE_CAPABILITIES = {
    "surface": ("discovery", "dns_intelligence", "network_intelligence", "fingerprint", "certificate_intelligence", "historical_surface", "cloud_intelligence"),
    "rapid": ("fingerprint", "certificate_intelligence", "vulnerability"),
    "network": ("dns_intelligence", "fingerprint", "service_exposure"),
    "balanced": (
        "discovery",
        "dns_intelligence",
        "network_intelligence",
        "fingerprint",
        "certificate_intelligence",
        "historical_surface",
        "web_surface",
        "web_assessment",
        "cloud_exposure",
        "vulnerability",
        "service_exposure",
        "cloud_intelligence",
        "credential_exposure",
    ),
}


def _cloud_intelligence(findings: list[dict]) -> list[dict]:
    values = []
    for row in findings:
        values.append(str(row.get("asset") or ""))
        evidence = row.get("evidence") or {}
        for key in ("url", "matched_at", "asset"):
            value = evidence.get(key)
            if value:
                values.append(str(value))
        for key in ("cname", "san"):
            seq = evidence.get(key) or []
            if isinstance(seq, list):
                values.extend(str(x) for x in seq if x)
            elif seq:
                values.append(str(seq))
    summary = summarize_signals(cloud_signals(values))
    return [
        {
            "asset": signal.get("value") or "cloud",
            "category": "cloud_intelligence",
            "title": "Cloud infrastructure signal",
            "severity": "info",
            "confidence": int(signal.get("confidence", 80)),
            "evidence": {
                "cloud_provider": signal.get("value"),
                "reason": signal.get("reason"),
                "validation_required": signal.get("validation_required", False),
            },
        }
        for signal in summary.get("signals", [])
    ]



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
            if not registry.available(provider_name, target):
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
    cloud = _cloud_intelligence(public.get("findings", []))
    if cloud:
        public["findings"].extend(cloud)
        public["finding_count"] = len(public["findings"])
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
