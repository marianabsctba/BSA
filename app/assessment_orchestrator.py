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
    "surface": ("subfinder", "amass", "assetfinder", "alterx", "puredns", "dnsx", "asnmap", "httpx", "tlsx", "gau"),
    "rapid": ("httpx", "tlsx", "nuclei"),
    "network": ("dnsx", "httpx", "naabu", "nmap"),
    "balanced": ("subfinder", "amass", "assetfinder", "alterx", "puredns", "dnsx", "asnmap", "httpx", "whatweb", "tlsx", "testssl", "gau", "katana", "safeweb", "zap", "cloud", "nuclei", "openvas", "naabu", "nmap", "cti", "threatfox", "hibp", "hudsonrock", "leak", "trufflehog"),
}

DISCOVERY_PROVIDERS = {"subfinder", "amass", "assetfinder", "alterx"}
FOLLOWUP_PROVIDERS = ("puredns", "dnsx", "httpx", "tlsx", "whatweb")
VULN_FOLLOWUP_PROVIDERS = ("nuclei", "zap")
MAX_FOLLOWUP_TARGETS = 32
MAX_VULN_FOLLOWUP_TARGETS = 8

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
        "tls_assessment",
        "technology_intelligence",
        "historical_surface",
        "web_surface",
        "web_assessment",
        "cloud_exposure",
        "vulnerability",
        "service_exposure",
        "cloud_intelligence",
        "credential_exposure",
        "intelligence",
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



def _finding_key(row: dict) -> tuple:
    evidence = row.get("evidence") or {}
    classification = evidence.get("classification") if isinstance(evidence, dict) else {}
    classification = classification if isinstance(classification, dict) else {}
    vulnerability_id = (
        evidence.get("vulnerability_id")
        or evidence.get("cve")
        or classification.get("cve-id")
        or classification.get("cve_id")
    )
    relationship = evidence.get("relationship") if isinstance(evidence, dict) else None
    return (
        str(row.get("asset") or "").strip().lower().rstrip("."),
        str(row.get("category") or ""),
        str(row.get("title") or ""),
        str(vulnerability_id or ""),
        str(relationship or ""),
    )


def _deduplicate_findings(findings: list[dict]) -> tuple[list[dict], int]:
    merged: dict[tuple, dict] = {}
    duplicates = 0
    for row in findings:
        key = _finding_key(row)
        if key not in merged:
            item = dict(row)
            item["evidence"] = dict(row.get("evidence") or {})
            item["evidence"]["corroboration_count"] = 1
            merged[key] = item
            continue
        duplicates += 1
        current = merged[key]
        evidence = current.get("evidence") or {}
        count = int(evidence.get("corroboration_count", 1)) + 1
        evidence["corroboration_count"] = count
        evidence["corroborated"] = True
        current["evidence"] = evidence
        current["confidence"] = min(
            100,
            max(int(current.get("confidence", 0)), int(row.get("confidence", 0))) + min(10, (count - 1) * 3),
        )
    return list(merged.values()), duplicates


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
        "followup_targets": [],
        "vulnerability_followup_targets": [],
        "scope_filtered": 0,
        "vulnerability_targets": [],
    }
    discovered_subjects: list[str] = []
    validated_web_subjects: list[str] = []
    validated_web_subjects: list[str] = []

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
                subject = str(subject)
                engine.add_provider_result(provider_name, subject, payload)
                if provider_name in DISCOVERY_PROVIDERS and subject != target:
                    if authorize is None or authorize(subject):
                        if subject not in discovered_subjects and len(discovered_subjects) < MAX_FOLLOWUP_TARGETS:
                            discovered_subjects.append(subject)
                    else:
                        internal["scope_filtered"] += 1
        except Exception as exc:
            internal["errors"].append(
                {
                    "provider": provider_name,
                    "error": exc.__class__.__name__,
                }
            )

    if profile in {"surface", "balanced"}:
        for child in discovered_subjects:
            internal["followup_targets"].append(child)
            for provider_name in FOLLOWUP_PROVIDERS:
                try:
                    if not registry.available(provider_name, child):
                        continue
                    results = registry.execute(provider_name, target=child)
                    for result in results:
                        payload = asdict(result)
                        evidence = payload.get("evidence") or {}
                        subject = str(
                            evidence.get("asset")
                            or evidence.get("url")
                            or evidence.get("matched_at")
                            or child
                        )
                        if authorize is not None and not authorize(subject):
                            internal["scope_filtered"] += 1
                            continue
                        engine.add_provider_result(provider_name, subject, payload)
                        if provider_name == "httpx":
                            status_code = evidence.get("status_code")
                            url = evidence.get("url") or subject
                            if status_code and url and url not in validated_web_subjects:
                                validated_web_subjects.append(str(url))
                        if provider_name == "httpx":
                            evidence = payload.get("evidence") or {}
                            status = evidence.get("status_code")
                            url = evidence.get("url") or subject
                            if status is not None and str(url).startswith(("http://", "https://")):
                                if url not in validated_web_subjects and len(validated_web_subjects) < MAX_VULN_FOLLOWUP_TARGETS:
                                    validated_web_subjects.append(str(url))
                except Exception as exc:
                    internal["errors"].append(
                        {"provider": provider_name, "error": exc.__class__.__name__, "phase": "followup"}
                    )

    if profile == "balanced":
        for child in validated_web_subjects[:MAX_VULN_FOLLOWUP_TARGETS]:
            internal["vulnerability_followup_targets"].append(child)
            for provider_name in VULN_FOLLOWUP_PROVIDERS:
                try:
                    if authorize is not None and not authorize(child):
                        internal["scope_filtered"] += 1
                        continue
                    if not registry.available(provider_name, child):
                        continue
                    results = registry.execute(provider_name, target=child)
                    for result in results:
                        payload = asdict(result)
                        evidence = payload.get("evidence") or {}
                        subject = str(
                            evidence.get("asset")
                            or evidence.get("url")
                            or evidence.get("matched_at")
                            or child
                        )
                        if authorize is not None and not authorize(subject):
                            internal["scope_filtered"] += 1
                            continue
                        engine.add_provider_result(provider_name, subject, payload)
                except Exception as exc:
                    internal["errors"].append(
                        {"provider": provider_name, "error": exc.__class__.__name__, "phase": "vulnerability-followup"}
                    )

    if profile == "balanced":
        for web_target in validated_web_subjects[:MAX_VULNERABILITY_TARGETS]:
            if authorize is not None and not authorize(web_target):
                internal["scope_filtered"] += 1
                continue
            internal["vulnerability_targets"].append(web_target)
            for provider_name in VULNERABILITY_FOLLOWUP_PROVIDERS:
                try:
                    if not registry.available(provider_name, web_target):
                        continue
                    results = registry.execute(provider_name, target=web_target)
                    for result in results:
                        payload = asdict(result)
                        evidence = payload.get("evidence") or {}
                        subject = str(
                            evidence.get("asset")
                            or evidence.get("url")
                            or evidence.get("matched_at")
                            or web_target
                        )
                        if authorize is not None and not authorize(subject):
                            internal["scope_filtered"] += 1
                            continue
                        engine.add_provider_result(provider_name, subject, payload)
                except Exception as exc:
                    internal["errors"].append(
                        {"provider": provider_name, "error": exc.__class__.__name__, "phase": "vulnerability-followup"}
                    )

    public = engine.export_public()
    raw_finding_count = public["finding_count"]
    deduped, duplicate_count = _deduplicate_findings(public.get("findings", []))
    public["findings"] = deduped
    public["finding_count"] = len(deduped)
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
                "raw_evidence_count": raw_finding_count,
                "deduplicated_evidence": duplicate_count,
                "followup_targets": len(internal["followup_targets"]),
                "vulnerability_followup_targets": len(internal["vulnerability_followup_targets"]),
                "scope_filtered": internal["scope_filtered"],
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
