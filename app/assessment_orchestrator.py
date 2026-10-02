"""Unified exposure assessment orchestration for Be Safe ASM.

Profiles describe product intent, not underlying tools. The orchestrator runs
only engines available on the worker, normalizes their evidence and returns a
product-safe payload.
"""

from dataclasses import asdict
from typing import Callable
import os
import time

from .assessment_engine import AssessmentEngine
from .assessment_registry import registry
from .exposure_signals import cloud_signals, summarize_signals
from .vulnerability_evidence import vulnerability_identity_key


PROFILES = {
    "surface": ("subfinder", "amass", "assetfinder", "alterx", "puredns", "dnsx", "asnmap", "httpx", "tlsx", "gau"),
    "rapid": ("httpx", "tlsx", "nuclei"),
    "network": ("dnsx", "httpx", "naabu", "nmap"),
    "balanced": ("subfinder", "amass", "assetfinder", "alterx", "puredns", "dnsx", "asnmap", "httpx", "whatweb", "tlsx", "testssl", "gau", "katana", "safeweb", "zap", "cloud", "nuclei", "naabu", "nmap", "cti", "threatfox", "hibp", "hudsonrock", "leak", "trufflehog"),
}

DISCOVERY_PROVIDERS = {"subfinder", "amass", "assetfinder", "alterx"}
FOLLOWUP_PROVIDERS = ("puredns", "dnsx", "httpx", "tlsx", "whatweb")
VULN_FOLLOWUP_PROVIDERS = ("nuclei", "zap")
DEFERRED_BALANCED_PROVIDERS = set(VULN_FOLLOWUP_PROVIDERS)
MAX_FOLLOWUP_TARGETS = 32
MAX_VULN_FOLLOWUP_TARGETS = 8


def _bounded_env_int(name: str, default: int, minimum: int, maximum: int) -> int:
    try:
        value = int(os.getenv(name, str(default)))
    except (TypeError, ValueError):
        value = default
    return max(minimum, min(maximum, value))


def _runtime_budget() -> dict:
    return {
        "max_seconds": _bounded_env_int("BSA_ASSESSMENT_BUDGET_SECONDS", 480, 30, 3600),
        "max_followup_targets": _bounded_env_int(
            "BSA_ASSESSMENT_MAX_FOLLOWUPS", MAX_FOLLOWUP_TARGETS, 1, MAX_FOLLOWUP_TARGETS
        ),
        "max_vulnerability_followup_targets": _bounded_env_int(
            "BSA_ASSESSMENT_MAX_VULN_FOLLOWUPS", MAX_VULN_FOLLOWUP_TARGETS, 1, MAX_VULN_FOLLOWUP_TARGETS
        ),
        "max_findings": _bounded_env_int("BSA_ASSESSMENT_MAX_FINDINGS", 2000, 50, 10000),
    }


PROFILE_OPTIONAL_CAPABILITIES = {
    "surface": (),
    "rapid": (),
    "network": (),
    "balanced": ("credential_exposure", "intelligence"),
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


def _provider_capabilities(provider_name: str) -> tuple[str, ...]:
    return tuple(
        capability
        for capability, providers in registry.CAPABILITY_PROVIDERS.items()
        if provider_name in providers
    )


def _record_capability_call(
    telemetry: dict[str, dict],
    provider_name: str,
    *,
    elapsed_ms: int,
    result_count: int = 0,
    error: bool = False,
) -> None:
    for capability in _provider_capabilities(provider_name):
        row = telemetry.setdefault(
            capability,
            {"calls": 0, "execution_ms": 0, "raw_results": 0, "errors": 0},
        )
        row["calls"] += 1
        row["execution_ms"] += max(0, int(elapsed_ms))
        row["raw_results"] += max(0, int(result_count))
        if error:
            row["errors"] += 1


def _capability_telemetry_public(telemetry: dict[str, dict]) -> list[dict]:
    return [
        {"name": name, **values}
        for name, values in sorted(telemetry.items())
    ]


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
    return vulnerability_identity_key(row)


def _deduplicate_findings(findings: list[dict]) -> tuple[list[dict], int]:
    merged: dict[tuple, dict] = {}
    duplicates = 0
    for row in findings:
        key = _finding_key(row)
        if key not in merged:
            item = dict(row)
            source = item.pop("_source_backend", None)
            item["_source_backends"] = [source] if source else []
            item["evidence"] = dict(row.get("evidence") or {})
            item["evidence"]["corroboration_count"] = 1
            item["evidence"]["independent_source_count"] = 1 if source else 0
            item["evidence"]["independently_corroborated"] = False
            merged[key] = item
            continue
        duplicates += 1
        current = merged[key]
        evidence = current.get("evidence") or {}
        incoming = row.get("evidence") or {}
        count = int(evidence.get("corroboration_count", 1)) + 1
        evidence["corroboration_count"] = count
        evidence["corroborated"] = True

        source = row.get("_source_backend")
        source_backends = list(current.get("_source_backends") or [])
        if source and source not in source_backends:
            source_backends.append(source)
        current["_source_backends"] = source_backends
        independent_count = len(source_backends)
        evidence["independent_source_count"] = independent_count
        evidence["independently_corroborated"] = independent_count >= 2

        refs = evidence.get("reference") or evidence.get("references") or []
        incoming_refs = incoming.get("reference") or incoming.get("references") or []
        if isinstance(refs, str):
            refs = [refs]
        if isinstance(incoming_refs, str):
            incoming_refs = [incoming_refs]
        merged_refs = sorted({str(x) for x in [*refs, *incoming_refs] if x})
        if merged_refs:
            evidence["references"] = merged_refs[:20]

        state_rank = {"needs_validation": 1, "observed": 2, "confirmed_evidence": 3, "confirmed": 4}
        current_state = str(evidence.get("validation_state") or "")
        incoming_state = str(incoming.get("validation_state") or "")
        if state_rank.get(incoming_state, 0) > state_rank.get(current_state, 0):
            evidence["validation_state"] = incoming_state

        for field in ("cvss", "cpe", "vulnerability_id"):
            if not evidence.get(field) and incoming.get(field):
                evidence[field] = incoming.get(field)

        current["evidence"] = evidence
        corroboration_boost = min(12, max(0, independent_count - 1) * 4)
        current["confidence"] = min(
            100,
            max(int(current.get("confidence", 0)), int(row.get("confidence", 0))) + corroboration_boost,
        )
        severity_rank = {"info": 0, "low": 1, "medium": 2, "high": 3, "critical": 4}
        if severity_rank.get(str(row.get("severity") or "info"), 0) > severity_rank.get(str(current.get("severity") or "info"), 0):
            current["severity"] = row.get("severity")
    out = []
    for item in merged.values():
        item.pop("_source_backend", None)
        item.pop("_source_backends", None)
        out.append(item)
    return out, duplicates


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

    budget = _runtime_budget()
    started = time.monotonic()
    deadline = started + budget["max_seconds"]
    engine = AssessmentEngine()
    internal = {
        "profile": profile,
        "budget": dict(budget),
        "budget_exhausted": False,
        "execution_ms": 0,
        "provider_calls": 0,
        "capability_telemetry": {},
        "attempted": [],
        "available": [],
        "deferred": [],
        "errors": [],
        "followup_targets": [],
        "vulnerability_followup_targets": [],
        "scope_filtered": 0,
    }
    discovered_subjects: list[str] = []
    validated_web_subjects: list[str] = []

    def budget_available() -> bool:
        if time.monotonic() >= deadline:
            internal["budget_exhausted"] = True
            return False
        if len(engine.findings) >= budget["max_findings"]:
            internal["budget_exhausted"] = True
            return False
        return True

    for provider_name in PROFILES[profile]:
        if not budget_available():
            break
        internal["attempted"].append(provider_name)
        if profile == "balanced" and provider_name in DEFERRED_BALANCED_PROVIDERS:
            internal["deferred"].append(provider_name)
            continue
        try:
            if not registry.available(provider_name, target):
                continue
            internal["available"].append(provider_name)
            internal["provider_calls"] += 1
            call_started = time.monotonic()
            results = registry.execute(provider_name, target=target)
            _record_capability_call(
                internal["capability_telemetry"],
                provider_name,
                elapsed_ms=round((time.monotonic() - call_started) * 1000),
                result_count=len(results),
            )
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
                if authorize is not None and not authorize(subject):
                    internal["scope_filtered"] += 1
                    continue
                engine.add_provider_result(provider_name, subject, payload)
                if provider_name == "httpx":
                    status = evidence.get("status_code")
                    url = evidence.get("url") or subject
                    if status is not None and str(url).startswith(("http://", "https://")):
                        if url not in validated_web_subjects and len(validated_web_subjects) < budget["max_vulnerability_followup_targets"]:
                            validated_web_subjects.append(str(url))
                if provider_name in DISCOVERY_PROVIDERS and subject != target:
                    if subject not in discovered_subjects and len(discovered_subjects) < budget["max_followup_targets"]:
                        discovered_subjects.append(subject)
        except Exception as exc:
            _record_capability_call(
                internal["capability_telemetry"],
                provider_name,
                elapsed_ms=0,
                error=True,
            )
            internal["errors"].append(
                {
                    "provider": provider_name,
                    "error": exc.__class__.__name__,
                }
            )

    if profile in {"surface", "balanced"}:
        for child in discovered_subjects:
            if not budget_available():
                break
            internal["followup_targets"].append(child)
            for provider_name in FOLLOWUP_PROVIDERS:
                if not budget_available():
                    break
                try:
                    if not registry.available(provider_name, child):
                        continue
                    internal["provider_calls"] += 1
                    call_started = time.monotonic()
                    results = registry.execute(provider_name, target=child)
                    _record_capability_call(
                        internal["capability_telemetry"],
                        provider_name,
                        elapsed_ms=round((time.monotonic() - call_started) * 1000),
                        result_count=len(results),
                    )
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
                            status = evidence.get("status_code")
                            url = evidence.get("url") or subject
                            if status is not None and str(url).startswith(("http://", "https://")):
                                if url not in validated_web_subjects and len(validated_web_subjects) < budget["max_vulnerability_followup_targets"]:
                                    validated_web_subjects.append(str(url))
                except Exception as exc:
                    _record_capability_call(
                        internal["capability_telemetry"],
                        provider_name,
                        elapsed_ms=0,
                        error=True,
                    )
                    internal["errors"].append(
                        {"provider": provider_name, "error": exc.__class__.__name__, "phase": "followup"}
                    )

    if profile == "balanced":
        for child in validated_web_subjects[:budget["max_vulnerability_followup_targets"]]:
            if not budget_available():
                break
            internal["vulnerability_followup_targets"].append(child)
            for provider_name in VULN_FOLLOWUP_PROVIDERS:
                if not budget_available():
                    break
                try:
                    if authorize is not None and not authorize(child):
                        internal["scope_filtered"] += 1
                        continue
                    if not registry.available(provider_name, child):
                        continue
                    internal["provider_calls"] += 1
                    call_started = time.monotonic()
                    results = registry.execute(provider_name, target=child)
                    _record_capability_call(
                        internal["capability_telemetry"],
                        provider_name,
                        elapsed_ms=round((time.monotonic() - call_started) * 1000),
                        result_count=len(results),
                    )
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
                    _record_capability_call(
                        internal["capability_telemetry"],
                        provider_name,
                        elapsed_ms=0,
                        error=True,
                    )
                    internal["errors"].append(
                        {"provider": provider_name, "error": exc.__class__.__name__, "phase": "vulnerability-followup"}
                    )


    internal["execution_ms"] = round((time.monotonic() - started) * 1000)
    public = engine.export_public()
    orchestration_rows = engine.export_orchestration_rows()
    raw_finding_count = len(orchestration_rows)
    deduped, duplicate_count = _deduplicate_findings(orchestration_rows)
    public["findings"] = deduped
    public["finding_count"] = len(deduped)
    cloud = _cloud_intelligence(public.get("findings", []))
    if cloud:
        public["findings"].extend(cloud)
        public["finding_count"] = len(public["findings"])
    capability_health = registry.capability_health(target, PROFILE_CAPABILITIES[profile])
    optional_capabilities = set(PROFILE_OPTIONAL_CAPABILITIES.get(profile, ()))
    core_health = [row for row in capability_health if row.get("name") not in optional_capabilities]
    optional_health = [row for row in capability_health if row.get("name") in optional_capabilities]
    operational_capabilities = sum(1 for row in core_health if row.get("operational"))
    requested_capabilities = len(core_health)
    capability_coverage_percent = round(
        100 * operational_capabilities / max(1, requested_capabilities)
    )
    optional_operational = sum(1 for row in optional_health if row.get("operational"))

    public.update(
        {
            "profile": profile,
            "capabilities": list(PROFILE_CAPABILITIES[profile]),
            "optional_capabilities": sorted(optional_capabilities),
            "partial_coverage": bool(internal["errors"]) or internal["budget_exhausted"] or operational_capabilities < requested_capabilities,
            "coverage": {
                "requested_capabilities": requested_capabilities,
                "operational_capabilities": operational_capabilities,
                "capability_coverage_percent": capability_coverage_percent,
                "optional_capabilities": len(optional_health),
                "optional_operational_capabilities": optional_operational,
                "capability_status": capability_health,
                "evidence_count": public["finding_count"],
                "raw_evidence_count": raw_finding_count,
                "deduplicated_evidence": duplicate_count,
                "followup_targets": len(internal["followup_targets"]),
                "vulnerability_followup_targets": len(internal["vulnerability_followup_targets"]),
                "scope_filtered": internal["scope_filtered"],
                "budget_exhausted": internal["budget_exhausted"],
                "execution_ms": internal["execution_ms"],
                "provider_calls": internal["provider_calls"],
                "capability_metrics": _capability_telemetry_public(
                    internal["capability_telemetry"]
                ),
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
