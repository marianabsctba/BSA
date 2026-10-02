from ...correlation import correlate_evidence
from ...discovery import collect_target
from ...exposure_signals import cloud_signals, summarize_signals, takeover_signals
from ...history import change_summary, record_observations
from ...local_ai import (
    OLLAMA_MODEL,
    analyze_api_surface,
    correlate_exposure,
    enabled as local_ai_enabled,
    judge_correlation,
    plan_discovery,
    prioritize_collection,
    validate_asset_identity,
)

SUPPORTED_INTELLIGENCE_OPERATIONS={
    "discovery.ai_identity",
    "discovery.ai_prioritize",
    "discovery.ai_api_surface",
    "discovery.ai_correlate",
    "discovery.signals",
    "discovery.ai_judge",
    "discovery.ai_plan",
    "discovery.changes",
    "discovery.correlation",
}


def supports(operation: str) -> bool:
    return operation in SUPPORTED_INTELLIGENCE_OPERATIONS


def run_discovery_intelligence_operation(operation: str, target: str, payload: dict, principal):
    payload=payload or {}

    if operation=="discovery.ai_identity":
        data=collect_target(target,["dns","http","tls","ct","rdap"])
        assets=correlate_evidence(target,data["evidence"])
        items=[{
            "fingerprint":asset.fingerprint,
            "value":asset.value,
            "asset_type":asset.asset_type,
            "confidence":asset.confidence,
            "sources":list(asset.sources),
            "evidence_count":asset.evidence_count,
            "tags":list(asset.tags),
        } for asset in assets]
        result=validate_asset_identity(items,data["evidence"])
        return {
            "target":data["target"],
            "ai_enabled":local_ai_enabled(),
            "model":OLLAMA_MODEL if local_ai_enabled() else None,
            "assets":items,
            "evidence_count":data["evidence_count"],
            "identity_validation":result,
        }

    if operation=="discovery.ai_prioritize":
        data=collect_target(target,["dns","http","tls","ct"])
        signals=[{
            "kind":evidence.get("kind"),
            "value":evidence.get("value"),
            "confidence":evidence.get("confidence"),
        } for evidence in data["evidence"] if evidence.get("kind") in {
            "http_status","certificate_name","a_record","aaaa","openapi_endpoint"
        }]
        candidate_checks=["dns","http","tls","ct","ports","rdap","ip_intel"]
        result=prioritize_collection(target,data["evidence"],signals,candidate_checks)
        return {
            "target":data["target"],
            "ai_enabled":local_ai_enabled(),
            "model":OLLAMA_MODEL if local_ai_enabled() else None,
            "evidence_count":data["evidence_count"],
            "candidate_checks":candidate_checks,
            "prioritization":result,
            "fallback":"deterministic collector order" if result is None else None,
        }

    if operation=="discovery.ai_api_surface":
        data=collect_target(target,["http"])
        endpoints=[e for e in data["evidence"] if e.get("kind")=="openapi_endpoint"]
        technologies=[
            e for e in data["evidence"]
            if str(e.get("kind","")).startswith("technology:")
        ]
        result=analyze_api_surface(target,endpoints,technologies)
        return {
            "target":data["target"],
            "ai_enabled":local_ai_enabled(),
            "model":OLLAMA_MODEL if local_ai_enabled() else None,
            "endpoint_count":len(endpoints),
            "evidence_count":data["evidence_count"],
            "analysis":result,
            "fallback":"deterministic evidence only" if result is None else None,
        }

    if operation=="discovery.ai_correlate":
        data=collect_target(target,["dns","http","tls","ct","ports","rdap"])
        result=correlate_exposure(target,data["evidence"])
        return {
            "target":data["target"],
            "ai_enabled":local_ai_enabled(),
            "model":OLLAMA_MODEL if local_ai_enabled() else None,
            "evidence_count":data["evidence_count"],
            "correlation":result,
        }

    if operation=="discovery.signals":
        data=collect_target(target,["dns","http","tls","ct","ports","rdap"])
        values=[str(e.get("value","")) for e in data["evidence"]]
        http_values=[
            str(e.get("value",""))
            for e in data["evidence"]
            if str(e.get("kind","")).startswith(("http_","page_"))
        ]
        signals=cloud_signals(values)+takeover_signals(http_values)
        return {
            "target":data["target"],
            "evidence_count":data["evidence_count"],
            **summarize_signals(signals),
        }

    if operation=="discovery.ai_judge":
        data=collect_target(target,["dns","http","tls","ct","ports","rdap"])
        grouped={}
        for evidence in data["evidence"]:
            grouped.setdefault(str(evidence.get("subject",target)),[]).append(evidence)
        decisions=[]
        for subject,items in grouped.items():
            if len(items)<2:
                continue
            decision=judge_correlation(subject,items)
            if decision:
                decisions.append({"subject":subject,"decision":decision})
        return {
            "target":data["target"],
            "evidence_count":data["evidence_count"],
            "ai_enabled":local_ai_enabled(),
            "model":OLLAMA_MODEL if local_ai_enabled() else None,
            "decisions":decisions,
        }

    if operation=="discovery.ai_plan":
        data=collect_target(target,["dns","http","tls","ct"])
        plan=plan_discovery(target,data)
        return {
            "target":data["target"],
            "ai_enabled":local_ai_enabled(),
            "model":OLLAMA_MODEL if local_ai_enabled() else None,
            "evidence_count":data["evidence_count"],
            "plan":plan,
            "fallback":"deterministic discovery only" if plan is None else None,
        }

    if operation=="discovery.changes":
        data=collect_target(target,["dns","http","tls","ct"])
        assets=correlate_evidence(data["target"],data["evidence"])
        record_observations(assets,principal.tenant_id)
        return {
            "target":data["target"],
            "changes":[{
                "fingerprint":asset.fingerprint,
                "asset":asset.value,
                "type":asset.asset_type,
                "change":change_summary(asset.fingerprint,principal.tenant_id),
            } for asset in assets],
        }

    if operation=="discovery.correlation":
        data=collect_target(target,["dns","http","tls","ct"])
        assets=correlate_evidence(data["target"],data["evidence"])
        observations=record_observations(assets,principal.tenant_id)
        return {
            "target":data["target"],
            "evidence_count":data["evidence_count"],
            "confidence":data["confidence"],
            "assets":[{
                "fingerprint":asset.fingerprint,
                "value":asset.value,
                "type":asset.asset_type,
                "confidence":asset.confidence,
                "sources":list(asset.sources),
                "evidence_count":asset.evidence_count,
                "tags":list(asset.tags),
                "evidence_refs":list(asset.evidence_refs),
                "independent_source_count":len(asset.sources),
                "identity_quality":"corroborated" if len(asset.sources)>=2 and asset.evidence_count>=2 else "single-source" if len(asset.sources)==1 else "unverified",
                "history":change_summary(asset.fingerprint,principal.tenant_id),
            } for asset in assets],
            "observation_count":len(observations),
        }

    raise ValueError(f"unsupported discovery intelligence operation: {operation}")
