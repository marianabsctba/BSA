from datetime import datetime, timezone

from .asset_identity import normalize_asset_value
from .correlation import correlate_evidence
from .digital_risk import InfrastructureIndicator, build_infrastructure_graph, build_infrastructure_links
from .discovery import adaptive_discovery, collect_target, discover_surface
from .discovery_orchestrator import plan_candidate_collection
from .exposure_signals import cloud_signals, summarize_signals, takeover_signals
from .graph import build_risk_graph
from .history import change_summary, record_lifecycle, record_observations
from .ip_intelligence import ip_exposure_signal
from .local_ai import (
    OLLAMA_MODEL,
    analyze_api_surface,
    correlate_exposure,
    enabled as local_ai_enabled,
    judge_correlation,
    plan_discovery,
    prioritize_collection,
    validate_asset_identity,
)
from .scope import asset_in_scope
from .store import ASSETS as STORE_ASSETS, FINDINGS as STORE_FINDINGS
from .technology_intelligence import extract_technologies, fingerprint_technology, technology_match_quality


def _tenant_state(principal):
    assets=[a for a in STORE_ASSETS if getattr(a,"tenant_id","tenant-demo")==principal.tenant_id and asset_in_scope(principal,a.value)]
    ids={a.id for a in assets}
    findings=[f for f in STORE_FINDINGS if getattr(f,"tenant_id","tenant-demo")==principal.tenant_id and f.asset_id in ids]
    return assets,findings


def _collect(target: str, checks: list[str]):
    return collect_target(target,checks)


def run_active_operation(operation: str, target: str, payload: dict, principal):
    payload=payload or {}

    if operation=="discovery.basic":
        checks=list(dict.fromkeys(payload.get("checks") or ["dns","http","tls","ct"]))
        allowed={"dns","http","tls","ct"}
        if not checks or any(x not in allowed for x in checks):
            raise ValueError("checks must contain only dns, http, tls and ct")
        return _collect(target,checks)

    if operation=="discovery.adaptive":
        max_rounds=max(1,min(3,int(payload.get("max_rounds",3))))
        max_assets=max(1,min(100,int(payload.get("max_assets",40))))
        result=adaptive_discovery(target,max_rounds=max_rounds,max_assets=max_assets)
        candidates=[{
            "kind":"hostname","value":x["value"],"confidence":x["confidence"],
            "evidence_refs":x["evidence_refs"],"reasons":x["reasons"],
        } for x in result.get("candidates",[])]
        plans=plan_candidate_collection(candidates,max_jobs=max_assets)
        authorized=[p for p in plans if asset_in_scope(principal,p.target)]
        return {
            "target":result["seed"],"rounds":result["rounds"],"candidates":candidates,
            "collection_plan":[{
                "collector":p.collector,"target_kind":p.target_kind,"target":p.target,
                "priority":p.priority,"reason":p.reason,
            } for p in authorized],
            "summary":{
                "candidate_count":len(candidates),"planned_jobs":len(authorized),
                "max_assets":max_assets,"scope_filtered_jobs":len(plans)-len(authorized),
            },
        }

    if operation=="discovery.ip_intelligence":
        data=_collect(target,["dns","http","tls","ct","ports","rdap","ip_intel"])
        ips=sorted({str(e.get("value")) for e in data["evidence"] if e.get("kind") in {"a_record","aaaa"}})
        return {"target":data["target"],"ips":[ip_exposure_signal(x) for x in ips],"evidence_count":data["evidence_count"]}

    if operation=="discovery.ai_identity":
        data=_collect(target,["dns","http","tls","ct","rdap"])
        assets=correlate_evidence(target,data["evidence"])
        items=[{
            "fingerprint":a.fingerprint,"value":a.value,"asset_type":a.asset_type,
            "confidence":a.confidence,"sources":list(a.sources),"evidence_count":a.evidence_count,
            "tags":list(a.tags),
        } for a in assets]
        result=validate_asset_identity(items,data["evidence"])
        return {
            "target":data["target"],"ai_enabled":local_ai_enabled(),
            "model":OLLAMA_MODEL if local_ai_enabled() else None,
            "assets":items,"evidence_count":data["evidence_count"],"identity_validation":result,
        }

    if operation=="discovery.ai_prioritize":
        data=_collect(target,["dns","http","tls","ct"])
        signals=[{
            "kind":e.get("kind"),"value":e.get("value"),"confidence":e.get("confidence")
        } for e in data["evidence"] if e.get("kind") in {"http_status","certificate_name","a_record","aaaa","openapi_endpoint"}]
        candidate_checks=["dns","http","tls","ct","ports","rdap","ip_intel"]
        result=prioritize_collection(target,data["evidence"],signals,candidate_checks)
        return {
            "target":data["target"],"ai_enabled":local_ai_enabled(),
            "model":OLLAMA_MODEL if local_ai_enabled() else None,
            "evidence_count":data["evidence_count"],"candidate_checks":candidate_checks,
            "prioritization":result,"fallback":"deterministic collector order" if result is None else None,
        }

    if operation=="discovery.ai_api_surface":
        data=_collect(target,["http"])
        endpoints=[e for e in data["evidence"] if e.get("kind")=="openapi_endpoint"]
        technologies=[e for e in data["evidence"] if str(e.get("kind","")).startswith("technology:")]
        result=analyze_api_surface(target,endpoints,technologies)
        return {
            "target":data["target"],"ai_enabled":local_ai_enabled(),
            "model":OLLAMA_MODEL if local_ai_enabled() else None,
            "endpoint_count":len(endpoints),"evidence_count":data["evidence_count"],
            "analysis":result,"fallback":"deterministic evidence only" if result is None else None,
        }

    if operation=="discovery.ai_correlate":
        data=_collect(target,["dns","http","tls","ct","ports","rdap"])
        result=correlate_exposure(target,data["evidence"])
        return {
            "target":data["target"],"ai_enabled":local_ai_enabled(),
            "model":OLLAMA_MODEL if local_ai_enabled() else None,
            "evidence_count":data["evidence_count"],"correlation":result,
        }

    if operation=="discovery.signals":
        data=_collect(target,["dns","http","tls","ct","ports","rdap"])
        values=[str(e.get("value","")) for e in data["evidence"]]
        http_values=[str(e.get("value","")) for e in data["evidence"] if str(e.get("kind","")).startswith(("http_","page_"))]
        signals=cloud_signals(values)+takeover_signals(http_values)
        return {"target":data["target"],"evidence_count":data["evidence_count"],**summarize_signals(signals)}

    if operation=="discovery.ai_judge":
        data=_collect(target,["dns","http","tls","ct","ports","rdap"])
        grouped={}
        for e in data["evidence"]:
            grouped.setdefault(str(e.get("subject",target)),[]).append(e)
        decisions=[]
        for subject,items in grouped.items():
            if len(items)<2:
                continue
            decision=judge_correlation(subject,items)
            if decision:
                decisions.append({"subject":subject,"decision":decision})
        return {
            "target":data["target"],"evidence_count":data["evidence_count"],
            "ai_enabled":local_ai_enabled(),"model":OLLAMA_MODEL if local_ai_enabled() else None,
            "decisions":decisions,
        }

    if operation=="discovery.ai_plan":
        data=_collect(target,["dns","http","tls","ct"])
        plan=plan_discovery(target,data)
        return {
            "target":data["target"],"ai_enabled":local_ai_enabled(),
            "model":OLLAMA_MODEL if local_ai_enabled() else None,
            "evidence_count":data["evidence_count"],"plan":plan,
            "fallback":"deterministic discovery only" if plan is None else None,
        }

    if operation=="technology.intelligence":
        data=_collect(target,["http","tls"])
        observations=extract_technologies(data["evidence"])
        fingerprints=fingerprint_technology(data["evidence"])
        items=[]
        for o in observations:
            item={
                "product":o.product,"version":o.version,"confidence":o.confidence,"source":o.source,
                "evidence":o.evidence,"version_confirmed":o.version_confirmed,
            }
            item["matching"]=technology_match_quality(o)
            items.append(item)
        return {
            "target":data["target"],"technologies":items,"fingerprints":fingerprints,
            "summary":{
                "products":len(items),"version_confirmed":sum(x["version_confirmed"] for x in items),
                "product_only":sum(not x["version_confirmed"] for x in items),
                "fingerprint_candidates":len(fingerprints),
                "cve_matching":sum(x["matching"]["matching_allowed"] for x in items),
            },
        }

    if operation=="discovery.changes":
        data=_collect(target,["dns","http","tls","ct"])
        assets=correlate_evidence(data["target"],data["evidence"])
        record_observations(assets,principal.tenant_id)
        return {
            "target":data["target"],
            "changes":[{
                "fingerprint":a.fingerprint,"asset":a.value,"type":a.asset_type,
                "change":change_summary(a.fingerprint,principal.tenant_id),
            } for a in assets],
        }

    if operation=="discovery.graph":
        source_assets,findings=_tenant_state(principal)
        data=_collect(target,["dns","http","tls","ct"])
        assets=correlate_evidence(data["target"],data["evidence"])
        return build_risk_graph(data["target"],assets,data["evidence"],source_assets=source_assets,findings=findings)

    if operation=="discovery.correlation":
        data=_collect(target,["dns","http","tls","ct"])
        assets=correlate_evidence(data["target"],data["evidence"])
        observations=record_observations(assets,principal.tenant_id)
        return {
            "target":data["target"],"evidence_count":data["evidence_count"],"confidence":data["confidence"],
            "assets":[{
                "fingerprint":a.fingerprint,"value":a.value,"type":a.asset_type,"confidence":a.confidence,
                "sources":list(a.sources),"evidence_count":a.evidence_count,"tags":list(a.tags),
                "evidence_refs":list(a.evidence_refs),"independent_source_count":len(a.sources),
                "identity_quality":"corroborated" if len(a.sources)>=2 and a.evidence_count>=2 else "single-source" if len(a.sources)==1 else "unverified",
                "history":change_summary(a.fingerprint,principal.tenant_id),
            } for a in assets],
            "observation_count":len(observations),
        }

    if operation=="easm.discover":
        max_depth=int(payload.get("max_depth",2))
        max_assets=int(payload.get("max_assets",40))
        if max_depth<0 or max_depth>3 or max_assets<1 or max_assets>100:
            raise ValueError("invalid discovery bounds")
        return discover_surface(
            target,max_depth=max_depth,max_assets=max_assets,
            scope_validator=lambda candidate: asset_in_scope(principal,candidate),
        )

    if operation=="easm.lifecycle":
        data=_collect(target,["dns","http","tls","ct"])
        assets=correlate_evidence(data["target"],data["evidence"])
        lifecycle=record_lifecycle(assets,data["evidence"],principal.tenant_id)
        changed=[x for x in lifecycle if x["state"]=="changed"]
        new=[x for x in lifecycle if x["state"]=="new"]
        return {
            "target":data["target"],"observed_at":datetime.now(timezone.utc).isoformat(),
            "summary":{
                "assets":len(lifecycle),"new":len(new),"changed":len(changed),
                "stable":len(lifecycle)-len(new)-len(changed),
                "evidence":data["evidence_count"],"confidence":data["confidence"],
            },
            "assets":lifecycle,
        }

    if operation in {"discovery.infrastructure","discovery.infrastructure_graph"}:
        data=_collect(target,["dns","http","tls","ct"])
        item=InfrastructureIndicator(indicator=data["target"],source="bsa_discovery",confidence=data["confidence"])
        for e in data["evidence"]:
            kind=e.get("kind","")
            value=e.get("value")
            if kind=="a_record" and not item.ip:
                item.ip=value
            elif kind=="certificate_cn" and not item.certificate_sha256:
                item.certificate_sha256=value
            elif kind=="certificate_name" and value and value!=data["target"]:
                item.related_domains.append(value)
            elif kind=="http_header:server":
                item.registrar=value
        if operation=="discovery.infrastructure_graph":
            graph=build_infrastructure_graph(item)
            graph["discovery"]={"target":data["target"],"evidence_count":data["evidence_count"],"confidence":data["confidence"]}
            return graph
        result=build_infrastructure_links(item)
        result["discovery"]={"target":data["target"],"evidence_count":data["evidence_count"],"confidence":data["confidence"]}
        result["evidence"]=data["evidence"]
        return result

    if operation=="discovery.risk_paths":
        source_assets,findings=_tenant_state(principal)
        data=_collect(target,["dns","http","tls","ct"])
        assets=correlate_evidence(data["target"],data["evidence"])
        graph=build_risk_graph(data["target"],assets,data["evidence"],source_assets=source_assets,findings=findings)
        return {"target":data["target"],"paths":graph["top_risk_paths"],"summary":graph["risk_summary"]}

    raise ValueError(f"unsupported active operation: {operation}")
