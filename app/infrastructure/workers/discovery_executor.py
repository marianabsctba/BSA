from ...discovery import adaptive_discovery, collect_target
from ...discovery_orchestrator import plan_candidate_collection
from ...ip_intelligence import ip_exposure_signal
from ...scope import asset_in_scope


SUPPORTED_DISCOVERY_OPERATIONS={
    "discovery.basic",
    "discovery.adaptive",
    "discovery.ip_intelligence",
}


def supports(operation: str) -> bool:
    return operation in SUPPORTED_DISCOVERY_OPERATIONS


def run_discovery_operation(operation: str, target: str, payload: dict, principal):
    payload=payload or {}

    if operation=="discovery.basic":
        checks=list(dict.fromkeys(payload.get("checks") or ["dns","http","tls","ct"]))
        allowed={"dns","http","tls","ct"}
        if not checks or any(check not in allowed for check in checks):
            raise ValueError("checks must contain only dns, http, tls and ct")
        return collect_target(target,checks)

    if operation=="discovery.adaptive":
        max_rounds=max(1,min(3,int(payload.get("max_rounds",3))))
        max_assets=max(1,min(100,int(payload.get("max_assets",40))))
        result=adaptive_discovery(target,max_rounds=max_rounds,max_assets=max_assets)
        candidates=[{
            "kind":"hostname",
            "value":item["value"],
            "confidence":item["confidence"],
            "evidence_refs":item["evidence_refs"],
            "reasons":item["reasons"],
        } for item in result.get("candidates",[])]
        plans=plan_candidate_collection(candidates,max_jobs=max_assets)
        authorized=[plan for plan in plans if asset_in_scope(principal,plan.target)]
        return {
            "target":result["seed"],
            "rounds":result["rounds"],
            "candidates":candidates,
            "collection_plan":[{
                "collector":plan.collector,
                "target_kind":plan.target_kind,
                "target":plan.target,
                "priority":plan.priority,
                "reason":plan.reason,
            } for plan in authorized],
            "summary":{
                "candidate_count":len(candidates),
                "planned_jobs":len(authorized),
                "max_assets":max_assets,
                "scope_filtered_jobs":len(plans)-len(authorized),
            },
        }

    if operation=="discovery.ip_intelligence":
        data=collect_target(target,["dns","http","tls","ct","ports","rdap","ip_intel"])
        ips=sorted({
            str(evidence.get("value"))
            for evidence in data["evidence"]
            if evidence.get("kind") in {"a_record","aaaa"}
        })
        return {
            "target":data["target"],
            "ips":[ip_exposure_signal(ip) for ip in ips],
            "evidence_count":data["evidence_count"],
        }

    raise ValueError(f"unsupported discovery operation: {operation}")
