from datetime import datetime, timezone

from ...correlation import correlate_evidence
from ...digital_risk import (
    InfrastructureIndicator,
    build_infrastructure_graph,
    build_infrastructure_links,
)
from ...discovery import collect_target, discover_surface
from ...graph import build_risk_graph
from ...history import record_lifecycle
from ...repositories.assets_findings import asset_finding_repository
from ...scope import asset_in_scope


SUPPORTED_EASM_OPERATIONS={
    "easm.discover",
    "easm.lifecycle",
    "discovery.graph",
    "discovery.infrastructure",
    "discovery.infrastructure_graph",
    "discovery.risk_paths",
}


def supports(operation: str) -> bool:
    return operation in SUPPORTED_EASM_OPERATIONS


def _tenant_state(principal):
    repository=asset_finding_repository()
    assets=[
        asset for asset in repository.list_assets(principal.tenant_id)
        if asset_in_scope(principal,asset.value)
    ]
    asset_ids={asset.id for asset in assets}
    findings=repository.list_findings(principal.tenant_id,asset_ids)
    return assets,findings


def run_easm_operation(operation: str, target: str, payload: dict, principal):
    payload=payload or {}

    if operation=="easm.discover":
        max_depth=int(payload.get("max_depth",2))
        max_assets=int(payload.get("max_assets",40))
        if max_depth<0 or max_depth>3 or max_assets<1 or max_assets>100:
            raise ValueError("invalid discovery bounds")
        return discover_surface(
            target,
            max_depth=max_depth,
            max_assets=max_assets,
            scope_validator=lambda candidate: asset_in_scope(principal,candidate),
        )

    if operation=="easm.lifecycle":
        data=collect_target(target,["dns","http","tls","ct"])
        assets=correlate_evidence(data["target"],data["evidence"])
        lifecycle=record_lifecycle(assets,data["evidence"],principal.tenant_id)
        changed=[item for item in lifecycle if item["state"]=="changed"]
        new=[item for item in lifecycle if item["state"]=="new"]
        return {
            "target":data["target"],
            "observed_at":datetime.now(timezone.utc).isoformat(),
            "summary":{
                "assets":len(lifecycle),
                "new":len(new),
                "changed":len(changed),
                "stable":len(lifecycle)-len(new)-len(changed),
                "evidence":data["evidence_count"],
                "confidence":data["confidence"],
            },
            "assets":lifecycle,
        }

    if operation=="discovery.graph":
        source_assets,findings=_tenant_state(principal)
        data=collect_target(target,["dns","http","tls","ct"])
        assets=correlate_evidence(data["target"],data["evidence"])
        return build_risk_graph(
            data["target"],
            assets,
            data["evidence"],
            source_assets=source_assets,
            findings=findings,
        )

    if operation in {"discovery.infrastructure","discovery.infrastructure_graph"}:
        data=collect_target(target,["dns","http","tls","ct"])
        item=InfrastructureIndicator(
            indicator=data["target"],
            source="bsa_discovery",
            confidence=data["confidence"],
        )
        for evidence in data["evidence"]:
            kind=evidence.get("kind","")
            value=evidence.get("value")
            if kind=="a_record" and not item.ip:
                item.ip=value
            elif kind=="certificate_cn" and not item.certificate_sha256:
                item.certificate_sha256=value
            elif kind=="certificate_name" and value and value!=data["target"]:
                item.related_domains.append(value)
            elif kind=="http_header:server":
                item.registrar=value

        discovery_context={
            "target":data["target"],
            "evidence_count":data["evidence_count"],
            "confidence":data["confidence"],
        }
        if operation=="discovery.infrastructure_graph":
            graph=build_infrastructure_graph(item)
            graph["discovery"]=discovery_context
            return graph

        result=build_infrastructure_links(item)
        result["discovery"]=discovery_context
        result["evidence"]=data["evidence"]
        return result

    if operation=="discovery.risk_paths":
        source_assets,findings=_tenant_state(principal)
        data=collect_target(target,["dns","http","tls","ct"])
        assets=correlate_evidence(data["target"],data["evidence"])
        graph=build_risk_graph(
            data["target"],
            assets,
            data["evidence"],
            source_assets=source_assets,
            findings=findings,
        )
        return {
            "target":data["target"],
            "paths":graph["top_risk_paths"],
            "summary":graph["risk_summary"],
        }

    raise ValueError(f"unsupported EASM operation: {operation}")
