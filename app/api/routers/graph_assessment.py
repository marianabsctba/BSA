from datetime import datetime, timezone
from hashlib import sha256
import os

from fastapi import APIRouter, HTTPException, Request
from fastapi.responses import JSONResponse
from pydantic import BaseModel, Field

from ...api.active_scan import govern_active_scan
from ...asset_identity import normalize_asset_value
from ...assessment_registry import registry
from ...auth import Principal, audit, rate_limit_action
from ...ctem_retest import reconcile_ctem_retest_job
from ...graph import build_risk_graph, remediation_options, simulate_remediation
from ...history import recent_change_events, reopen_ctem_item, upsert_ctem_item
from ...job_queue import (
    cancel_job,
    claim_materialization,
    enqueue_assessment,
    finish_materialization,
    get_job,
)
from ...local_ai import (
    OLLAMA_MODEL,
    enabled as local_ai_enabled,
    explain_attack_path,
)
from ...models import Asset, AssetType, Finding, Severity
from ...risk_engine import assess_ctem_priority
from ...scope import asset_in_scope
from ...store import ASSETS as STORE_ASSETS, FINDINGS as STORE_FINDINGS, persist_state
from ...vulnerability_evidence import (
    normalize_vulnerability_evidence,
    vulnerability_identity_key,
)
from ...vulnerability_intelligence import enrich_finding
from ..dependencies import require
from ..tenant_scope import tenant_scope


router=APIRouter()



@router.get("/api/v1/changes")
def list_changes(request: Request, hours: int=24, limit: int=200):
    principal=require(request,"assets:read")
    assets,_=tenant_scope(principal)
    by_fingerprint={
        asset.fingerprint:asset
        for asset in assets
        if getattr(asset,"fingerprint",None)
    }
    events=recent_change_events(
        principal.tenant_id,
        hours=hours,
        limit=limit,
    )
    scoped_events=[]
    for event in events:
        asset=by_fingerprint.get(event.get("fingerprint"))
        if asset is None:
            continue
        event["asset_id"]=asset.id
        event["asset"]=asset.value
        event["type"]=asset.type.value
        scoped_events.append(event)
    return {
        "hours":max(1,min(int(hours),24*90)),
        "count":len(scoped_events),
        "items":scoped_events,
    }


class RemediationSimulationRequest(BaseModel):
    path:list[str]=Field(default_factory=list)
    finding_node_ids:list[str]=Field(default_factory=list)


@router.post("/api/v1/graph/simulate")
def graph_simulate(payload: RemediationSimulationRequest, request: Request):
    principal=require(request,"assets:read")
    assets,findings=tenant_scope(principal)
    graph=build_risk_graph(
        f"tenant:{principal.tenant_id}",
        assets,
        [],
        source_assets=assets,
        findings=findings,
    )
    nodes={node["id"]:type("Node",(),node)() for node in graph["nodes"]}
    edges=[type("Edge",(),edge)() for edge in graph["edges"]]
    return simulate_remediation(
        nodes,
        edges,
        payload.path,
        payload.finding_node_ids,
    )


@router.post("/api/v1/graph/attack-path/explain")
def explain_attack_path_api(payload: dict, request: Request):
    principal=require(request,"assets:read")
    path=payload.get("path") or []
    if not path or len(path)>30:
        raise HTTPException(status_code=400,detail="Invalid attack path")
    assets,findings=tenant_scope(principal)
    graph=build_risk_graph(
        f"tenant:{principal.tenant_id}",
        assets,
        [],
        source_assets=assets,
        findings=findings,
    )
    graph_nodes={node["id"]:node for node in graph["nodes"]}
    selected=[graph_nodes[node] for node in path if node in graph_nodes]
    evidence={
        "nodes":selected,
        "paths":[
            item
            for item in graph.get("top_risk_paths",[])
            if any(node in path for node in item.get("nodes",[]))
        ],
    }
    result=explain_attack_path(path,evidence)
    if not result:
        return {
            "ai":{
                "enabled":local_ai_enabled(),
                "provider":"ollama-local",
                "grounded":False,
            },
            "summary":"Local AI unavailable.",
            "facts":[],
            "inference":[],
            "unknowns":["AI unavailable; use graph evidence directly."],
            "validation":[],
            "confidence":0,
        }
    result["ai"]={
        "enabled":True,
        "provider":"ollama-local",
        "model":OLLAMA_MODEL,
        "grounded":True,
    }
    return result


@router.get("/api/v1/risk/remediation-options")
def risk_remediation_options(request: Request):
    principal=require(request,"assets:read")
    assets,findings=tenant_scope(principal)
    graph=build_risk_graph(
        f"tenant:{principal.tenant_id}",
        assets,
        [],
        source_assets=assets,
        findings=findings,
    )
    nodes={node["id"]:type("Node",(),node)() for node in graph["nodes"]}
    edges=[type("Edge",(),edge)() for edge in graph["edges"]]
    options=remediation_options(
        nodes,
        edges,
        graph.get("top_risk_paths",[]),
    )
    return {
        "summary":{
            "options":len(options),
            "total_risk_reduction":sum(
                item["risk_reduction"] for item in options
            ),
        },
        "options":options,
    }


@router.get("/api/v1/risk/attack-paths")
def risk_attack_paths(request: Request):
    principal=require(request,"assets:read")
    assets,findings=tenant_scope(principal)
    graph=build_risk_graph(
        f"tenant:{principal.tenant_id}",
        assets,
        [],
        source_assets=assets,
        findings=findings,
    )
    paths=graph.get("top_risk_paths",[])
    for path in paths:
        path["risk_model"]="contextual-residual"
        path["decision_factors"]={
            "highest_node_risk":max(
                (
                    node.get("risk_score",0)
                    for node in graph["nodes"]
                    if node["id"] in path.get("nodes",[])
                ),
                default=0,
            ),
            "weakest_link_confidence":path.get(
                "explanation",
                {},
            ).get("weakest_link",{}).get("confidence",0),
            "choke_points":len(path.get("choke_points",[])),
            "control_unknowns":path.get(
                "control_summary",
                {},
            ).get("unknown",0),
        }
    return {"summary":graph["risk_summary"],"paths":paths}


@router.get("/api/v1/graph/control-coverage")
def graph_control_coverage(request: Request):
    principal=require(request,"assets:read")
    assets,findings=tenant_scope(principal)
    graph=build_risk_graph(
        f"tenant:{principal.tenant_id}",
        assets,
        [],
        source_assets=assets,
        findings=findings,
    )
    covered=[
        node
        for node in graph["nodes"]
        if node.get("control_coverage")=="covered"
    ]
    unknown=[
        node
        for node in graph["nodes"]
        if node.get("control_coverage")=="unknown"
        and node.get("kind") not in {
            "internet",
            "finding",
            "threat",
            "certificate",
            "ip",
        }
    ]
    controls={}
    for node in covered:
        for control in node.get("security_controls",[]):
            controls.setdefault(
                control["type"],
                {"count":0,"providers":set()},
            )
            controls[control["type"]]["count"]+=1
            controls[control["type"]]["providers"].add(control["provider"])
    return {
        "coverage":{
            "covered_assets":len(covered),
            "unknown_assets":len(unknown),
            "coverage_percent":(
                round(len(covered)/(len(covered)+len(unknown))*100)
                if covered or unknown else 0
            ),
        },
        "controls":[
            {
                "type":key,
                "count":value["count"],
                "providers":sorted(value["providers"]),
            }
            for key,value in controls.items()
        ],
        "choke_points":sorted(
            [
                {
                    "node_id":node["id"],
                    "label":node["label"],
                    "score":node.get("choke_point_score",0),
                }
                for node in graph["nodes"]
                if node.get("choke_point_score",0)>0
            ],
            key=lambda item:item["score"],
            reverse=True,
        )[:10],
    }


@router.get("/api/v1/graph")
def graph(request: Request):
    principal=require(request,"assets:read")
    assets,findings=tenant_scope(principal)
    return build_risk_graph(
        "External Surface",
        assets,
        [],
        source_assets=assets,
        findings=findings,
    )


class AssessmentRequest(BaseModel):
    target:str=Field(min_length=1,max_length=2048)
    authorization_ref:str=Field(min_length=1,max_length=200)
    profile:str=Field(
        default="rapid",
        pattern="^(surface|rapid|network|balanced)$",
    )


def _materialize_assessment_result(principal, result: dict) -> dict:
    now=datetime.now(timezone.utc).isoformat()
    created_assets=0
    created_findings=0
    created_ctem=0
    regressions_reopened=0
    ctem_regressions_reopened=0
    skipped_out_of_scope=0

    scoped_assets,_=tenant_scope(principal)
    by_value={asset.value.lower():asset for asset in scoped_assets}

    for row in result.get("findings",[]):
        value=str(row.get("asset") or "").strip()
        if not value:
            continue
        if not asset_in_scope(principal,value):
            skipped_out_of_scope+=1
            continue

        evidence=row.get("evidence") or {}
        validation_required=(
            bool(evidence.get("validation_required"))
            if isinstance(evidence,dict)
            else False
        )
        if validation_required or str(row.get("category") or "")=="candidate_discovery":
            continue

        confidence=max(0,min(100,int(row.get("confidence",50) or 50)))
        if "://" in value:
            kind=AssetType.APPLICATION
        elif value.count(":")==1 and value.rsplit(":",1)[1].isdigit():
            kind=AssetType.SERVICE
        else:
            kind=AssetType.SUBDOMAIN if value.count(".")>=2 else AssetType.DOMAIN
        canonical_value=normalize_asset_value(kind.value,value) or value.lower()
        asset=by_value.get(canonical_value)

        if asset is None:
            digest=sha256(
                f"{principal.tenant_id}|{kind.value}|{canonical_value}".encode()
            ).hexdigest()[:16]
            asset=Asset(
                tenant_id=principal.tenant_id,
                id=f"ast-{digest}",
                value=canonical_value,
                type=kind,
                status="observed",
                confidence=confidence,
                criticality=3,
                source="assessment-intelligence",
                tags=["assessment-observed"],
                first_seen=now,
                last_seen=now,
                fingerprint=f"fp-{digest}",
                evidence_count=1,
                sources=["assessment-intelligence"],
            )
            STORE_ASSETS.append(asset)
            by_value[canonical_value]=asset
            created_assets+=1
        else:
            asset.last_seen=now
            asset.confidence=max(asset.confidence,confidence)
            asset.evidence_count+=1
            if "assessment-intelligence" not in asset.sources:
                asset.sources.append("assessment-intelligence")

        try:
            severity=Severity(str(row.get("severity") or "info").lower())
        except ValueError:
            severity=Severity.INFO

        vuln_ctx=normalize_vulnerability_evidence(row)
        vulnerability_id=vuln_ctx["vulnerability_id"]
        cvss=vuln_ctx["cvss"]
        cpe=vuln_ctx["cpe"]
        title=str(row.get("title") or "Exposure evidence")
        finding_key=vulnerability_identity_key(row,canonical_value)
        finding_identity=(
            f"{principal.tenant_id}|{asset.id}|{repr(finding_key)}"
        )
        finding_digest=sha256(finding_identity.encode()).hexdigest()[:16]
        finding_id=f"fdg-{finding_digest}"
        finding=next(
            (
                item
                for item in STORE_FINDINGS
                if item.tenant_id==principal.tenant_id
                and item.id==finding_id
            ),
            None,
        )
        regression_reopened=False

        if finding is None:
            finding=Finding(
                tenant_id=principal.tenant_id,
                id=finding_id,
                asset_id=asset.id,
                title=title,
                severity=severity,
                confidence=confidence,
                status="open",
                evidence="Evidence confirmed by assessment intelligence.",
                remediation="Review the exposure and validate remediation.",
                vulnerability_id=vulnerability_id,
                cpe=cpe,
                cvss=cvss,
                detected_at=now,
                source_refs=vuln_ctx["references"],
                independent_source_count=vuln_ctx["independent_source_count"],
                independently_corroborated=vuln_ctx[
                    "independently_corroborated"
                ],
                false_positive_confidence=vuln_ctx[
                    "false_positive_confidence"
                ],
                validation_state=vuln_ctx["validation_state"],
                evidence_quality=vuln_ctx["evidence_quality"],
                affected_component=vuln_ctx["affected_component"],
                affected_components=(
                    [vuln_ctx["affected_component"]]
                    if vuln_ctx["affected_component"]
                    else []
                ),
            )
            if finding.vulnerability_id:
                finding=enrich_finding(finding)
            STORE_FINDINGS.append(finding)
            created_findings+=1
        else:
            if finding.status in {
                "resolved",
                "verified",
                "closed",
                "remediated",
            }:
                finding.status="open"
                finding.detected_at=now
                finding.evidence=(
                    "Exposure re-observed after remediation; "
                    "regression requires retest."
                )
                regressions_reopened+=1
                regression_reopened=True
            finding.confidence=max(finding.confidence,confidence)
            severity_rank={
                Severity.INFO:0,
                Severity.LOW:1,
                Severity.MEDIUM:2,
                Severity.HIGH:3,
                Severity.CRITICAL:4,
            }
            if severity_rank.get(severity,0)>severity_rank.get(
                finding.severity,
                0,
            ):
                finding.severity=severity
            if vulnerability_id and not finding.vulnerability_id:
                finding.vulnerability_id=vulnerability_id
            if cpe and not finding.cpe:
                finding.cpe=cpe
            if cvss is not None and finding.cvss is None:
                finding.cvss=cvss
            finding.false_positive_confidence=min(
                finding.false_positive_confidence or 100,
                vuln_ctx["false_positive_confidence"],
            )
            if vuln_ctx["evidence_quality"]>=finding.evidence_quality:
                finding.validation_state=vuln_ctx["validation_state"]
                finding.evidence_quality=vuln_ctx["evidence_quality"]
            if vuln_ctx["references"]:
                finding.source_refs=sorted(
                    set(finding.source_refs+vuln_ctx["references"])
                )[:20]
            finding.independent_source_count=max(
                finding.independent_source_count,
                vuln_ctx["independent_source_count"],
            )
            finding.independently_corroborated=(
                finding.independently_corroborated
                or vuln_ctx["independently_corroborated"]
                or finding.independent_source_count>=2
            )
            if vuln_ctx["affected_component"]:
                finding.affected_component=vuln_ctx["affected_component"]
                if (
                    vuln_ctx["affected_component"]
                    not in finding.affected_components
                ):
                    finding.affected_components.append(
                        vuln_ctx["affected_component"]
                    )
                finding.affected_components=finding.affected_components[:50]
            if finding.vulnerability_id:
                enriched=enrich_finding(finding)
                finding.cvss=enriched.cvss
                finding.epss=enriched.epss
                finding.kev=enriched.kev
                finding.cpe=enriched.cpe
                finding.published_at=enriched.published_at

        ctem_item_id=f"assessment:{principal.tenant_id}:{finding.id}"
        if regression_reopened:
            regression_refs=list(finding.source_refs) or [
                f"assessment:{result.get('assessment_id') or finding.id}"
            ]
            try:
                reopened=reopen_ctem_item(
                    ctem_item_id,
                    principal.tenant_id,
                    regression_refs,
                    notes=(
                        "assessment evidence re-observed after "
                        "verified remediation"
                    ),
                )
                if reopened.get("reopened"):
                    ctem_regressions_reopened+=1
            except KeyError:
                pass
            audit(
                principal,
                "reopen",
                "finding_regression",
                finding.id,
                {
                    "asset_id":asset.id,
                    "evidence_refs":regression_refs[:20],
                },
            )

        priority_data=assess_ctem_priority(finding,asset)
        priority=int(priority_data["priority"])
        if priority>=45:
            upsert_ctem_item(
                {
                    "item_id":ctem_item_id,
                    "asset_id":asset.id,
                    "finding_id":finding.id,
                    "priority":priority,
                    "action":priority_data["action"],
                    "title":"Exposure requiring remediation attention",
                    "drivers":priority_data["drivers"],
                    "evidence_refs":list(finding.source_refs),
                },
                principal.tenant_id,
            )
            created_ctem+=1

    persist_state(STORE_ASSETS,STORE_FINDINGS)
    return {
        "assets_created":created_assets,
        "findings_created":created_findings,
        "ctem_items":created_ctem,
        "regressions_reopened":regressions_reopened,
        "ctem_regressions_reopened":ctem_regressions_reopened,
        "skipped_out_of_scope":skipped_out_of_scope,
    }


@router.get("/api/v1/exposure/assessment/capabilities")
def exposure_assessment_capabilities(
    request: Request,
    target: str|None=None,
):
    principal=require(request,"assets:read")
    if target and not asset_in_scope(principal,target):
        raise HTTPException(status_code=403,detail="target outside assigned scope")
    return {
        "bundle":os.getenv("BSA_ENGINE_BUNDLE","core"),
        "capabilities":registry.capability_health(target),
    }


@router.post("/api/v1/exposure/assessment")
def exposure_assessment(payload: AssessmentRequest, request: Request):
    principal=require(request,"discovery:run")
    if not asset_in_scope(principal,payload.target):
        raise HTTPException(status_code=403,detail="target outside assigned scope")
    authorization_ref=govern_active_scan(
        request,
        principal,
        payload.target,
        payload.authorization_ref,
    )
    if not rate_limit_action(
        "exposure-assessment",
        principal.user_id,
        limit=8,
        window_seconds=300,
    ):
        raise HTTPException(
            status_code=429,
            detail="assessment rate limit exceeded",
        )
    job=enqueue_assessment(
        principal,
        payload.target,
        payload.profile,
        authorization_ref or "development",
    )
    audit(
        principal,
        "queue",
        "exposure_assessment",
        payload.target,
        {
            "profile":payload.profile,
            "authorization_ref":authorization_ref or "development",
            "job_id":job["job_id"],
        },
    )
    return JSONResponse(
        status_code=202,
        content={
            "job_id":job["job_id"],
            "status":job["status"],
            "target":job["target"],
            "profile":job["profile"],
        },
    )


@router.post("/api/v1/exposure/assessment/jobs/{job_id}/cancel")
def exposure_assessment_job_cancel(job_id: str, request: Request):
    principal=require(request,"discovery:run")
    job=cancel_job(job_id,principal.tenant_id)
    if not job:
        raise HTTPException(
            status_code=404,
            detail="assessment job not found",
        )
    if job["status"]!="cancelled":
        raise HTTPException(
            status_code=409,
            detail="assessment job can no longer be cancelled",
        )
    audit(
        principal,
        "cancel",
        "exposure_assessment",
        job["target"],
        {"job_id":job_id},
    )
    return {"job_id":job_id,"status":"cancelled"}


@router.get("/api/v1/exposure/assessment/jobs/{job_id}")
def exposure_assessment_job(job_id: str, request: Request):
    principal=require(request,"discovery:run")
    job=get_job(job_id,principal.tenant_id)
    if not job:
        raise HTTPException(
            status_code=404,
            detail="assessment job not found",
        )
    result=job.get("result")
    job_principal=None
    if job["status"]=="succeeded" and result is not None:
        job_principal=Principal(
            user_id=job["user_id"],
            tenant_id=job["tenant_id"],
            email=job["email"],
            role=job["role"],
            name=job["name"],
        )
    if (
        job["status"]=="succeeded"
        and result is not None
        and not job.get("materialized")
    ):
        if claim_materialization(job_id,principal.tenant_id):
            try:
                result["materialization"]=_materialize_assessment_result(
                    job_principal,
                    result,
                )
                finish_materialization(job_id,principal.tenant_id,True)
                audit(
                    job_principal,
                    "complete",
                    "exposure_assessment",
                    job["target"],
                    {
                        "profile":job["profile"],
                        "authorization_ref":job["authorization_ref"],
                        "job_id":job_id,
                        "finding_count":result.get("finding_count",0),
                        "partial_coverage":result.get(
                            "partial_coverage",
                            False,
                        ),
                    },
                )
                job["materialized"]=True
            except Exception:
                finish_materialization(
                    job_id,
                    principal.tenant_id,
                    False,
                )
                raise
        else:
            job=get_job(job_id,principal.tenant_id) or job
    ctem_retest_result=None
    if (
        job["status"]=="succeeded"
        and result is not None
        and job_principal is not None
        and job.get("materialized")
    ):
        ctem_retest_result=reconcile_ctem_retest_job(
            job_principal,
            job,
            result,
            audit,
        )
    return {
        "job_id":job["job_id"],
        "status":job["status"],
        "target":job["target"],
        "profile":job["profile"],
        "created_at":job["created_at"],
        "started_at":job.get("started_at"),
        "completed_at":job.get("completed_at"),
        "error":job.get("error"),
        "materialized":bool(job.get("materialized")),
        "ctem_retest":ctem_retest_result,
        "result":result,
    }
