from fastapi import APIRouter, Request

from ...engine_health import public_engine_health
from ...graph import RELATIONSHIPS
from ...history import (
    ctem_operational_summary,
    ctem_queue_view,
    ctem_verification_history,
    list_ctem_items,
    recent_change_events,
)
from ...intelligence import ownership_confidence
from ...job_queue import queue_metrics
from ...models import Dashboard
from ...scoring import exposure_score
from ...scope import asset_in_scope
from ...tenant_sla_policy import sla_policy_for
from ...vulnerability_intelligence import vulnerability_intelligence
from ..dependencies import require
from ..tenant_scope import tenant_scope


router=APIRouter()



@router.get("/api/v1/reports/summary")
def report_summary(request: Request):
    principal=require(request,"assets:read")
    assets,findings=tenant_scope(principal)
    open_findings=[finding for finding in findings if finding.status=="open"]
    ownership=[ownership_confidence(asset) for asset in assets]
    score=exposure_score(findings,assets)

    def state(asset):
        if asset.status in {"approved","owned","managed"}:
            return "approved"
        if asset.status in {"dependency","third_party"}:
            return "dependency"
        if asset.status in {"monitor","monitor_only"}:
            return "monitor_only"
        if asset.status in {"requires_investigation","investigate"}:
            return "requires_investigation"
        return "candidate"

    exposure_rows=[
        {
            "id":asset.id,
            "value":asset.value,
            "type":asset.type.value,
            "state":state(asset),
            "confidence":asset.confidence,
            "evidence_count":asset.evidence_count,
        }
        for asset in assets[:40]
    ]

    asset_map={asset.id:asset for asset in assets}
    vulnerability_rows=[]
    for finding in open_findings:
        intel=vulnerability_intelligence(
            finding,
            asset_map.get(finding.asset_id),
        )
        vulnerability_rows.append({
            "id":finding.id,
            "vulnerability":finding.vulnerability_id or finding.title,
            "asset":(
                asset_map.get(finding.asset_id).value
                if asset_map.get(finding.asset_id)
                else None
            ),
            "priority":intel.priority_score,
            "exploitability":intel.exploitability,
            "impact":intel.business_impact,
            "confidence":intel.confidence,
            "band":intel.band,
            "data_quality_gap":bool(intel.data_quality),
        })
    vulnerability_rows.sort(key=lambda item:item["priority"],reverse=True)

    states=[state(asset) for asset in assets]
    engine_profiles=public_engine_health().get("profiles",{})
    ctem_items=list_ctem_items(principal.tenant_id)
    ctem_summary=ctem_operational_summary(
        ctem_items,
        sla_policy=sla_policy_for(principal.tenant_id),
    )
    ctem_queue=ctem_queue_view(ctem_items)
    queue_summary=queue_metrics(principal.tenant_id)

    return {
        "executive":{
            "total_assets":len(assets),
            "exposed_services":sum(
                1 for asset in assets if asset.type.value=="service"
            ),
            "open_findings":len(open_findings),
            "critical_findings":sum(
                1 for finding in open_findings
                if finding.severity.value=="critical"
            ),
            "exposure_score":score.score,
            "approved":sum(item=="approved" for item in states),
            "candidates":sum(item=="candidate" for item in states),
            "unowned":sum(1 for asset in assets if not asset.owner),
            "low_confidence":sum(
                1 for asset in assets if asset.confidence<70
            ),
            "confirmed_assets":sum(
                1 for item in ownership if item.state=="confirmed"
            ),
        },
        "exposure":{
            "summary":{
                "total_assets":len(assets),
                "exposed_assets":sum(
                    1
                    for asset in assets
                    if asset.type.value in {
                        "service",
                        "application",
                        "ip",
                        "domain",
                        "subdomain",
                    }
                ),
                "approved":sum(item=="approved" for item in states),
                "candidates":sum(item=="candidate" for item in states),
            },
            "items":exposure_rows,
        },
        "vulnerabilities":{
            "summary":{
                "findings":len(vulnerability_rows),
                "critical":sum(
                    item["band"]=="critical" for item in vulnerability_rows
                ),
                "high":sum(
                    item["band"]=="high" for item in vulnerability_rows
                ),
                "data_quality_gaps":sum(
                    item["data_quality_gap"] for item in vulnerability_rows
                ),
            },
            "items":vulnerability_rows[:40],
        },
        "operations":{
            "queue":queue_summary,
            "coverage":{
                "rapid":{
                    "state":engine_profiles.get("rapid",{}).get(
                        "state",
                        "unknown",
                    ),
                    "coverage_percent":engine_profiles.get("rapid",{}).get(
                        "coverage_percent",
                        0,
                    ),
                },
                "balanced":{
                    "state":engine_profiles.get("balanced",{}).get(
                        "state",
                        "unknown",
                    ),
                    "coverage_percent":engine_profiles.get("balanced",{}).get(
                        "coverage_percent",
                        0,
                    ),
                },
            },
            "ctem":{
                "active_items":ctem_summary.get("active_items",0),
                "overdue_items":ctem_summary.get("overdue_items",0),
                "oldest_active_age_hours":ctem_summary.get(
                    "oldest_active_age_hours",
                    0,
                ),
                "critical":ctem_queue.get("buckets",{}).get(
                    "critical",
                    {},
                ).get("count",0),
                "high":ctem_queue.get("buckets",{}).get(
                    "high",
                    {},
                ).get("count",0),
                "retest":sum(
                    1 for item in ctem_items if item.get("state")=="resolved"
                ),
                "regressions":sum(
                    1
                    for item in ctem_items
                    if item.get("state")=="in_progress"
                    and any(
                        verification.get("result")=="failed"
                        for verification in ctem_verification_history(
                            item.get("item_id"),
                            principal.tenant_id,
                        )
                    )
                ),
            },
        },
    }


@router.get("/api/v1/dashboard",response_model=Dashboard)
def dashboard(request: Request):
    principal=require(request,"assets:read")
    assets,findings=tenant_scope(principal)
    changes=recent_change_events(
        principal.tenant_id,
        hours=24,
        limit=1000,
    )
    ownership=[ownership_confidence(asset) for asset in assets]
    score=exposure_score(findings,assets)

    return Dashboard(
        total_assets=len(assets),
        exposed_services=sum(
            1 for asset in assets if asset.type.value=="service"
        ),
        open_findings=sum(
            1 for finding in findings if finding.status=="open"
        ),
        critical_findings=sum(
            1
            for finding in findings
            if finding.status=="open"
            and finding.severity.value=="critical"
        ),
        exposure_score=score.score,
        confirmed_assets=sum(
            1 for item in ownership if item.state=="confirmed"
        ),
        candidate_assets=sum(
            1 for item in ownership if item.state=="candidate"
        ),
        changes_24h=len(changes),
        attack_paths=len(RELATIONSHIPS),
    )
