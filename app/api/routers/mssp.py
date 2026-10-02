from datetime import datetime, timezone

from fastapi import APIRouter, HTTPException, Request

from ...auth import _db
from ...ctem_store import history, list_plans
from ...exposure import exposure_breakdown
from ...store import ASSETS as STORE_ASSETS, FINDINGS as STORE_FINDINGS
from ...tenant_sla_policy import serialize_sla_policy, sla_policy_for, sla_threshold_hours
from ..dependencies import require


router=APIRouter()


@router.get("/api/v1/mssp/command-center/trend")
def mssp_command_center_trend(request: Request):
    principal=require(request,"assets:read")
    if principal.role not in {"superadmin","admin","manager"}:
        raise HTTPException(status_code=403,detail="MSSP role required")
    conn=_db()
    try:
        if principal.role=="superadmin":
            tenants=[dict(row) for row in conn.execute(
                "SELECT id,name FROM tenants ORDER BY name"
            ).fetchall()]
        else:
            tenants=[dict(row) for row in conn.execute(
                "SELECT id,name FROM tenants WHERE id=?",
                (principal.tenant_id,),
            ).fetchall()]
    finally:
        conn.close()
    out=[]
    for tenant in tenants:
        events=history(tenant["id"],90)
        out.append({
            "tenant_id":tenant["id"],
            "tenant":tenant["name"],
            "events":events,
        })
    return {"days":90,"tenants":out}


@router.get("/api/v1/mssp/command-center")
def mssp_command_center(request: Request):
    principal=require(request,"assets:read")
    if principal.role not in {"superadmin","admin","manager"}:
        raise HTTPException(status_code=403,detail="MSSP role required")
    conn=_db()
    try:
        if principal.role=="superadmin":
            tenants=[dict(row) for row in conn.execute(
                "SELECT id,name,active FROM tenants ORDER BY name"
            ).fetchall()]
        else:
            tenants=[dict(row) for row in conn.execute(
                "SELECT id,name,active FROM tenants WHERE id=?",
                (principal.tenant_id,),
            ).fetchall()]
    finally:
        conn.close()

    rows=[]
    for tenant in tenants:
        assets=[
            asset for asset in STORE_ASSETS
            if getattr(asset,"tenant_id","tenant-demo")==tenant["id"]
        ]
        findings=[
            finding for finding in STORE_FINDINGS
            if getattr(finding,"tenant_id","tenant-demo")==tenant["id"]
            and finding.status=="open"
        ]
        scores=[exposure_breakdown(asset,findings).score for asset in assets]
        plans=list_plans(tenant["id"])
        overdue=sum(
            1 for plan in plans
            if plan.get("status") in {"planned","approved","in_progress"}
            and plan.get("effort")=="alto"
        )
        risk=round(sum(scores)/len(scores)) if scores else 0
        critical=sum(
            1 for finding in findings
            if getattr(finding,"severity",None)
            and str(finding.severity).lower().endswith("critical")
        )
        approved=sum(1 for plan in plans if plan.get("status")=="approved")
        in_progress=sum(1 for plan in plans if plan.get("status")=="in_progress")
        remediated=sum(
            1 for plan in plans
            if plan.get("status") in {"remediated","retest","closed"}
        )
        now_ts=datetime.now(timezone.utc)
        active_plans=[
            plan for plan in plans
            if plan.get("status") not in {"closed","remediated"}
        ]
        aging_days=[]
        for plan in active_plans:
            try:
                created=datetime.fromisoformat(
                    plan.get("created_at","").replace("Z","+00:00")
                )
                aging_days.append(max(0,(now_ts-created).days))
            except Exception:
                pass

        sla_policy=sla_policy_for(tenant["id"])
        sla_breaches=0
        for plan in active_plans:
            try:
                created=datetime.fromisoformat(
                    plan.get("created_at","").replace("Z","+00:00")
                )
                age_hours=max(0,(now_ts-created).total_seconds()/3600)
            except Exception:
                age_hours=0
            priority=int(
                plan.get(
                    "priority",
                    plan.get("risk_score",plan.get("residual_score",0)),
                )
                or 0
            )
            if age_hours>sla_threshold_hours(priority,sla_policy):
                sla_breaches+=1

        sla_compliance=(
            round((len(active_plans)-sla_breaches)/len(active_plans)*100)
            if active_plans else 100
        )
        residual=(
            round(
                sum(plan.get("residual_score",0) for plan in active_plans)
                / len(active_plans)
            )
            if active_plans else 0
        )
        risk_reduction=sum(max(0,plan.get("risk_reduction",0)) for plan in plans)
        rows.append({
            "tenant_id":tenant["id"],
            "tenant":tenant["name"],
            "active":tenant["active"],
            "risk":risk,
            "assets":len(assets),
            "open_findings":len(findings),
            "critical_findings":critical,
            "ctem":len(plans),
            "approved":approved,
            "in_progress":in_progress,
            "remediated":remediated,
            "overdue":overdue,
            "ctem_aging":len(active_plans),
            "avg_ctem_age_days":(
                round(sum(aging_days)/len(aging_days)) if aging_days else 0
            ),
            "sla_compliance":sla_compliance,
            "sla_breaches":sla_breaches,
            "sla_policy":serialize_sla_policy(sla_policy),
            "risk_residual":residual,
            "risk_reduction_30d":risk_reduction,
        })

    rows.sort(key=lambda item:item["risk"],reverse=True)
    return {
        "tenants":rows,
        "summary":{
            "tenants":len(rows),
            "critical_tenants":sum(item["risk"]>=80 for item in rows),
            "open_findings":sum(item["open_findings"] for item in rows),
            "ctem_plans":sum(item["ctem"] for item in rows),
            "overdue":sum(item["overdue"] for item in rows),
            "remediated":sum(item["remediated"] for item in rows),
            "in_progress":sum(item["in_progress"] for item in rows),
            "sla_compliance":(
                round(sum(item["sla_compliance"] for item in rows)/len(rows))
                if rows else 100
            ),
            "sla_breaches":sum(item["sla_breaches"] for item in rows),
            "risk_residual":(
                round(sum(item["risk_residual"] for item in rows)) if rows else 0
            ),
            "risk_reduction_30d":sum(
                item["risk_reduction_30d"] for item in rows
            ),
        },
    }
