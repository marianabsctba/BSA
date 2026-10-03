from __future__ import annotations

import json

from . import job_queue


def latest_assessment_quality(tenant_id: str) -> dict:
    """Summarize the latest tenant assessment without exposing backend identities."""
    conn=job_queue._db()
    try:
        row=conn.execute(
            """SELECT status,profile,result_json,error,created_at,started_at,completed_at
               FROM assessment_jobs
               WHERE tenant_id=? AND job_type='assessment'
               ORDER BY COALESCE(completed_at,started_at,created_at) DESC, created_at DESC
               LIMIT 1""",
            (tenant_id,),
        ).fetchone()
    finally:
        conn.close()

    if not row:
        return {
            "state":"never_run",
            "profile":None,
            "finding_count":None,
            "partial_coverage":None,
            "zero_findings_interpretable":False,
            "interpretation":"no assessment execution is available for this tenant",
            "completed_at":None,
            "coverage":{},
            "effectiveness":{},
        }

    status=str(row["status"] or "unknown")
    base={
        "profile":str(row["profile"] or "") or None,
        "completed_at":row["completed_at"],
        "coverage":{},
        "effectiveness":{},
    }
    if status!="succeeded":
        return {
            **base,
            "state":"failed" if status=="failed" else status,
            "finding_count":None,
            "partial_coverage":True,
            "zero_findings_interpretable":False,
            "interpretation":"assessment did not complete successfully",
        }

    try:
        result=json.loads(row["result_json"] or "{}")
    except (TypeError,json.JSONDecodeError):
        result={}
    coverage=result.get("coverage") if isinstance(result.get("coverage"),dict) else {}
    effectiveness=(
        coverage.get("effectiveness")
        if isinstance(coverage.get("effectiveness"),dict)
        else {}
    )
    finding_count=max(0,int(result.get("finding_count",0) or 0))
    partial=bool(result.get("partial_coverage",False))
    execution_success=int(effectiveness.get("execution_success_percent",0) or 0)
    exercised=int(effectiveness.get("exercised_capability_percent",0) or 0)
    complete=(not partial and execution_success==100 and exercised==100)

    if finding_count==0 and complete:
        interpretation="assessment completed with full exercised coverage and no findings"
    elif finding_count==0:
        interpretation="no findings were returned, but execution quality is incomplete"
    elif complete:
        interpretation="assessment completed with full exercised coverage"
    else:
        interpretation="findings are available, but execution quality is partial"

    return {
        **base,
        "state":"complete" if complete else "partial",
        "finding_count":finding_count,
        "partial_coverage":not complete,
        "zero_findings_interpretable":bool(finding_count==0 and complete),
        "interpretation":interpretation,
        "coverage":{
            "requested_capabilities":coverage.get("requested_capabilities",0),
            "operational_capabilities":coverage.get("operational_capabilities",0),
            "capability_coverage_percent":coverage.get("capability_coverage_percent",0),
            "budget_exhausted":bool(coverage.get("budget_exhausted",False)),
            "provider_calls":coverage.get("provider_calls",0),
        },
        "effectiveness":{
            "execution_success_percent":execution_success,
            "exercised_capability_percent":exercised,
            "productive_capability_percent":int(
                effectiveness.get("productive_capability_percent",0) or 0
            ),
            "evidenced_finding_percent":int(
                effectiveness.get("evidenced_finding_percent",0) or 0
            ),
            "high_confidence_finding_percent":int(
                effectiveness.get("high_confidence_finding_percent",0) or 0
            ),
            "confirmed_evidence_count":int(
                effectiveness.get("confirmed_evidence_count",0) or 0
            ),
            "independently_corroborated_count":int(
                effectiveness.get("independently_corroborated_count",0) or 0
            ),
            "successful_calls":int(effectiveness.get("successful_calls",0) or 0),
            "failed_calls":int(effectiveness.get("failed_calls",0) or 0),
        },
    }
