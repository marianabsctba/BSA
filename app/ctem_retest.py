"""Conservative CTEM retest reconciliation.

A completed assessment only closes CTEM work when coverage is complete enough
and no matching material exposure remains. Partial coverage is never treated
as proof of remediation.
"""
from __future__ import annotations

from hashlib import sha256
from urllib.parse import urlparse


MATERIAL_SEVERITIES={"critical","high","medium","low"}


def _identity_values(finding: dict) -> set[str]:
    values=set()
    for key in ("id","finding_id","vulnerability_id","template_id","cve","title"):
        value=finding.get(key)
        if value:
            values.add(str(value).strip().lower())
    evidence=finding.get("evidence") or {}
    for key in ("id","finding_id","vulnerability_id","template_id","cve","title"):
        value=evidence.get(key)
        if value:
            values.add(str(value).strip().lower())
    return values


def _hostish(value: str) -> str:
    raw=str(value or "").strip().lower()
    if not raw:
        return ""
    parsed=urlparse(raw if "://" in raw else "//"+raw)
    host=parsed.hostname or raw.split("/",1)[0].split(":",1)[0]
    return host.rstrip(".")


def _finding_matches_item(item: dict, finding: dict, target: str) -> bool:
    finding_id=str(item.get("finding_id") or "").strip().lower()
    if finding_id:
        identities=_identity_values(finding)
        return finding_id in identities or any(finding_id in x or x in finding_id for x in identities if x)

    evidence=finding.get("evidence") or {}
    asset=_hostish(
        finding.get("asset")
        or evidence.get("asset")
        or evidence.get("url")
        or evidence.get("matched_at")
        or ""
    )
    target=_hostish(target)
    if asset and target:
        return asset==target or asset.endswith("."+target) or target.endswith("."+asset)

    title=str(finding.get("title") or "").strip().lower()
    item_title=str(item.get("title") or "").strip().lower()
    if item_title and title and item_title!="surface change requiring ctem attention":
        item_tokens={x for x in item_title.split() if len(x)>=5}
        return bool(item_tokens and any(x in title for x in item_tokens))
    return False


def _finding_ref(finding: dict, job_id: str, index: int) -> list[str]:
    evidence=finding.get("evidence") or {}
    refs=evidence.get("references") or evidence.get("reference") or []
    if isinstance(refs,str):
        refs=[refs]
    out=[str(x) for x in refs if x]
    if out:
        return out[:20]
    raw="|".join([
        str(job_id),
        str(index),
        str(finding.get("asset") or ""),
        str(finding.get("title") or ""),
        str(finding.get("severity") or ""),
    ])
    return ["assessment:"+sha256(raw.encode("utf-8")).hexdigest()[:24]]


def classify_ctem_retest(item: dict, result: dict, *, job_id: str, target: str) -> dict:
    """Return passed/failed/inconclusive with explicit evidence references."""
    coverage=result.get("coverage") or {}
    coverage_percent=int(coverage.get("capability_coverage_percent") or 0)
    partial=bool(result.get("partial_coverage"))
    complete=(not partial) and coverage_percent>=100

    findings=list(result.get("findings") or [])
    matching=[]
    refs=[]
    for index,finding in enumerate(findings):
        severity=str(finding.get("severity") or "").lower()
        if severity not in MATERIAL_SEVERITIES:
            continue
        if _finding_matches_item(item,finding,target):
            matching.append(finding)
            refs.extend(_finding_ref(finding,job_id,index))

    coverage_ref=f"assessment-job:{job_id}:coverage:{coverage_percent}"
    if matching:
        return {
            "outcome":"failed",
            "reason":"matching material exposure remains after retest",
            "matching_findings":len(matching),
            "coverage_percent":coverage_percent,
            "partial_coverage":partial,
            "evidence_refs":sorted(set(refs+[coverage_ref])),
        }
    if complete:
        return {
            "outcome":"passed",
            "reason":"complete retest coverage found no matching material exposure",
            "matching_findings":0,
            "coverage_percent":coverage_percent,
            "partial_coverage":False,
            "evidence_refs":[coverage_ref],
        }
    return {
        "outcome":"inconclusive",
        "reason":"retest coverage is partial or insufficient for closure",
        "matching_findings":0,
        "coverage_percent":coverage_percent,
        "partial_coverage":partial,
        "evidence_refs":[coverage_ref],
    }


def reconcile_ctem_retest_job(principal, job: dict, result: dict, audit_callback=None) -> dict | None:
    """Idempotently reconcile one completed assessment back into its CTEM item."""
    from .history import (
        ctem_retest_for_job,
        claim_ctem_retest_reconciliation,
        release_ctem_retest_reconciliation,
        complete_ctem_retest,
        list_ctem_items,
        record_ctem_transition,
        verify_ctem_item,
    )

    tenant_id=str(getattr(principal,"tenant_id","") or "")
    link=ctem_retest_for_job(job["job_id"],tenant_id)
    if not link:
        return None
    if link.get("outcome"):
        return link
    if not claim_ctem_retest_reconciliation(job["job_id"],tenant_id):
        return ctem_retest_for_job(job["job_id"],tenant_id)

    item=next(
        (x for x in list_ctem_items(tenant_id) if x.get("item_id")==link.get("item_id")),
        None,
    )
    if item is None:
        refs=[f"assessment-job:{job['job_id']}:ctem-item-missing"]
        return complete_ctem_retest(job["job_id"],tenant_id,"inconclusive",refs)

    try:
        decision=classify_ctem_retest(
            item,result,job_id=job["job_id"],target=job.get("target",""),
        )
        outcome=decision["outcome"]
    refs=list(decision.get("evidence_refs") or [])
    previous_state=str(item.get("state") or "")

    if outcome in {"passed","failed"}:
        try:
            verified=verify_ctem_item(
                item["item_id"],
                tenant_id,
                outcome,
                refs,
                f"Automated authorized retest {job['job_id']}: {decision.get('reason','')}",
            )
            next_state=str(verified.get("state") or previous_state)
            record_ctem_transition(
                item["item_id"],
                tenant_id,
                "retest_verified" if outcome=="passed" else "retest_failed",
                previous_state,
                next_state,
                actor_id=str(getattr(principal,"user_id","") or ""),
                request_id=str(job["job_id"]),
            )
        except ValueError:
            outcome="inconclusive"
            decision["reason"]="CTEM state is not eligible for automatic verification"
            refs=sorted(set(refs+[f"assessment-job:{job['job_id']}:state:{previous_state}"]))
            record_ctem_transition(
                item["item_id"],
                tenant_id,
                "retest_inconclusive",
                previous_state,
                previous_state,
                actor_id=str(getattr(principal,"user_id","") or ""),
                request_id=str(job["job_id"]),
            )
    else:
        record_ctem_transition(
            item["item_id"],
            tenant_id,
            "retest_inconclusive",
            previous_state,
            previous_state,
            actor_id=str(getattr(principal,"user_id","") or ""),
            request_id=str(job["job_id"]),
        )

    complete_ctem_retest(job["job_id"],tenant_id,outcome,refs)
    payload={
        "job_id":job["job_id"],
        "outcome":outcome,
        "coverage_percent":decision.get("coverage_percent",0),
        "matching_findings":decision.get("matching_findings",0),
        "partial_coverage":decision.get("partial_coverage",False),
    }
    if audit_callback is not None:
        audit_callback(principal,"ctem_retest_reconcile","ctem",item["item_id"],payload)
        return {**decision,"outcome":outcome,"evidence_refs":refs}
    except Exception:
        release_ctem_retest_reconciliation(job["job_id"],tenant_id)
        raise
