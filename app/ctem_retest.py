"""Conservative CTEM retest reconciliation.

A completed assessment only closes CTEM work when coverage is complete enough
and no matching material exposure remains. Partial coverage is never treated
as proof of remediation.
"""
from __future__ import annotations

from hashlib import sha256


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


def _finding_matches_item(item: dict, finding: dict, target: str) -> bool:
    finding_id=str(item.get("finding_id") or "").strip().lower()
    if finding_id:
        identities=_identity_values(finding)
        return finding_id in identities or any(finding_id in x or x in finding_id for x in identities if x)

    asset=str(finding.get("asset") or (finding.get("evidence") or {}).get("asset") or "").strip().lower()
    target=str(target or "").strip().lower()
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
