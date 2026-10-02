from dataclasses import asdict

from ...risk_engine import assess_risk, normalize_cpe, cpe_product
from ...risk_policy import calculate_risk
from ...tenant_risk_policy import policy_for, serialize_policy


def build_risk_register(tenant_id: str, assets: list, findings: list) -> dict:
    asset_map={a.id:a for a in assets}
    policy=policy_for(tenant_id)
    items=[]
    for finding in findings:
        if finding.status!="open":
            continue
        asset=asset_map.get(finding.asset_id)
        risk=calculate_risk(finding,asset,policy)
        items.append({
            "finding_id":finding.id,
            "asset_id":finding.asset_id,
            "asset":asset.value if asset else None,
            "title":finding.title,
            "risk":risk,
        })
    items.sort(
        key=lambda item:(item["risk"]["residual_score"],item["risk"]["score"]),
        reverse=True,
    )
    return {
        "policy":serialize_policy(policy),
        "summary":{
            "findings":len(items),
            "critical":sum(x["risk"]["band"]=="critical" for x in items),
            "high":sum(x["risk"]["band"]=="high" for x in items),
            "medium":sum(x["risk"]["band"]=="medium" for x in items),
            "low":sum(x["risk"]["band"]=="low" for x in items),
            "validation_required":sum(x["risk"]["validation_required"] for x in items),
            "average_inherent":round(sum(x["risk"]["inherent_score"] for x in items)/len(items)) if items else 0,
            "average_residual":round(sum(x["risk"]["residual_score"] for x in items)/len(items)) if items else 0,
        },
        "items":items,
    }


def build_risk_overview(assets: list, findings: list) -> dict:
    asset_map={a.id:a for a in assets}
    items=[]
    for finding in findings:
        if finding.status!="open":
            continue
        asset=asset_map.get(finding.asset_id)
        risk=assess_risk(finding,asset)
        product,version=cpe_product(finding.cpe)
        items.append({
            "finding_id":finding.id,
            "asset_id":finding.asset_id,
            "asset":asset.value if asset else None,
            "vulnerability_id":finding.vulnerability_id,
            "cpe":normalize_cpe(finding.cpe),
            "cpe_product":product,
            "cpe_version":version,
            "risk":asdict(risk),
        })
    items.sort(key=lambda item:item["risk"]["score"],reverse=True)
    return {
        "summary":{
            "findings":len(items),
            "critical":sum(x["risk"]["band"]=="critical" for x in items),
            "high":sum(x["risk"]["band"]=="high" for x in items),
            "medium":sum(x["risk"]["band"]=="medium" for x in items),
            "low":sum(x["risk"]["band"]=="low" for x in items),
            "average":round(sum(x["risk"]["score"] for x in items)/len(items)) if items else 0,
        },
        "items":items,
    }
