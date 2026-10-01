"""Risk correlation layer for ASM findings.

Converts multiple weak signals into contextual exposure priority.
"""


def calculate_exposure_risk(asset, findings=None, context=None):
    findings = findings or []
    context = context or {}

    score = 0
    score += min(len(findings) * 8, 40)

    if context.get("internet_exposed"):
        score += 20
    if context.get("critical_asset"):
        score += 20
    if context.get("technology_outdated"):
        score += 10
    if context.get("recent_change"):
        score += 10

    return {
        "asset": asset,
        "risk_score": min(score, 100),
        "signals": {
            "findings": len(findings),
            "internet_exposed": bool(context.get("internet_exposed")),
            "critical_asset": bool(context.get("critical_asset")),
        },
    }
