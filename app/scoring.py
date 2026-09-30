from dataclasses import dataclass
from .models import Asset, Finding, Severity
from .intelligence import finding_context_score

SEVERITY_WEIGHT = {
    Severity.INFO: 1,
    Severity.LOW: 3,
    Severity.MEDIUM: 7,
    Severity.HIGH: 14,
    Severity.CRITICAL: 24,
}


@dataclass(frozen=True)
class ScoreResult:
    score: int
    penalty: int
    rationale: list[dict]


def exposure_score(findings: list[Finding], assets: list[Asset] | None = None) -> ScoreResult:
    """Return a 0–100 posture score with a transparent, contextual penalty breakdown."""
    rationale: list[dict] = []
    penalty = 0
    asset_map = {a.id: a for a in (assets or [])}

    for finding in findings:
        if finding.status != "open":
            continue

        asset = asset_map.get(finding.asset_id)
        if asset:
            contextual = finding_context_score(finding, asset)
            item_penalty = max(1, round(contextual / 5))
        else:
            base = SEVERITY_WEIGHT[finding.severity]
            confidence_factor = max(0.25, finding.confidence / 100)
            item_penalty = max(1, round(base * confidence_factor))

        penalty += item_penalty
        rationale.append({
            "finding_id": finding.id,
            "severity": finding.severity.value,
            "confidence": finding.confidence,
            "asset_id": finding.asset_id,
            "penalty": item_penalty,
        })

    return ScoreResult(
        score=max(0, 100 - min(100, penalty)),
        penalty=min(100, penalty),
        rationale=rationale,
    )
