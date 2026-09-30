from dataclasses import dataclass
from .models import Finding, Severity

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


def exposure_score(findings: list[Finding]) -> ScoreResult:
    """Return a 0–100 posture score with a transparent penalty breakdown."""
    rationale: list[dict] = []
    penalty = 0

    for finding in findings:
        if finding.status != "open":
            continue

        base = SEVERITY_WEIGHT[finding.severity]
        confidence_factor = max(0.25, finding.confidence / 100)
        item_penalty = max(1, round(base * confidence_factor))
        penalty += item_penalty
        rationale.append(
            {
                "finding_id": finding.id,
                "severity": finding.severity.value,
                "confidence": finding.confidence,
                "penalty": item_penalty,
            }
        )

    return ScoreResult(
        score=max(0, 100 - min(100, penalty)),
        penalty=min(100, penalty),
        rationale=rationale,
    )
