"""
Contextual Risk Engine

Internal risk calculation layer for Be Safe ASM.
The UI should consume intelligence results, not scanner details.
"""

from dataclasses import dataclass, field


@dataclass
class RiskContext:
    exposure_score: int = 0
    asset_criticality: int = 0
    vulnerability_score: int = 0
    threat_score: int = 0
    confidence_score: int = 0
    evidence_count: int = 0
    factors: list[str] = field(default_factory=list)


class ContextualRiskEngine:
    """Calculates contextual exposure risk from correlated evidence."""

    def calculate(self, context: RiskContext) -> dict:
        weights = {
            "exposure": 0.30,
            "criticality": 0.20,
            "vulnerability": 0.25,
            "threat": 0.15,
            "confidence": 0.10,
        }

        score = (
            context.exposure_score * weights["exposure"]
            + context.asset_criticality * weights["criticality"]
            + context.vulnerability_score * weights["vulnerability"]
            + context.threat_score * weights["threat"]
            + context.confidence_score * weights["confidence"]
        )

        return {
            "risk_score": round(min(score, 100)),
            "evidence_count": context.evidence_count,
            "factors": context.factors,
            "classification": self._classification(score),
        }

    def _classification(self, score: float) -> str:
        if score >= 85:
            return "critical"
        if score >= 65:
            return "high"
        if score >= 40:
            return "medium"
        return "low"
