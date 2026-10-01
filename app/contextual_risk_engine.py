"""Contextual Risk Engine

Internal risk calculation layer for Be Safe ASM.
The UI consumes contextual intelligence and never scanner/provider details.
"""

from dataclasses import dataclass, field
from typing import Iterable


@dataclass
class RiskContext:
    exposure_score: int = 0
    asset_criticality: int = 0
    vulnerability_score: int = 0
    threat_score: int = 0
    confidence_score: int = 0
    business_impact_score: int = 0
    change_risk_delta: int = 0
    evidence_count: int = 0
    factors: list[str] = field(default_factory=list)
    business_context: dict = field(default_factory=dict)


class ContextualRiskEngine:
    """Calculates contextual exposure risk from correlated evidence."""

    WEIGHTS = {
        "exposure": 0.25,
        "criticality": 0.18,
        "vulnerability": 0.22,
        "threat": 0.12,
        "confidence": 0.08,
        "business": 0.15,
    }

    def calculate(self, context: RiskContext) -> dict:
        base_score = (
            self._bounded(context.exposure_score) * self.WEIGHTS["exposure"]
            + self._bounded(context.asset_criticality) * self.WEIGHTS["criticality"]
            + self._bounded(context.vulnerability_score) * self.WEIGHTS["vulnerability"]
            + self._bounded(context.threat_score) * self.WEIGHTS["threat"]
            + self._bounded(context.confidence_score) * self.WEIGHTS["confidence"]
            + self._bounded(context.business_impact_score) * self.WEIGHTS["business"]
        )

        # Surface change is deliberately a bounded modifier rather than a new
        # dominant score dimension. A new exposed service may raise urgency,
        # while a confirmed removal can lower it.
        change_modifier = max(-20, min(20, int(context.change_risk_delta or 0) * 0.20))
        score = self._bounded(round(base_score + change_modifier))

        factors = list(dict.fromkeys(context.factors + self._business_factors(context.business_context)))

        return {
            "risk_score": score,
            "base_score": round(base_score),
            "change_modifier": round(change_modifier),
            "evidence_count": max(0, int(context.evidence_count or 0)),
            "factors": factors,
            "classification": self._classification(score),
            "business_context": self._public_business_context(context.business_context),
        }

    def from_evidence(
        self,
        *,
        exposure_score: int,
        asset_criticality: int,
        vulnerability_score: int,
        threat_score: int,
        confidence_score: int,
        evidence: Iterable[object] = (),
        business_context: dict | None = None,
        change_risk_delta: int = 0,
        factors: Iterable[str] = (),
    ) -> dict:
        business = business_context or {}
        return self.calculate(
            RiskContext(
                exposure_score=exposure_score,
                asset_criticality=asset_criticality,
                vulnerability_score=vulnerability_score,
                threat_score=threat_score,
                confidence_score=confidence_score,
                business_impact_score=self._business_impact(business),
                change_risk_delta=change_risk_delta,
                evidence_count=sum(1 for _ in evidence),
                factors=list(factors),
                business_context=business,
            )
        )

    @staticmethod
    def _bounded(value: int | float) -> int:
        return max(0, min(100, int(round(value or 0))))

    def _business_impact(self, context: dict) -> int:
        explicit = context.get("impact_score")
        if explicit is not None:
            return self._bounded(explicit)

        score = 0
        if context.get("production"):
            score += 30
        if context.get("internet_facing"):
            score += 20
        if context.get("critical_service"):
            score += 30
        if context.get("regulated"):
            score += 10
        if context.get("customer_facing"):
            score += 10
        return self._bounded(score)

    @staticmethod
    def _business_factors(context: dict) -> list[str]:
        labels = []
        if context.get("production"):
            labels.append("produção")
        if context.get("critical_service"):
            labels.append("serviço crítico")
        if context.get("customer_facing"):
            labels.append("serviço voltado a clientes")
        if context.get("regulated"):
            labels.append("contexto regulado")
        if context.get("internet_facing"):
            labels.append("exposição externa")
        owner = context.get("owner")
        if not owner:
            labels.append("sem responsável definido")
        return labels

    @staticmethod
    def _public_business_context(context: dict) -> dict:
        allowed = {
            "production",
            "critical_service",
            "customer_facing",
            "regulated",
            "internet_facing",
            "owner",
            "business_unit",
            "service_name",
            "sla",
        }
        return {k: v for k, v in context.items() if k in allowed and v is not None}

    @staticmethod
    def _classification(score: float) -> str:
        if score >= 85:
            return "critical"
        if score >= 65:
            return "high"
        if score >= 40:
            return "medium"
        return "low"
