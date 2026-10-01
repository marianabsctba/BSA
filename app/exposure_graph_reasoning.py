"""Exposure Graph Reasoning Layer.

Correlates asset relationships, evidence, business context and surface changes.
No internal assessment provider names are exposed by this layer.
"""

from datetime import datetime, timezone
from typing import Iterable

from .contextual_risk_engine import ContextualRiskEngine


class ExposureGraphReasoner:
    def __init__(self, risk_engine: ContextualRiskEngine | None = None):
        self.risk_engine = risk_engine or ContextualRiskEngine()

    def explain_risk(
        self,
        asset: str,
        relationships: Iterable[dict] | None = None,
        findings: Iterable[dict] | None = None,
        *,
        business_context: dict | None = None,
        change_correlations: Iterable[object] | None = None,
    ) -> dict:
        relationships = list(relationships or [])
        findings = list(findings or [])
        business = business_context or {}
        changes = list(change_correlations or [])

        confidence = self._confidence(relationships, findings)
        exposure_score = self._exposure_score(asset, relationships, findings, business)
        vulnerability_score = self._vulnerability_score(findings)
        threat_score = self._threat_score(findings)
        criticality = self._criticality(business)
        change_delta = sum(int(getattr(c, "risk_delta", 0) or 0) for c in changes)

        reasons = self._reasons(relationships, findings, business, changes)

        risk = self.risk_engine.from_evidence(
            exposure_score=exposure_score,
            asset_criticality=criticality,
            vulnerability_score=vulnerability_score,
            threat_score=threat_score,
            confidence_score=confidence,
            evidence=findings,
            business_context=business,
            change_risk_delta=change_delta,
            factors=reasons,
        )

        return {
            "asset": asset,
            "risk": risk,
            "risk_context": {
                "confidence": confidence,
                "reasons": risk["factors"],
                "relationship_count": len(relationships),
                "change_count": len(changes),
            },
            "evidence_count": len(findings),
            "generated_at": datetime.now(timezone.utc).isoformat(),
        }

    @staticmethod
    def _confidence(relationships: list[dict], findings: list[dict]) -> int:
        values = []
        for rel in relationships:
            value = rel.get("confidence")
            if value is not None:
                values.append(int(value))
        for finding in findings:
            value = finding.get("confidence")
            if value is not None:
                values.append(int(value))
        if not values:
            return 40
        return max(0, min(100, round(sum(values) / len(values))))

    @staticmethod
    def _exposure_score(asset: str, relationships: list[dict], findings: list[dict], business: dict) -> int:
        score = 20
        if business.get("internet_facing"):
            score += 45
        if any(str(r.get("relation", "")).lower() in {"resolves_to", "exposes", "hosts", "serves"} for r in relationships):
            score += 15
        if findings:
            score += 20
        return min(100, score)

    @staticmethod
    def _vulnerability_score(findings: list[dict]) -> int:
        severity = {"critical": 100, "high": 80, "medium": 55, "low": 25, "info": 5}
        values = [severity.get(str(f.get("severity", "info")).lower(), 0) for f in findings]
        return max(values, default=0)

    @staticmethod
    def _threat_score(findings: list[dict]) -> int:
        values = []
        for finding in findings:
            raw = finding.get("threat_score")
            if raw is not None:
                values.append(max(0, min(100, int(raw))))
            elif finding.get("known_exploited") or finding.get("active_threat"):
                values.append(90)
        return max(values, default=0)

    @staticmethod
    def _criticality(business: dict) -> int:
        explicit = business.get("criticality_score")
        if explicit is not None:
            return max(0, min(100, int(explicit)))
        score = 20
        if business.get("production"):
            score += 25
        if business.get("critical_service"):
            score += 35
        if business.get("customer_facing"):
            score += 10
        if business.get("regulated"):
            score += 10
        return min(100, score)

    @staticmethod
    def _reasons(relationships: list[dict], findings: list[dict], business: dict, changes: list[object]) -> list[str]:
        reasons = []
        if relationships:
            reasons.append("contexto de relacionamento do ativo confirmado")
        if findings:
            reasons.append("evidências de exposição correlacionadas")
        if changes:
            reasons.append("mudança recente na superfície de ataque")
        if business.get("production"):
            reasons.append("ativo em produção")
        if business.get("critical_service"):
            reasons.append("serviço de negócio crítico")
        if business.get("internet_facing"):
            reasons.append("ativo acessível externamente")
        if not business.get("owner"):
            reasons.append("ativo sem responsável definido")
        return reasons
