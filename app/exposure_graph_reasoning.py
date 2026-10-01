"""
Exposure Graph Reasoning Layer

Internal intelligence layer that correlates assets, evidence and risk context.
The product layer should expose conclusions and evidence, not underlying engines.
"""

from datetime import datetime


class ExposureGraphReasoner:
    def explain_risk(self, asset, relationships=None, findings=None):
        relationships = relationships or []
        findings = findings or []

        confidence = 50
        reasons = []

        if relationships:
            confidence += 10
            reasons.append("Asset relationship context available")

        if findings:
            confidence += 20
            reasons.append("Confirmed exposure evidence available")

        return {
            "asset": asset,
            "risk_context": {
                "confidence": min(confidence, 100),
                "reasons": reasons,
            },
            "evidence_count": len(findings),
            "generated_at": datetime.utcnow().isoformat() + "Z",
        }
