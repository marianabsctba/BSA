"""Be Safe ASM assessment orchestration layer.

This module intentionally abstracts security engines from the platform.
Individual providers (Nuclei, OpenVAS, ZAP, Nmap, CTI, etc.) can feed the
same evidence model without exposing implementation details in the UI.
"""

from dataclasses import dataclass, asdict
from datetime import datetime, timezone
from typing import Any
import uuid


@dataclass
class AssessmentFinding:
    asset: str
    engine: str
    category: str
    title: str
    severity: str
    confidence: int
    evidence: dict[str, Any]


class AssessmentEngine:
    """Coordinates multiple security assessment providers."""

    PROVIDERS = {
        "nuclei": "vulnerability_validation",
        "openvas": "vulnerability_assessment",
        "zap": "dast",
        "nmap": "service_discovery",
        "dns": "external_discovery",
        "ct": "certificate_intelligence",
        "cti": "threat_intelligence",
        "leak": "credential_exposure",
    }

    def __init__(self):
        self.findings: list[AssessmentFinding] = []

    def register_finding(self, finding: AssessmentFinding):
        self.findings.append(finding)

    def add_provider_result(self, provider: str, asset: str, result: dict):
        category = self.PROVIDERS.get(provider, "unknown")
        self.register_finding(
            AssessmentFinding(
                asset=asset,
                engine=provider,
                category=category,
                title=result.get("title", "assessment finding"),
                severity=result.get("severity", "info"),
                confidence=int(result.get("confidence", 50)),
                evidence=result,
            )
        )

    def export(self):
        return {
            "assessment_id": str(uuid.uuid4()),
            "generated_at": datetime.now(timezone.utc).isoformat(),
            "providers": self.PROVIDERS,
            "findings": [asdict(item) for item in self.findings],
            "finding_count": len(self.findings),
        }
