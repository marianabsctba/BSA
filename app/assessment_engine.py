"""Be Safe ASM assessment orchestration layer.

Security engines are internal implementation details. Public exports contain
only normalized exposure intelligence, evidence and confidence.
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
    """Coordinates multiple internal assessment providers."""

    PROVIDERS = {
        "nuclei": "vulnerability_validation",
        "openvas": "vulnerability_assessment",
        "zap": "dast",
        "nmap": "service_discovery",
        "dns": "external_discovery",
        "ct": "certificate_intelligence",
        "cti": "threat_intelligence",
        "leak": "credential_exposure",
        "httpx": "surface_validation",
        "subfinder": "external_discovery",
        "amass": "external_discovery",
        "safeweb": "web_assessment",
    }

    def __init__(self):
        self.findings: list[AssessmentFinding] = []

    def register_finding(self, finding: AssessmentFinding):
        self.findings.append(finding)

    def add_provider_result(self, provider: str, asset: str, result: dict):
        category = self.PROVIDERS.get(provider, "assessment")
        self.register_finding(
            AssessmentFinding(
                asset=asset,
                engine=provider,
                category=category,
                title=result.get("title", "assessment finding"),
                severity=result.get("severity", "info"),
                confidence=max(0, min(100, int(result.get("confidence", 50)))),
                evidence=result.get("evidence") or result,
            )
        )

    def export_public(self) -> dict:
        """Product-safe output: provider/tool identities are intentionally removed."""
        findings = []
        for item in self.findings:
            findings.append(
                {
                    "asset": item.asset,
                    "category": item.category,
                    "title": item.title,
                    "severity": item.severity,
                    "confidence": item.confidence,
                    "evidence": self._sanitize_evidence(item.evidence),
                }
            )
        return {
            "assessment_id": str(uuid.uuid4()),
            "generated_at": datetime.now(timezone.utc).isoformat(),
            "findings": findings,
            "finding_count": len(findings),
        }

    def export_internal(self) -> dict:
        """Internal diagnostics only. Never expose this payload through tenant APIs."""
        return {
            "assessment_id": str(uuid.uuid4()),
            "generated_at": datetime.now(timezone.utc).isoformat(),
            "findings": [asdict(item) for item in self.findings],
            "finding_count": len(self.findings),
        }

    def export(self) -> dict:
        # Backwards-compatible default is the safe product boundary.
        return self.export_public()

    @staticmethod
    def _sanitize_evidence(evidence: dict[str, Any]) -> dict[str, Any]:
        blocked = {
            "engine",
            "provider",
            "scanner",
            "command",
            "binary",
            "template",
            "template_id",
            "tool",
            "tool_name",
        }
        return {k: v for k, v in (evidence or {}).items() if str(k).lower() not in blocked}
