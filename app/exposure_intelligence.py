"""Be Safe ASM exposure intelligence layer.

Internal engines are implementation details. The customer-facing product
receives normalized exposure intelligence, evidence and risk context.
"""

from dataclasses import dataclass, asdict
from datetime import datetime, timezone
from typing import Any


@dataclass
class ExposureFinding:
    asset: str
    title: str
    severity: str
    confidence: int
    evidence: list[Any]
    business_context: dict[str, Any]
    recommendation: str


def normalize_finding(
    asset: str,
    title: str,
    severity: str,
    evidence: list[Any] | None = None,
    confidence: int = 0,
    business_context: dict[str, Any] | None = None,
    recommendation: str = "Review exposure and apply remediation controls",
) -> dict:
    """Create a customer-safe exposure record.

    Tool provenance stays internal and is not part of the product contract.
    """
    finding = ExposureFinding(
        asset=asset,
        title=title,
        severity=severity,
        confidence=confidence,
        evidence=evidence or [],
        business_context=business_context or {},
        recommendation=recommendation,
    )
    return {
        **asdict(finding),
        "created_at": datetime.now(timezone.utc).isoformat(),
        "category": "exposure_intelligence",
    }


def calculate_contextual_priority(finding: dict) -> int:
    score = 0
    severity = finding.get("severity", "").lower()
    score += {"critical": 50, "high": 35, "medium": 20, "low": 5}.get(severity, 0)
    score += min(int(finding.get("confidence", 0)) // 5, 20)
    context = finding.get("business_context", {})
    if context.get("internet_exposed"):
        score += 15
    if context.get("critical_asset"):
        score += 15
    return min(score, 100)
