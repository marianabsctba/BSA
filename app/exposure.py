from dataclasses import dataclass
from .models import Asset, Finding, Severity
from .intelligence import blast_radius


@dataclass(frozen=True)
class ExposureBreakdown:
    score: int
    internet: int
    exploitability: int
    criticality: int
    intelligence: int
    confidence: int
    shadow: int
    rationale: list[str]


def exposure_breakdown(asset: Asset, findings: list[Finding]) -> ExposureBreakdown:
    """Explainable 0-100 exposure score. It is intentionally evidence-driven."""
    asset_findings = [f for f in findings if f.asset_id == asset.id and f.status == "open"]
    internet = 18 if "internet-facing" in asset.tags else 0
    remote = 8 if "remote-access" in asset.tags else 0
    criticality = min(20, asset.criticality * 4)
    confidence = round(asset.confidence * 0.10)

    severity_points = {
        Severity.INFO: 0,
        Severity.LOW: 4,
        Severity.MEDIUM: 9,
        Severity.HIGH: 15,
        Severity.CRITICAL: 20,
    }
    exploitability = min(20, sum(severity_points[f.severity] for f in asset_findings))

    shadow = 10 if "candidate" in asset.tags or "shadow" in asset.tags else 0
    intelligence = min(15, sum(3 for f in asset_findings if f.confidence >= 85))

    score = min(100, internet + remote + criticality + confidence + exploitability + shadow + intelligence)
    reasons: list[str] = []
    if internet:
        reasons.append("exposição direta à Internet")
    if remote:
        reasons.append("acesso remoto identificado")
    if exploitability:
        reasons.append(f"{len(asset_findings)} finding(s) aberto(s) contextualizado(s)")
    if shadow:
        reasons.append("asset candidato/shadow")
    if asset.criticality >= 4:
        reasons.append("criticidade operacional elevada")

    return ExposureBreakdown(
        score=score,
        internet=internet,
        exploitability=exploitability,
        criticality=criticality,
        intelligence=intelligence,
        confidence=confidence,
        shadow=shadow,
        rationale=reasons,
    )


def exposure_band(score: int) -> str:
    if score >= 85:
        return "critical"
    if score >= 70:
        return "high"
    if score >= 45:
        return "medium"
    return "low"
