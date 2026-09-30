from dataclasses import dataclass
from .models import Asset, Finding, Severity


@dataclass(frozen=True)
class OwnershipResult:
    score: int
    state: str
    reasons: list[str]


def ownership_confidence(asset: Asset) -> OwnershipResult:
    score = asset.confidence
    reasons: list[str] = []

    if asset.source in {"seed", "authoritative", "manual"}:
        score = min(100, score + 10)
        reasons.append("fonte autoritativa")
    if asset.type.value in {"domain", "subdomain"}:
        reasons.append("identidade DNS observada")
    if "third-party" in asset.tags:
        score = max(0, score - 25)
        reasons.append("indício de terceiro")
    if "shared-hosting" in asset.tags:
        score = max(0, score - 15)
        reasons.append("infraestrutura compartilhada")
    if "confirmed-owner" in asset.tags:
        score = 100
        reasons.append("ownership confirmado")

    state = "confirmed" if score >= 90 else "probable" if score >= 70 else "candidate"
    return OwnershipResult(score=score, state=state, reasons=reasons)


def blast_radius(asset: Asset) -> int:
    base = asset.criticality * 15
    if "internet-facing" in asset.tags:
        base += 10
    if "remote-access" in asset.tags:
        base += 15
    if "identity" in asset.tags:
        base += 15
    if "production" in asset.tags:
        base += 10
    return min(100, base)


def finding_context_score(finding: Finding, asset: Asset) -> int:
    sev = {
        Severity.INFO: 5,
        Severity.LOW: 15,
        Severity.MEDIUM: 35,
        Severity.HIGH: 60,
        Severity.CRITICAL: 85,
    }[finding.severity]

    confidence = finding.confidence / 100
    criticality = asset.criticality / 5
    blast = blast_radius(asset) / 100
    return round(min(100, sev * 0.55 + 25 * criticality + 20 * blast) * confidence)
