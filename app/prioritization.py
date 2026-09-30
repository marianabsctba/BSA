from dataclasses import dataclass

from .models import Asset, Finding, Severity
from .intelligence import blast_radius, ownership_confidence


@dataclass(frozen=True)
class ActionPriority:
    priority: str
    score: int
    impact: int
    urgency: int
    confidence: int
    reasons: list[str]
    action: str


_SEVERITY = {
    Severity.INFO: 0,
    Severity.LOW: 15,
    Severity.MEDIUM: 35,
    Severity.HIGH: 65,
    Severity.CRITICAL: 90,
}


def prioritize_finding(finding: Finding, asset: Asset | None, path_score: int = 0) -> ActionPriority:
    if asset is None:
        return ActionPriority("P3", 20, 0, _SEVERITY[finding.severity], finding.confidence, ["ativo não encontrado"], "validar ownership e contexto")

    ownership = ownership_confidence(asset)
    impact = min(100, round(asset.criticality / 5 * 55 + blast_radius(asset) * 0.45))
    urgency = _SEVERITY[finding.severity]
    path = min(100, path_score)
    score = min(100, round(impact * 0.45 + urgency * 0.30 + path * 0.15 + finding.confidence * 0.10))

    reasons = []
    if asset.criticality >= 4:
        reasons.append("ativo de alta criticidade")
    if "internet-facing" in asset.tags:
        reasons.append("exposto à Internet")
    if "remote-access" in asset.tags:
        reasons.append("acesso remoto")
    if path >= 70:
        reasons.append("presente em caminho de exposição prioritário")
    if ownership.state == "candidate":
        reasons.append("ownership ainda requer validação")

    if score >= 85:
        priority, action = "P1", "conter/mitigar e validar exposição imediatamente"
    elif score >= 65:
        priority, action = "P2", "priorizar correção no próximo ciclo operacional"
    else:
        priority, action = "P3", "corrigir conforme janela e risco contextual"

    return ActionPriority(priority, score, impact, urgency, finding.confidence, reasons, action)
