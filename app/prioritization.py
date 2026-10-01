from dataclasses import dataclass

from .models import Asset, Finding, Severity
from .intelligence import blast_radius, ownership_confidence
from .local_ai import enabled as local_ai_enabled, ask


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

def ai_context_signal(finding: Finding, asset: Asset | None, path_score: int = 0) -> dict:
    """Optional advisory AI context. Deterministic score remains authoritative."""
    if not local_ai_enabled() or asset is None:
        return {"enabled":False,"confidence":0,"signals":[],"unknowns":["AI unavailable or asset missing"]}
    evidence={
        "finding":{"severity":finding.severity.value,"confidence":finding.confidence,"title":finding.title},
        "asset":{"type":asset.type.value,"criticality":asset.criticality,"confidence":asset.confidence,"tags":list(asset.tags)},
        "path_score":path_score,
    }
    system=("You are Be Safe ASM Risk Context Analyst. Respond in Brazilian Portuguese. "
            "Use ONLY supplied evidence. Never change or assign the final risk score. "
            "Identify contextual signals, conflicts and unknowns that a deterministic engine should consider. "
            "Return JSON keys: signals, conflicts, unknowns, confidence.")
    raw=ask(system,"Analyze contextual risk signals. JSON only.\n"+__import__("json").dumps(evidence,ensure_ascii=False,separators=(",",":")))
    if not raw:return {"enabled":True,"confidence":0,"signals":[],"unknowns":["AI unavailable"]}
    try:
        data=__import__("json").loads(raw)
        return {"enabled":True,"confidence":int(data.get("confidence",0) or 0),
                "signals":data.get("signals",[]),"conflicts":data.get("conflicts",[]),"unknowns":data.get("unknowns",[])}
    except Exception:
        return {"enabled":True,"confidence":0,"signals":[],"unknowns":["Unstructured AI response"]}

