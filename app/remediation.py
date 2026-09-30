from dataclasses import dataclass

from .models import Asset, Finding, Severity
from .exposure import exposure_breakdown


@dataclass(frozen=True)
class RemediationPlan:
    finding_id: str
    asset_id: str
    priority: str
    current_score: int
    residual_score: int
    risk_reduction: int
    action: str
    validation: str
    owner: str
    effort: str
    rationale: list[str]


def _action_for(finding: Finding, asset: Asset) -> tuple[str, str, str, list[str]]:
    if "remote-access" in asset.tags:
        return (
            "restringir exposição do acesso remoto, aplicar MFA/política de acesso e validar origem",
            "validar que a superfície remota deixou de estar exposta e repetir discovery",
            "Infra / IAM",
            ["acesso remoto aumenta o blast radius", "redução de exposição deve ser validada externamente"],
        )
    if "internet-facing" in asset.tags and finding.severity in {Severity.CRITICAL, Severity.HIGH}:
        return (
            "corrigir o finding na aplicação/serviço e aplicar mitigação compensatória até a correção",
            "reexecutar coleta externa e confirmar ausência da condição observada",
            "AppSec / Infra",
            ["ativo exposto diretamente", "finding de alta severidade"],
        )
    if finding.severity == Severity.CRITICAL:
        return (
            "corrigir o finding crítico e preservar evidência de validação",
            "retestar a condição e confirmar fechamento",
            "Security / Owner",
            ["severidade crítica"],
        )
    return (
        "corrigir a condição conforme a janela de risco contextual",
        "reexecutar a evidência que originou o finding",
        "Owner do ativo",
        ["tratamento orientado ao contexto do ativo"],
    )


def build_remediation_plan(finding: Finding, asset: Asset) -> RemediationPlan:
    current = exposure_breakdown(asset, [finding]).score
    action, validation, owner, rationale = _action_for(finding, asset)

    reduction = 28
    if "internet-facing" in asset.tags:
        reduction += 12
    if finding.severity == Severity.CRITICAL:
        reduction += 15
    elif finding.severity == Severity.HIGH:
        reduction += 10
    residual = max(0, current - min(65, reduction))

    if current >= 85 or finding.severity == Severity.CRITICAL:
        priority = "P1"
    elif current >= 65 or finding.severity == Severity.HIGH:
        priority = "P2"
    else:
        priority = "P3"

    effort = "baixo" if reduction >= 50 else "médio" if reduction >= 35 else "alto"

    return RemediationPlan(
        finding_id=finding.id,
        asset_id=asset.id,
        priority=priority,
        current_score=current,
        residual_score=residual,
        risk_reduction=current - residual,
        action=action,
        validation=validation,
        owner=owner,
        effort=effort,
        rationale=rationale,
    )
