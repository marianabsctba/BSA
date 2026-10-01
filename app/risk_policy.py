from dataclasses import dataclass
from .models import Asset, Finding
from .risk_engine import assess_risk

@dataclass(frozen=True)
class RiskPolicy:
    name: str = "BSA Default"
    likelihood_weight: float = 0.45
    impact_weight: float = 0.40
    confidence_weight: float = 0.15
    internet_multiplier: float = 1.15
    production_multiplier: float = 1.10
    remote_access_multiplier: float = 1.10
    compensating_control_reduction: float = 0.15
    stale_evidence_days: int = 30
    stale_confidence_penalty: int = 10

DEFAULT_POLICY = RiskPolicy()

def _has(asset: Asset|None, tag: str) -> bool:
    return bool(asset and tag in asset.tags)

def calculate_risk(finding: Finding, asset: Asset|None, policy: RiskPolicy=DEFAULT_POLICY) -> dict:
    base=assess_risk(finding,asset)
    likelihood=base.likelihood
    impact=base.impact
    drivers=list(base.drivers)
    controls=[]
    if _has(asset,"mfa-enabled") and _has(asset,"remote-access"):
        likelihood=round(likelihood*(1-policy.compensating_control_reduction))
        controls.append("MFA reduz likelihood de exploração de acesso remoto")
    if _has(asset,"waf-protected") and _has(asset,"internet-facing"):
        likelihood=round(likelihood*(1-policy.compensating_control_reduction*.7))
        controls.append("WAF é considerado controle compensatório")
    if _has(asset,"segmented"):
        impact=round(impact*.90)
        controls.append("segmentação reduz blast radius")
    if _has(asset,"internet-facing"):
        likelihood=min(100,round(likelihood*policy.internet_multiplier))
    if _has(asset,"production"):
        impact=min(100,round(impact*policy.production_multiplier))
    if _has(asset,"remote-access"):
        likelihood=min(100,round(likelihood*policy.remote_access_multiplier))

    confidence=base.confidence
    # Unknown evidence never becomes zero risk; it increases uncertainty and
    # is surfaced separately so operators know the score needs validation.
    uncertainty=max(0,100-confidence)
    score=min(100,round(
        likelihood*policy.likelihood_weight+
        impact*policy.impact_weight+
        confidence*policy.confidence_weight
    ))
    residual=max(0,round(score*(1-sum([
        policy.compensating_control_reduction for _ in controls
    ]))))
    band="critical" if score>=85 else "high" if score>=70 else "medium" if score>=45 else "low"
    return {
        "score":score,"band":band,"inherent_score":base.score,"residual_score":residual,
        "likelihood":likelihood,"impact":impact,"uncertainty":uncertainty,
        "confidence":confidence,"exploitability":base.exploitability,
        "exposure":base.exposure,"business_criticality":base.business_criticality,
        "drivers":drivers,"controls":controls,"policy":policy.name,
        "validation_required":uncertainty>=30 or finding.false_positive_confidence>=60
    }
