from dataclasses import dataclass, asdict
from .risk_policy import RiskPolicy, DEFAULT_POLICY
from .risk_engine import assess_risk
from .models import Finding, Asset

@dataclass(frozen=True)
class TenantRiskPolicy(RiskPolicy):
    tenant_id: str = "tenant-demo"
    version: int = 1

def policy_for(tenant_id: str) -> TenantRiskPolicy:
    # Persistent policy storage can be added without changing the calculation contract.
    return TenantRiskPolicy(tenant_id=tenant_id)

def serialize_policy(policy: TenantRiskPolicy) -> dict:
    return asdict(policy)

def validate_policy(policy: TenantRiskPolicy) -> list[str]:
    errors=[]
    for name in ("likelihood_weight","impact_weight","confidence_weight"):
        value=getattr(policy,name)
        if value<0 or value>1: errors.append(name+" must be between 0 and 1")
    total=policy.likelihood_weight+policy.impact_weight+policy.confidence_weight
    if abs(total-1)>0.001: errors.append("risk weights must sum to 1")
    for name in ("internet_multiplier","production_multiplier","remote_access_multiplier","compensating_control_reduction"):
        value=getattr(policy,name)
        if value<0 or value>2: errors.append(name+" outside allowed range")
    return errors
