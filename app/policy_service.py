from dataclasses import asdict

from .tenant_risk_policy import (
    TenantRiskPolicy,
    policy_for,
    save_policy,
    serialize_policy,
    validate_policy,
)
from .tenant_sla_policy import (
    TenantSLAPolicy,
    save_sla_policy,
    serialize_sla_policy,
    sla_policy_for,
    validate_sla_policy,
)


RISK_POLICY_FIELDS={
    "likelihood_weight",
    "impact_weight",
    "confidence_weight",
    "internet_multiplier",
    "production_multiplier",
    "remote_access_multiplier",
    "compensating_control_reduction",
    "stale_evidence_days",
    "stale_confidence_penalty",
    "name",
}


def get_risk_policy_view(tenant_id: str) -> dict:
    policy=policy_for(tenant_id)
    return {"policy":serialize_policy(policy),"validation":validate_policy(policy)}


def build_and_save_risk_policy(
    tenant_id: str,
    user_id: str,
    body: dict,
) -> TenantRiskPolicy:
    base=policy_for(tenant_id)
    values={k:body[k] for k in RISK_POLICY_FIELDS if k in body}
    candidate=TenantRiskPolicy(
        **{
            **base.__dict__,
            **values,
            "tenant_id":tenant_id,
            "version":base.version+1,
        }
    )
    errors=validate_policy(candidate)
    if errors:
        raise ValueError(errors)
    save_policy(candidate,updated_by=user_id)
    return candidate


def get_sla_policy_view(tenant_id: str) -> dict:
    policy=sla_policy_for(tenant_id)
    return {"policy":serialize_sla_policy(policy),"validation":validate_sla_policy(policy)}


def build_and_save_sla_policy(
    tenant_id: str,
    user_id: str,
    critical_hours: int,
    high_hours: int,
    medium_hours: int,
    low_hours: int,
) -> TenantSLAPolicy:
    current=sla_policy_for(tenant_id)
    candidate=TenantSLAPolicy(
        tenant_id=tenant_id,
        version=current.version+1,
        critical_hours=critical_hours,
        high_hours=high_hours,
        medium_hours=medium_hours,
        low_hours=low_hours,
    )
    errors=validate_sla_policy(candidate)
    if errors:
        raise ValueError(errors)
    save_sla_policy(candidate,updated_by=user_id)
    return candidate
